package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/hoaxisr/awg-manager/internal/amneziagw"
	"github.com/hoaxisr/awg-manager/internal/events"
	"github.com/hoaxisr/awg-manager/internal/response"
	"github.com/hoaxisr/awg-manager/internal/singbox"
	"github.com/hoaxisr/awg-manager/internal/singbox/vlink"
	"github.com/hoaxisr/awg-manager/internal/storage"
	"github.com/hoaxisr/awg-manager/internal/tunnel"
	tunnelservice "github.com/hoaxisr/awg-manager/internal/tunnel/service"
)

const (
	codePremiumGatewayBadKey      = "AMNEZIA_PREMIUM_GATEWAY_BAD_KEY"
	codePremiumGatewayUnavailable = "AMNEZIA_PREMIUM_GATEWAY_UNAVAILABLE"
	codePremiumGatewayBadTag      = "AMNEZIA_PREMIUM_GATEWAY_BAD_SUPPORT_TAG"
	codePremiumGatewayBadProtocol = "AMNEZIA_PREMIUM_GATEWAY_BAD_PROTOCOL"
	codePremiumGatewayApply       = "AMNEZIA_PREMIUM_GATEWAY_APPLY_FAILED"
)

const premiumVLESSTag = "amnezia-premium-vless"

// AmneziaPremiumGatewayHandler augments the legacy CP handler with the
// Premium V2 Gateway flow used by current AmneziaVPN clients. Legacy keys are
// delegated unchanged, so old installations keep the existing wizard.
type AmneziaPremiumGatewayHandler struct {
	legacy   *AmneziaPremiumHandler
	settings *storage.SettingsStore
	tunnels  TunnelService
	singbox  *singbox.Operator
	version  string
}

func NewAmneziaPremiumGatewayHandler(
	legacy *AmneziaPremiumHandler,
	settings *storage.SettingsStore,
	tunnels TunnelService,
	sb *singbox.Operator,
	version string,
) *AmneziaPremiumGatewayHandler {
	return &AmneziaPremiumGatewayHandler{
		legacy: legacy, settings: settings, tunnels: tunnels, singbox: sb,
		version: strings.TrimSpace(version),
	}
}

// gatewayState returns a copy. Callers may mutate it freely.
func (h *AmneziaPremiumGatewayHandler) gatewayState() storage.AmneziaPremiumGatewayState {
	cur, err := h.settings.Get()
	if err != nil || cur.AmneziaPremiumGateway == nil {
		return storage.AmneziaPremiumGatewayState{}
	}
	return *cur.AmneziaPremiumGateway
}

func (h *AmneziaPremiumGatewayHandler) updateGatewayState(
	mut func(*storage.AmneziaPremiumGatewayState),
) error {
	return h.settings.Update(func(s *storage.Settings) error {
		next := storage.AmneziaPremiumGatewayState{}
		if s.AmneziaPremiumGateway != nil {
			next = *s.AmneziaPremiumGateway
		}
		mut(&next)
		s.AmneziaPremiumGateway = &next
		return nil
	})
}

func validSupportTag(v string) bool {
	if v == "" || len(v) > 128 || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (h *AmneziaPremiumGatewayHandler) ensureSupportTag(preferred string) (string, error) {
	preferred = strings.TrimSpace(preferred)
	if preferred != "" && !validSupportTag(preferred) {
		return "", errors.New("Support tag должен быть непустой строкой до 128 байт без управляющих символов")
	}
	state := h.gatewayState()
	tag := preferred
	if tag == "" {
		tag = strings.TrimSpace(state.SupportTag)
	}
	if tag == "" {
		var err error
		tag, err = amneziagw.NewUUID()
		if err != nil {
			return "", err
		}
	}
	if state.SupportTag == tag {
		return tag, nil
	}
	if err := h.updateGatewayState(func(s *storage.AmneziaPremiumGatewayState) {
		s.SupportTag = tag
	}); err != nil {
		return "", err
	}
	return tag, nil
}

func (h *AmneziaPremiumGatewayHandler) currentAccountKey() (amneziagw.AccountKey, bool) {
	if h.legacy == nil {
		return amneziagw.AccountKey{}, false
	}
	raw := strings.TrimSpace(h.legacy.subscriptionKey())
	if raw == "" {
		return amneziagw.AccountKey{}, false
	}
	key, err := amneziagw.ParseVPNKey(raw)
	return key, err == nil
}

func (h *AmneziaPremiumGatewayHandler) gatewayClient() *amneziagw.Client {
	return amneziagw.NewClient(nil)
}

func premiumGatewayHTTPFailure(w http.ResponseWriter, err error) {
	var apiErr *amneziagw.APIError
	if errors.As(err, &apiErr) {
		status := apiErr.Status
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		msg := apiErr.Message
		if msg == "" {
			msg = "Сервис Amnezia отклонил запрос"
		}
		response.ErrorWithStatus(w, status, msg, codePremiumGatewayUnavailable)
		return
	}
	response.ErrorWithStatus(w, http.StatusBadGateway,
		"Gateway Amnezia недоступен — попробуйте позже", codePremiumGatewayUnavailable)
}

// Key replaces the route-level key handler. GET/DELETE and non-V2 POSTs are
// delegated to the legacy CP implementation. Premium V2 POSTs are validated
// against v1/account_info and can set Support tag in the same action.
func (h *AmneziaPremiumGatewayHandler) Key(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.legacy.Key(w, r)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil || len(raw) > maxBodySize {
		response.ErrorWithStatus(w, http.StatusBadRequest, "Некорректное тело запроса", "BAD_REQUEST")
		return
	}
	// Restore the body before any legacy delegation.
	r.Body = io.NopCloser(bytes.NewReader(raw))

	var req AmneziaPremiumKeyRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		h.legacy.Key(w, r)
		return
	}
	accountKey, err := amneziagw.ParseVPNKey(strings.TrimSpace(req.Key))
	if err != nil {
		h.legacy.Key(w, r)
		return
	}

	tag, err := h.ensureSupportTag(req.SupportTag)
	if err != nil {
		response.ErrorWithStatus(w, http.StatusBadRequest, err.Error(), codePremiumGatewayBadTag)
		return
	}

	// Validation is read-only but uses the exact installation_uuid that later
	// v1/config calls will use.
	if _, err := h.gatewayClient().AccountInfo(r.Context(), accountKey, tag, h.version); err != nil {
		premiumGatewayHTTPFailure(w, err)
		return
	}

	store := req.Store != nil && *req.Store
	gen := h.legacy.keyGeneration()
	cancelled, saveErr := h.legacy.commitKey(strings.TrimSpace(req.Key), gen, store)
	if cancelled {
		response.ErrorWithStatus(w, http.StatusConflict,
			"Состояние ключа подписки изменилось во время проверки", codePremiumStateChanged)
		return
	}

	out, stateErr := h.legacy.keyState()
	if stateErr != nil {
		h.legacy.log.Warn(logActionPremium, "gateway-key",
			"состояние сохранённого ключа не прочитано: "+stateErr.Error())
	}
	if saveErr != nil {
		out.SaveError = saveErrorMessage(saveErr)
	}
	if store && h.legacy.bus != nil {
		h.legacy.bus.PublishInvalidated(events.ResourceAmneziaPremiumKey, "gateway-saved")
	}
	response.Success(w, out)
}

// Device exposes the user-visible Support tag (installation_uuid). Changing
// it does not rotate the subscription API key; the next Gateway request uses
// the new identity immediately.
func (h *AmneziaPremiumGatewayHandler) Device(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		state := h.gatewayState()
		if strings.TrimSpace(state.SupportTag) == "" {
			tag, err := h.ensureSupportTag("")
			if err != nil {
				response.InternalError(w, "Не удалось создать Support tag")
				return
			}
			state.SupportTag = tag
		}
		response.Success(w, map[string]any{
			"supportTag":  state.SupportTag,
			"protocol":    state.Protocol,
			"countryCode": state.CountryCode,
			"awgTunnelId": state.AWGTunnelID,
			"vlessTag":    state.VLESSTag,
			"awgBackend":  state.AWGBackend,
		})
	case http.MethodPost:
		req, ok := parseJSON[struct {
			SupportTag string `json:"supportTag"`
		}](w, r, http.MethodPost)
		if !ok {
			return
		}
		tag, err := h.ensureSupportTag(req.SupportTag)
		if err != nil {
			response.ErrorWithStatus(w, http.StatusBadRequest, err.Error(), codePremiumGatewayBadTag)
			return
		}
		response.Success(w, map[string]string{"supportTag": tag})
	default:
		response.MethodNotAllowed(w)
	}
}

type premiumGatewayAccountInfo struct {
	DisplayName             string `json:"display_name"`
	SubscriptionDescription string `json:"subscription_description"`
	SubscriptionEndDate     string `json:"subscription_end_date"`
	ActiveDeviceCount       int64  `json:"active_device_count"`
	MaxDeviceCount          int64  `json:"max_device_count"`
	AvailableCountries      []struct {
		Code      string   `json:"server_country_code"`
		Name      string   `json:"server_country_name"`
		Protocols []string `json:"available_protocols"`
	} `json:"available_countries"`
	IssuedConfigs []struct {
		Code              string `json:"server_country_code"`
		LastDownloaded    string `json:"last_downloaded"`
		WorkerLastUpdated string `json:"worker_last_updated"`
		SourceType        string `json:"source_type"`
	} `json:"issued_configs"`
}

func gatewayCatalog(raw []byte) (AmneziaPremiumCatalogData, error) {
	var in premiumGatewayAccountInfo
	if err := json.Unmarshal(raw, &in); err != nil {
		return AmneziaPremiumCatalogData{}, err
	}
	if in.AvailableCountries == nil {
		return AmneziaPremiumCatalogData{}, errors.New("Gateway не вернул список стран")
	}
	plan := strings.TrimSpace(in.DisplayName)
	if plan == "" {
		plan = strings.TrimSpace(in.SubscriptionDescription)
	}
	out := AmneziaPremiumCatalogData{
		PlanName:            plan,
		SubscriptionEndDate: in.SubscriptionEndDate,
		ActiveDeviceCount:   in.ActiveDeviceCount,
		MaxDeviceCount:      in.MaxDeviceCount,
		Countries:           make([]AmneziaPremiumCountry, 0, len(in.AvailableCountries)),
	}
	for _, c := range in.AvailableCountries {
		out.Countries = append(out.Countries, AmneziaPremiumCountry{
			Code: c.Code, Name: c.Name, Protocols: c.Protocols,
		})
	}
	if in.IssuedConfigs != nil {
		out.IssuedConfigs = make([]AmneziaPremiumIssuedConfig, 0, len(in.IssuedConfigs))
		for _, c := range in.IssuedConfigs {
			out.IssuedConfigs = append(out.IssuedConfigs, AmneziaPremiumIssuedConfig{
				CountryCode:     c.Code,
				LastIssuedAt:    c.LastDownloaded,
				PortalUpdatedAt: c.WorkerLastUpdated,
				SourceType:      c.SourceType,
			})
		}
	}
	return out, nil
}

// GatewayCatalogData extends the existing catalog without changing its
// country/device fields, so existing wizard rendering stays compatible.
type GatewayCatalogData struct {
	AmneziaPremiumCatalogData
	Gateway         bool   `json:"gateway"`
	SupportTag      string `json:"supportTag"`
	CurrentCountry  string `json:"currentCountry"`
	CurrentProtocol string `json:"currentProtocol"`
	AWGBackend      string `json:"awgBackend,omitempty"`
}

// Catalog transparently delegates legacy keys and uses v1/account_info for
// Premium V2 keys.
func (h *AmneziaPremiumGatewayHandler) Catalog(w http.ResponseWriter, r *http.Request) {
	key, gateway := h.currentAccountKey()
	if !gateway {
		h.legacy.Catalog(w, r)
		return
	}
	if r.Method != http.MethodGet {
		response.MethodNotAllowed(w)
		return
	}
	tag, err := h.ensureSupportTag("")
	if err != nil {
		response.InternalError(w, "Не удалось подготовить Support tag")
		return
	}
	raw, err := h.gatewayClient().AccountInfo(r.Context(), key, tag, h.version)
	if err != nil {
		premiumGatewayHTTPFailure(w, err)
		return
	}
	catalog, err := gatewayCatalog(raw)
	if err != nil {
		response.ErrorWithStatus(w, http.StatusBadGateway,
			"Ответ Gateway Amnezia не удалось разобрать", codePremiumGatewayUnavailable)
		return
	}
	state := h.gatewayState()
	response.Success(w, GatewayCatalogData{
		AmneziaPremiumCatalogData: catalog,
		Gateway:         true,
		SupportTag:      tag,
		CurrentCountry:  state.CountryCode,
		CurrentProtocol: state.Protocol,
		AWGBackend:      state.AWGBackend,
	})
}

// Config preserves the old wizard contract: legacy keys use CP; Premium V2
// keys request an AWG config from v1/config without consuming a new CP slot.
func (h *AmneziaPremiumGatewayHandler) Config(w http.ResponseWriter, r *http.Request) {
	key, gateway := h.currentAccountKey()
	if !gateway {
		h.legacy.Config(w, r)
		return
	}
	req, ok := parseJSON[AmneziaPremiumConfigRequest](w, r, http.MethodPost)
	if !ok {
		return
	}
	country := strings.ToLower(strings.TrimSpace(req.CountryCode))
	if country == "" {
		response.ErrorWithStatus(w, http.StatusBadRequest, "Страна не выбрана", codePremiumNoCountry)
		return
	}
	tag, err := h.ensureSupportTag("")
	if err != nil {
		response.InternalError(w, "Не удалось подготовить Support tag")
		return
	}
	issued, err := h.gatewayClient().IssueConfig(r.Context(), key, amneziagw.IssueOptions{
		CountryCode: country, Protocol: "awg", InstallationUUID: tag, Version: h.version,
	})
	if err != nil {
		premiumGatewayHTTPFailure(w, err)
		return
	}
	response.Success(w, AmneziaPremiumConfigData{CountryCode: country, Config: issued.AWGConf})
}

// AmneziaPremiumSwitchRequest is used by both detailed Premium settings and
// the compact quick-switch control.
type AmneziaPremiumSwitchRequest struct {
	CountryCode string `json:"countryCode"`
	Protocol    string `json:"protocol"` // awg | vless
	AWGBackend  string `json:"awgBackend,omitempty"`
}

type AmneziaPremiumSwitchData struct {
	CountryCode string `json:"countryCode"`
	Protocol    string `json:"protocol"`
	SupportTag  string `json:"supportTag"`
	AWGTunnelID string `json:"awgTunnelId,omitempty"`
	VLESSTag    string `json:"vlessTag,omitempty"`
	AWGBackend  string `json:"awgBackend,omitempty"`
}

func (h *AmneziaPremiumGatewayHandler) Switch(w http.ResponseWriter, r *http.Request) {
	req, ok := parseJSON[AmneziaPremiumSwitchRequest](w, r, http.MethodPost)
	if !ok {
		return
	}
	key, gateway := h.currentAccountKey()
	if !gateway {
		response.ErrorWithStatus(w, http.StatusUnprocessableEntity,
			"Этот ключ не относится к Amnezia Premium V2 Gateway", codePremiumGatewayBadKey)
		return
	}
	country := strings.ToLower(strings.TrimSpace(req.CountryCode))
	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if country == "" {
		response.ErrorWithStatus(w, http.StatusBadRequest, "Страна не выбрана", codePremiumNoCountry)
		return
	}
	if protocol != "awg" && protocol != "vless" {
		response.ErrorWithStatus(w, http.StatusBadRequest,
			"Поддерживаются только AWG и VLESS", codePremiumGatewayBadProtocol)
		return
	}

	tag, err := h.ensureSupportTag("")
	if err != nil {
		response.InternalError(w, "Не удалось подготовить Support tag")
		return
	}
	issued, err := h.gatewayClient().IssueConfig(r.Context(), key, amneziagw.IssueOptions{
		CountryCode: country, Protocol: protocol, InstallationUUID: tag, Version: h.version,
	})
	if err != nil {
		premiumGatewayHTTPFailure(w, err)
		return
	}

	state := h.gatewayState()
	state.SupportTag = tag
	switch protocol {
	case "awg":
		if err := h.applyAWG(r.Context(), issued, req.AWGBackend, &state); err != nil {
			response.ErrorWithStatus(w, http.StatusInternalServerError,
				"Конфигурация получена, но AWG-туннель не удалось применить: "+err.Error(),
				codePremiumGatewayApply)
			return
		}
	case "vless":
		if err := h.applyVLESS(r.Context(), issued, &state); err != nil {
			response.ErrorWithStatus(w, http.StatusInternalServerError,
				"Конфигурация получена, но VLESS-туннель не удалось применить: "+err.Error(),
				codePremiumGatewayApply)
			return
		}
		// The previous AWG runtime must not remain active after an explicit
		// protocol switch. Keep its stored config for a fast switch back.
		if state.AWGTunnelID != "" && h.tunnels != nil {
			_ = h.tunnels.Stop(context.Background(), state.AWGTunnelID)
		}
	}

	state.Protocol = protocol
	state.CountryCode = country
	if err := h.updateGatewayState(func(s *storage.AmneziaPremiumGatewayState) {
		*s = state
	}); err != nil {
		response.InternalError(w, "Туннель переключён, но состояние Premium не удалось сохранить")
		return
	}
	if h.legacy.bus != nil {
		h.legacy.bus.PublishInvalidated(events.ResourceAmneziaPremiumCatalog, "gateway-switched")
		h.legacy.bus.PublishInvalidated(events.ResourceTunnels, "gateway-switched")
		h.legacy.bus.PublishInvalidated(events.ResourceSingboxTunnels, "gateway-switched")
	}
	response.Success(w, AmneziaPremiumSwitchData{
		CountryCode: state.CountryCode,
		Protocol:    state.Protocol,
		SupportTag:  state.SupportTag,
		AWGTunnelID: state.AWGTunnelID,
		VLESSTag:    state.VLESSTag,
		AWGBackend:  state.AWGBackend,
	})
}

func (h *AmneziaPremiumGatewayHandler) applyAWG(
	ctx context.Context,
	issued amneziagw.IssuedConfig,
	requestedBackend string,
	state *storage.AmneziaPremiumGatewayState,
) error {
	if h.tunnels == nil {
		return errors.New("сервис AWG-туннелей недоступен")
	}
	backend := strings.ToLower(strings.TrimSpace(requestedBackend))
	if backend == "" {
		backend = strings.ToLower(strings.TrimSpace(state.AWGBackend))
	}
	if backend == "" {
		backend = "nativewg"
	}
	if backend != "nativewg" && backend != "kernel" {
		return fmt.Errorf("неизвестный AWG backend %q", backend)
	}

	name := "Amnezia Premium · " + strings.ToUpper(issued.CountryCode)
	if state.AWGTunnelID != "" {
		current, err := h.tunnels.Get(ctx, state.AWGTunnelID)
		if err == nil && current != nil {
			if current.State == tunnel.StateRunning {
				if err := h.tunnels.Stop(ctx, state.AWGTunnelID); err != nil {
					return fmt.Errorf("stop %s: %w", state.AWGTunnelID, err)
				}
			}
			country := issued.CountryCode
			if err := h.tunnels.ReplaceConfig(ctx, state.AWGTunnelID, issued.AWGConf, name,
				tunnelservice.ReplaceOptions{AmneziaCountry: &country}); err != nil {
				return fmt.Errorf("replace %s: %w", state.AWGTunnelID, err)
			}
			if err := h.tunnels.Start(ctx, state.AWGTunnelID); err != nil {
				return fmt.Errorf("start %s: %w", state.AWGTunnelID, err)
			}
			state.AWGBackend = current.Backend
			return nil
		}
		// The tracked tunnel was removed manually; recreate it below.
		state.AWGTunnelID = ""
	}

	created, err := h.tunnels.Import(ctx, issued.AWGConf, name, backend,
		tunnelservice.ImportLink{AmneziaCountry: issued.CountryCode})
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}
	if created == nil || created.ID == "" {
		return errors.New("импорт не вернул ID туннеля")
	}
	state.AWGTunnelID = created.ID
	state.AWGBackend = backend
	if err := h.tunnels.Start(ctx, created.ID); err != nil {
		return fmt.Errorf("start %s: %w", created.ID, err)
	}
	return nil
}

func (h *AmneziaPremiumGatewayHandler) applyVLESS(
	ctx context.Context,
	issued amneziagw.IssuedConfig,
	state *storage.AmneziaPremiumGatewayState,
) error {
	if h.singbox == nil {
		return errors.New("sing-box недоступен")
	}
	// Reuse the mature Amnezia/Xray -> sing-box converter already used by
	// imports. The fragment supplies a deterministic local tag.
	link := "vpn://" + base64.RawURLEncoding.EncodeToString([]byte(issued.XrayJSON)) + "#" + premiumVLESSTag
	parsed, err := vlink.ParseLink(link)
	if err != nil {
		return fmt.Errorf("convert Xray to sing-box: %w", err)
	}
	targetTag := strings.TrimSpace(state.VLESSTag)
	if targetTag == "" {
		targetTag = premiumVLESSTag
	}
	if _, err := h.singbox.GetTunnel(ctx, targetTag); err == nil {
		if err := h.singbox.UpdateTunnel(ctx, targetTag, parsed.Outbound); err != nil {
			return fmt.Errorf("update sing-box tunnel %s: %w", targetTag, err)
		}
		state.VLESSTag = targetTag
		return nil
	}

	// AddTunnels allocates the corresponding NDMS proxy/TUN slot and applies
	// the merged sing-box config atomically.
	addLink := "vpn://" + base64.RawURLEncoding.EncodeToString([]byte(issued.XrayJSON)) + "#" + targetTag
	added, parseErrs, err := h.singbox.AddTunnels(ctx, addLink)
	if err != nil {
		return err
	}
	if len(added) == 0 {
		if len(parseErrs) > 0 {
			return parseErrs[0].Err
		}
		return errors.New("sing-box не добавил VLESS-туннель")
	}
	state.VLESSTag = added[0].Tag
	return nil
}
