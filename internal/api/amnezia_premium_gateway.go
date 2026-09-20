package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/hoaxisr/awg-manager/internal/amneziagw"
	"github.com/hoaxisr/awg-manager/internal/events"
	"github.com/hoaxisr/awg-manager/internal/response"
	"github.com/hoaxisr/awg-manager/internal/singbox"
	"github.com/hoaxisr/awg-manager/internal/singbox/vlink"
	"github.com/hoaxisr/awg-manager/internal/storage"
	"github.com/hoaxisr/awg-manager/internal/tunnel"
	tunnelservice "github.com/hoaxisr/awg-manager/internal/tunnel/service"
)

const maxPremiumSupportTagLen = 128

type AmneziaPremiumGatewayStateData struct {
	SupportTag  string `json:"supportTag"`
	Protocol    string `json:"protocol"`
	CountryCode string `json:"countryCode"`
	AWGBackend  string `json:"awgBackend"`
}

type AmneziaPremiumGatewayStateResponse struct {
	Success bool                           `json:"success"`
	Data    AmneziaPremiumGatewayStateData `json:"data"`
}

type AmneziaPremiumGatewayStateRequest struct {
	SupportTag  *string `json:"supportTag,omitempty"`
	Protocol    *string `json:"protocol,omitempty"`
	CountryCode *string `json:"countryCode,omitempty"`
	AWGBackend  *string `json:"awgBackend,omitempty"`
}

type AmneziaPremiumGatewayConfigRequest struct {
	CountryCode string `json:"countryCode" example:"nl"`
	Protocol    string `json:"protocol" example:"awg" enums:"awg,vless"`
}

type AmneziaPremiumGatewayConfigData struct {
	CountryCode string          `json:"countryCode"`
	Protocol    string          `json:"protocol"`
	SupportTag  string          `json:"supportTag"`
	Config      string          `json:"config,omitempty"`
	Link        string          `json:"link,omitempty"`
	Outbound    json.RawMessage `json:"outbound,omitempty" swaggertype:"object"`
}

type AmneziaPremiumGatewayConfigResponse struct {
	Success bool                            `json:"success"`
	Data    AmneziaPremiumGatewayConfigData `json:"data"`
}

func normalizePremiumProtocol(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "awg":
		return "awg", nil
	case "vless":
		return "vless", nil
	default:
		return "", fmt.Errorf("неподдерживаемый протокол %q", v)
	}
}

func validatePremiumSupportTag(v string) error {
	if len(v) > maxPremiumSupportTagLen {
		return fmt.Errorf("Support tag длиннее %d байт", maxPremiumSupportTagLen)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return errors.New("Support tag содержит управляющие символы")
		}
	}
	return nil
}

// ensurePremiumSupportTag returns the current Support tag. When requested is
// non-nil it explicitly replaces the tag; an empty explicit value generates a
// new UUID. With requested=nil an existing tag is preserved, otherwise one is
// generated on first use.
func (h *AmneziaPremiumHandler) ensurePremiumSupportTag(requested *string) (string, error) {
	cur, err := h.settings.Get()
	if err != nil {
		return "", err
	}
	tag := strings.TrimSpace(cur.AmneziaPremiumSupportTag)
	if requested != nil {
		tag = strings.TrimSpace(*requested)
		if tag == "" {
			tag = amneziagw.NewUUID()
		}
	} else if tag == "" {
		tag = amneziagw.NewUUID()
	}
	if err := validatePremiumSupportTag(tag); err != nil {
		return "", err
	}
	if tag == cur.AmneziaPremiumSupportTag {
		return tag, nil
	}
	if err := h.settings.Update(func(s *storage.Settings) error {
		s.AmneziaPremiumSupportTag = tag
		return nil
	}); err != nil {
		return "", err
	}
	return tag, nil
}

// GatewayState serves GET/POST /api/amnezia/premium/gateway-state.
// POST changes Support tag and/or the remembered country/protocol. Sending an
// explicitly empty supportTag rotates it to a freshly generated UUID.
func (h *AmneziaPremiumHandler) GatewayState(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cur, err := h.settings.Get()
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}
		proto, _ := normalizePremiumProtocol(cur.AmneziaPremiumProtocol)
		response.Success(w, AmneziaPremiumGatewayStateData{
			SupportTag:  cur.AmneziaPremiumSupportTag,
			Protocol:    proto,
			CountryCode: cur.AmneziaPremiumServerCountry,
			AWGBackend:  premiumAWGBackend(cur.AmneziaPremiumAWGBackend),
		})
	case http.MethodPost:
		req, ok := parseJSON[AmneziaPremiumGatewayStateRequest](w, r, http.MethodPost)
		if !ok {
			return
		}
		var supportTag string
		if req.SupportTag != nil {
			var err error
			supportTag, err = h.ensurePremiumSupportTag(req.SupportTag)
			if err != nil {
				response.BadRequest(w, err.Error())
				return
			}
		}
		err := h.settings.Update(func(s *storage.Settings) error {
			if req.Protocol != nil {
				p, err := normalizePremiumProtocol(*req.Protocol)
				if err != nil {
					return err
				}
				s.AmneziaPremiumProtocol = p
			}
			if req.CountryCode != nil {
				code := strings.ToLower(strings.TrimSpace(*req.CountryCode))
				if len(code) > maxCountryCodeLen {
					return fmt.Errorf("код страны длиннее %d байт", maxCountryCodeLen)
				}
				s.AmneziaPremiumServerCountry = code
			}
			if req.AWGBackend != nil {
				backend := premiumAWGBackend(*req.AWGBackend)
				if backend == "" {
					return fmt.Errorf("неподдерживаемый AWG backend %q", *req.AWGBackend)
				}
				s.AmneziaPremiumAWGBackend = backend
			}
			return nil
		})
		if err != nil {
			response.BadRequest(w, err.Error())
			return
		}
		cur, err := h.settings.Get()
		if err != nil {
			response.InternalError(w, err.Error())
			return
		}
		if supportTag == "" {
			supportTag = cur.AmneziaPremiumSupportTag
		}
		proto, _ := normalizePremiumProtocol(cur.AmneziaPremiumProtocol)
		response.Success(w, AmneziaPremiumGatewayStateData{
			SupportTag:  supportTag,
			Protocol:    proto,
			CountryCode: cur.AmneziaPremiumServerCountry,
			AWGBackend:  premiumAWGBackend(cur.AmneziaPremiumAWGBackend),
		})
	default:
		response.MethodNotAllowed(w)
	}
}

// premiumAWGBackend normalizes the two backends supported by the existing
// AWG tunnel service. Empty means the stored value is invalid; callers that
// need a default use nativewg.
func premiumAWGBackend(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "nativewg":
		return "nativewg"
	case "kernel":
		return "kernel"
	default:
		return ""
	}
}

var (
	errPremiumGatewayNoKey  = errors.New("amnezia premium gateway: no subscription key")
	errPremiumGatewayBadKey = errors.New("amnezia premium gateway: invalid subscription key")
)

// gatewayConfigData does the one external Gateway request shared by the raw
// config endpoint and the atomic runtime switch endpoint. It deliberately
// does not persist the selected country/protocol: a failed runtime apply must
// not become the UI's new "active" state.
func (h *AmneziaPremiumHandler) gatewayConfigData(
	ctx context.Context,
	countryInput, protocolInput string,
) (AmneziaPremiumGatewayConfigData, error) {
	country := strings.ToLower(strings.TrimSpace(countryInput))
	if country == "" {
		return AmneziaPremiumGatewayConfigData{}, fmt.Errorf("страна не выбрана")
	}
	if len(country) > maxCountryCodeLen {
		return AmneziaPremiumGatewayConfigData{}, fmt.Errorf("код страны длиннее %d байт", maxCountryCodeLen)
	}
	protocol, err := normalizePremiumProtocol(protocolInput)
	if err != nil {
		return AmneziaPremiumGatewayConfigData{}, err
	}

	key := h.subscriptionKey()
	if strings.TrimSpace(key) == "" {
		return AmneziaPremiumGatewayConfigData{}, errPremiumGatewayNoKey
	}
	sub, err := amneziagw.DecodeSubscriptionKey(key)
	if err != nil {
		return AmneziaPremiumGatewayConfigData{}, fmt.Errorf("%w: %v", errPremiumGatewayBadKey, err)
	}
	tag, err := h.ensurePremiumSupportTag(nil)
	if err != nil {
		return AmneziaPremiumGatewayConfigData{}, fmt.Errorf("сохранить Support tag: %w", err)
	}

	publicKey := ""
	privateKey := ""
	switch protocol {
	case "awg":
		privateKey, publicKey, err = amneziagw.GenerateAWGKeyPair()
	case "vless":
		publicKey = amneziagw.NewUUID()
	}
	if err != nil {
		return AmneziaPremiumGatewayConfigData{}, err
	}

	gw, err := amneziagw.NewClient(nil)
	if err != nil {
		return AmneziaPremiumGatewayConfigData{}, err
	}
	serverConfig, err := gw.Config(ctx, amneziagw.ConfigRequest{
		InstallationUUID: tag,
		UserCountryCode:   sub.UserCountryCode,
		ServerCountryCode: country,
		ServiceType:       sub.ServiceType,
		ServiceProtocol:   protocol,
		PublicKey:         publicKey,
		AuthData:          sub.AuthData,
	})
	if err != nil {
		return AmneziaPremiumGatewayConfigData{}, err
	}

	out := AmneziaPremiumGatewayConfigData{
		CountryCode: country,
		Protocol:    protocol,
		SupportTag:  tag,
	}
	switch protocol {
	case "awg":
		out.Config, err = amneziagw.ExtractAWGConf(serverConfig, privateKey)
	case "vless":
		var xray []byte
		xray, err = amneziagw.ExtractXrayClientConfig(serverConfig)
		if err == nil {
			out.Link = "vpn://" + base64.RawURLEncoding.EncodeToString(xray) + "#amnezia-premium"
			var parsed *vlink.ParsedOutbound
			parsed, err = vlink.ParseLink(out.Link)
			if err == nil {
				out.Outbound = parsed.Outbound
			}
		}
	}
	if err != nil {
		return AmneziaPremiumGatewayConfigData{}, err
	}
	return out, nil
}

func premiumGatewayHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errPremiumGatewayNoKey):
		response.ErrorWithStatus(w, http.StatusBadRequest,
			"Ключ подписки Amnezia не указан", codePremiumNoKey)
	case errors.Is(err, errPremiumGatewayBadKey):
		response.ErrorWithStatus(w, http.StatusUnprocessableEntity,
			"Ключ подписки не удалось разобрать", codePremiumKeyRejected)
	default:
		var ge *amneziagw.GatewayError
		if errors.As(err, &ge) {
			status := http.StatusBadGateway
			code := codePremiumServiceUnavailable
			if ge.Status == http.StatusForbidden {
				status = http.StatusForbidden
				code = codePremiumForbidden
			}
			response.ErrorWithStatus(w, status, ge.Error(), code)
			return
		}
		response.ErrorWithStatus(w, http.StatusBadGateway, err.Error(), codePremiumServiceUnavailable)
	}
}

// GatewayConfig obtains a reusable device config through Amnezia Gateway.
// Unlike the legacy CP download-config flow this uses installation_uuid
// (Support tag), so country/protocol changes update the same logical device.
func (h *AmneziaPremiumHandler) GatewayConfig(w http.ResponseWriter, r *http.Request) {
	req, ok := parseJSON[AmneziaPremiumGatewayConfigRequest](w, r, http.MethodPost)
	if !ok {
		return
	}
	out, err := h.gatewayConfigData(r.Context(), req.CountryCode, req.Protocol)
	if err != nil {
		premiumGatewayHTTPError(w, err)
		return
	}
	if err := h.settings.Update(func(s *storage.Settings) error {
		s.AmneziaPremiumProtocol = out.Protocol
		s.AmneziaPremiumServerCountry = out.CountryCode
		return nil
	}); err != nil {
		response.InternalError(w, err.Error())
		return
	}
	h.bus.PublishInvalidated(events.ResourceAmneziaPremiumCatalog, "gateway-config")
	response.Success(w, out)
}

// AmneziaPremiumSwitchRequest atomically changes the active Premium endpoint.
// Backend is consulted only when an AWG tunnel must be created for the first
// time; existing AWG tunnels keep their current backend.
type AmneziaPremiumSwitchRequest struct {
	CountryCode string `json:"countryCode" example:"nl"`
	Protocol    string `json:"protocol" example:"awg" enums:"awg,vless"`
	AWGBackend  string `json:"awgBackend,omitempty" example:"nativewg" enums:"nativewg,kernel"`
}

type AmneziaPremiumSwitchData struct {
	CountryCode string `json:"countryCode"`
	Protocol    string `json:"protocol"`
	SupportTag  string `json:"supportTag"`
	AWGTunnelID string `json:"awgTunnelId,omitempty"`
	VLESSTag    string `json:"vlessTag,omitempty"`
}

// Switch applies a freshly fetched Gateway config to the appropriate runtime.
// AWG stays on the existing native/kernel tunnel implementation. VLESS uses
// the existing sing-box tunnel operator and its Xray->sing-box converter.
func (h *AmneziaPremiumHandler) Switch(w http.ResponseWriter, r *http.Request) {
	req, ok := parseJSON[AmneziaPremiumSwitchRequest](w, r, http.MethodPost)
	if !ok {
		return
	}
	if h.tunnelSvc == nil {
		response.ErrorWithStatus(w, http.StatusServiceUnavailable,
			"AWG runtime не подключён", codePremiumServiceUnavailable)
		return
	}

	protocol, err := normalizePremiumProtocol(req.Protocol)
	if err != nil {
		response.BadRequest(w, err.Error())
		return
	}
	backend := premiumAWGBackend(req.AWGBackend)
	if backend == "" {
		response.BadRequest(w, "Поддерживаются только backend nativewg и kernel")
		return
	}
	cur, err := h.settings.Get()
	if err != nil {
		response.InternalError(w, err.Error())
		return
	}
	if strings.TrimSpace(req.AWGBackend) == "" {
		backend = premiumAWGBackend(cur.AmneziaPremiumAWGBackend)
	}

	cfg, err := h.gatewayConfigData(r.Context(), req.CountryCode, protocol)
	if err != nil {
		premiumGatewayHTTPError(w, err)
		return
	}

	awgID := strings.TrimSpace(cur.AmneziaPremiumAWGTunnelID)
	vlessTag := strings.TrimSpace(cur.AmneziaPremiumVLESSTag)

	switch protocol {
	case "awg":
		awgID, err = h.applyPremiumAWG(r.Context(), awgID, cfg.Config, cfg.CountryCode, backend)
	case "vless":
		if h.singboxOp == nil {
			err = errors.New("sing-box runtime не подключён")
			break
		}
		vlessTag, err = h.applyPremiumVLESS(r.Context(), vlessTag, cfg.Link, cfg.Outbound)
		// When moving from AWG to VLESS the old AWG interface must not keep a
		// competing default route. A stop failure aborts the switch so the UI
		// does not claim VLESS is active while AWG is still up.
		if err == nil && awgID != "" {
			state := h.tunnelSvc.GetState(r.Context(), awgID)
			if state.State == tunnel.StateRunning || state.State == tunnel.StateStarting || state.State == tunnel.StateBroken {
				if stopErr := h.tunnelSvc.Stop(r.Context(), awgID); stopErr != nil {
					err = fmt.Errorf("остановить прежний AWG туннель: %w", stopErr)
				}
			}
		}
	}
	if err != nil {
		response.ErrorWithStatus(w, http.StatusBadGateway, err.Error(), codePremiumServiceUnavailable)
		return
	}

	if err := h.settings.Update(func(s *storage.Settings) error {
		s.AmneziaPremiumProtocol = protocol
		s.AmneziaPremiumServerCountry = cfg.CountryCode
		s.AmneziaPremiumAWGBackend = backend
		s.AmneziaPremiumAWGTunnelID = awgID
		s.AmneziaPremiumVLESSTag = vlessTag
		return nil
	}); err != nil {
		response.InternalError(w, err.Error())
		return
	}

	h.bus.PublishInvalidated(events.ResourceAmneziaPremiumCatalog, "gateway-switch")
	h.bus.PublishInvalidated(events.ResourceTunnels, "premium-switch")
	h.bus.PublishInvalidated(events.ResourceSingboxTunnels, "premium-switch")
	response.Success(w, AmneziaPremiumSwitchData{
		CountryCode: cfg.CountryCode,
		Protocol:    protocol,
		SupportTag:  cfg.SupportTag,
		AWGTunnelID: awgID,
		VLESSTag:    vlessTag,
	})
}

func (h *AmneziaPremiumHandler) applyPremiumAWG(
	ctx context.Context,
	id, conf, country, backend string,
) (string, error) {
	if strings.TrimSpace(conf) == "" {
		return "", errors.New("Gateway вернул пустую AWG конфигурацию")
	}

	if id != "" {
		if current, err := h.tunnelSvc.Get(ctx, id); err == nil && current != nil {
			// Existing tunnel backend wins. ReplaceConfig intentionally
			// preserves it and restarts a running tunnel itself.
			state := h.tunnelSvc.GetState(ctx, id)
			countryCopy := country
			if err := h.tunnelSvc.ReplaceConfig(ctx, id, conf, current.Name,
				tunnelservice.ReplaceOptions{AmneziaCountry: &countryCopy}); err != nil {
				return "", err
			}
			if state.State != tunnel.StateRunning && state.State != tunnel.StateStarting && state.State != tunnel.StateBroken {
				if err := h.tunnelSvc.Start(ctx, id); err != nil {
					return id, err
				}
			}
			return id, nil
		}
	}

	name := "awg-" + strings.ToLower(country)
	created, err := h.tunnelSvc.Import(ctx, conf, name, backend,
		tunnelservice.ImportLink{AmneziaCountry: country})
	if err != nil {
		return "", err
	}
	if created == nil || created.ID == "" {
		return "", errors.New("AWG туннель создан без идентификатора")
	}
	if err := h.tunnelSvc.Start(ctx, created.ID); err != nil {
		// Return the id so a retry can reuse the already-created tunnel rather
		// than producing a duplicate after a transient start failure.
		_ = h.settings.Update(func(s *storage.Settings) error {
			s.AmneziaPremiumAWGTunnelID = created.ID
			s.AmneziaPremiumAWGBackend = backend
			return nil
		})
		return created.ID, err
	}
	return created.ID, nil
}

func (h *AmneziaPremiumHandler) applyPremiumVLESS(
	ctx context.Context,
	tag, link string,
	outbound json.RawMessage,
) (string, error) {
	if h.singboxOp == nil {
		return "", errors.New("sing-box runtime не подключён")
	}
	if len(outbound) == 0 || strings.TrimSpace(link) == "" {
		return "", errors.New("Gateway вернул пустую VLESS конфигурацию")
	}

	status := h.singboxOp.GetStatus(ctx)
	if !status.Installed {
		if err := h.singboxOp.Install(ctx); err != nil {
			return "", fmt.Errorf("установить sing-box: %w", err)
		}
		status = h.singboxOp.GetStatus(ctx)
	}

	if tag != "" {
		if _, err := h.singboxOp.GetTunnel(ctx, tag); err == nil {
			if err := h.singboxOp.UpdateTunnel(ctx, tag, outbound); err != nil {
				return "", err
			}
			if !status.Running {
				if err := h.singboxOp.Control(ctx, "start"); err != nil {
					return tag, err
				}
			}
			return tag, nil
		} else if !errors.Is(err, singbox.ErrTunnelNotFound) {
			return "", err
		}
	}

	added, parseErrs, err := h.singboxOp.AddTunnels(ctx, link)
	if err != nil {
		return "", err
	}
	if len(added) == 0 {
		if len(parseErrs) > 0 && parseErrs[0].Err != nil {
			return "", parseErrs[0].Err
		}
		return "", errors.New("sing-box не добавил VLESS outbound")
	}
	tag = added[0].Tag
	if !status.Running {
		if err := h.singboxOp.Control(ctx, "start"); err != nil {
			_ = h.settings.Update(func(s *storage.Settings) error {
				s.AmneziaPremiumVLESSTag = tag
				return nil
			})
			return tag, err
		}
	}
	return tag, nil
}
