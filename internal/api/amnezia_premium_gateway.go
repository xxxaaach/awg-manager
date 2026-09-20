package api

import (
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
	"github.com/hoaxisr/awg-manager/internal/singbox/vlink"
	"github.com/hoaxisr/awg-manager/internal/storage"
)

const maxPremiumSupportTagLen = 128

type AmneziaPremiumGatewayStateData struct {
	SupportTag  string `json:"supportTag"`
	Protocol    string `json:"protocol"`
	CountryCode string `json:"countryCode"`
}

type AmneziaPremiumGatewayStateResponse struct {
	Success bool                           `json:"success"`
	Data    AmneziaPremiumGatewayStateData `json:"data"`
}

type AmneziaPremiumGatewayStateRequest struct {
	SupportTag  *string `json:"supportTag,omitempty"`
	Protocol    *string `json:"protocol,omitempty"`
	CountryCode *string `json:"countryCode,omitempty"`
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
		})
	default:
		response.MethodNotAllowed(w)
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
	country := strings.ToLower(strings.TrimSpace(req.CountryCode))
	if country == "" {
		response.BadRequest(w, "Страна не выбрана")
		return
	}
	if len(country) > maxCountryCodeLen {
		response.BadRequest(w, fmt.Sprintf("Код страны длиннее %d байт", maxCountryCodeLen))
		return
	}
	protocol, err := normalizePremiumProtocol(req.Protocol)
	if err != nil {
		response.BadRequest(w, err.Error())
		return
	}

	key := h.subscriptionKey()
	if strings.TrimSpace(key) == "" {
		response.ErrorWithStatus(w, http.StatusBadRequest, "Ключ подписки Amnezia не указан", codePremiumNoKey)
		return
	}
	sub, err := amneziagw.DecodeSubscriptionKey(key)
	if err != nil {
		response.ErrorWithStatus(w, http.StatusUnprocessableEntity, "Ключ подписки не удалось разобрать", codePremiumKeyRejected)
		return
	}
	tag, err := h.ensurePremiumSupportTag(nil)
	if err != nil {
		response.InternalError(w, "Не удалось сохранить Support tag: "+err.Error())
		return
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
		response.InternalError(w, err.Error())
		return
	}

	gw, err := amneziagw.NewClient(nil)
	if err != nil {
		response.InternalError(w, err.Error())
		return
	}
	serverConfig, err := gw.Config(r.Context(), amneziagw.ConfigRequest{
		InstallationUUID: tag,
		UserCountryCode:   sub.UserCountryCode,
		ServerCountryCode: country,
		ServiceType:       sub.ServiceType,
		ServiceProtocol:   protocol,
		PublicKey:         publicKey,
		AuthData:          sub.AuthData,
	})
	if err != nil {
		var ge *amneziagw.GatewayError
		if errors.As(err, &ge) {
			status := http.StatusBadGateway
			if ge.Status == http.StatusForbidden {
				status = http.StatusForbidden
			}
			response.ErrorWithStatus(w, status, ge.Error(), codePremiumServiceUnavailable)
			return
		}
		response.ErrorWithStatus(w, http.StatusBadGateway, err.Error(), codePremiumServiceUnavailable)
		return
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
		response.ErrorWithStatus(w, http.StatusBadGateway, err.Error(), codePremiumServiceUnavailable)
		return
	}

	if err := h.settings.Update(func(s *storage.Settings) error {
		s.AmneziaPremiumProtocol = protocol
		s.AmneziaPremiumServerCountry = country
		return nil
	}); err != nil {
		response.InternalError(w, err.Error())
		return
	}
	h.bus.PublishInvalidated(events.ResourceAmneziaPremiumCatalog, "gateway-config")
	response.Success(w, out)
}
