package amneziagw

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
)

const (
	maxVPNPayload = 4 << 20
	awgPrivateKeyPlaceholder = "$WIREGUARD_CLIENT_PRIVATE_KEY"
)

// AccountKey is the non-secret metadata plus API credential carried by an
// Amnezia Premium V2 vpn:// key.
type AccountKey struct {
	Name            string
	Description     string
	ConfigVersion   int
	ServiceType     string
	ServiceProtocol string
	UserCountryCode string
	APIKey          string
}

type premiumKeyJSON struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	ConfigVersion int    `json:"config_version"`
	APIConfig     struct {
		ServiceType     string `json:"service_type"`
		ServiceProtocol string `json:"service_protocol"`
		UserCountryCode string `json:"user_country_code"`
	} `json:"api_config"`
	AuthData struct {
		APIKey string `json:"api_key"`
	} `json:"auth_data"`
}

// ParseVPNKey parses the Premium V2 key produced by AmneziaVPN. The official
// exporter prepends 00 00 00 ff to a zlib stream whose qCompress 4-byte size
// prefix has been removed. Older/plain test fixtures are accepted as well.
func ParseVPNKey(input string) (AccountKey, error) {
	raw, err := decodeVPNData(input)
	if err != nil {
		return AccountKey{}, err
	}
	var in premiumKeyJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return AccountKey{}, fmt.Errorf("amnezia gateway: premium key JSON: %w", err)
	}
	out := AccountKey{
		Name:            strings.TrimSpace(in.Name),
		Description:     strings.TrimSpace(in.Description),
		ConfigVersion:   in.ConfigVersion,
		ServiceType:     strings.TrimSpace(in.APIConfig.ServiceType),
		ServiceProtocol: strings.ToLower(strings.TrimSpace(in.APIConfig.ServiceProtocol)),
		UserCountryCode: strings.ToLower(strings.TrimSpace(in.APIConfig.UserCountryCode)),
		APIKey:          strings.TrimSpace(in.AuthData.APIKey),
	}
	if out.APIKey == "" {
		return AccountKey{}, errors.New("amnezia gateway: key has no auth_data.api_key")
	}
	if out.ServiceType == "" {
		return AccountKey{}, errors.New("amnezia gateway: key has no api_config.service_type")
	}
	return out, nil
}

// IsPremiumV2Key is a cheap semantic probe used to select the Gateway flow
// without breaking legacy Control Panel vpn:// keys.
func IsPremiumV2Key(input string) bool {
	_, err := ParseVPNKey(input)
	return err == nil
}

func decodeVPNData(input string) ([]byte, error) {
	s := strings.TrimSpace(input)
	if !strings.HasPrefix(strings.ToLower(s), "vpn://") {
		return nil, errors.New("amnezia gateway: key must start with vpn://")
	}
	encoded := strings.TrimSpace(s[len("vpn://"):])
	decoded, err := decodeBase64URL(encoded)
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: vpn base64: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("amnezia gateway: empty vpn payload")
	}

	// Premium V2 export signature. It is not the qCompress size prefix.
	if len(decoded) >= 4 && bytes.Equal(decoded[:4], []byte{0, 0, 0, 0xff}) {
		decoded = decoded[4:]
	}

	if out, ok := inflate(decoded); ok {
		return out, nil
	}
	// Full qCompress blob: first 4 bytes are the big-endian uncompressed size.
	if len(decoded) > 4 {
		if out, ok := inflate(decoded[4:]); ok {
			return out, nil
		}
	}
	// Fixtures and future formats may carry plain JSON.
	if json.Valid(decoded) {
		return decoded, nil
	}
	return nil, errors.New("amnezia gateway: unsupported vpn payload")
}

func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func inflate(data []byte) ([]byte, bool) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxVPNPayload+1))
	if err != nil || len(out) > maxVPNPayload {
		return nil, false
	}
	return out, true
}

// BasePayload builds the fields the official GatewayPayloadBuilder adds to
// requests. installationUUID is the user-visible Support tag in AWG Manager.
func BasePayload(installationUUID, version string) map[string]any {
	p := map[string]any{
		"os_version":        runtime.GOOS,
		"app_version":       strings.TrimSpace(version),
		"cli_name":          "AWG Manager",
		"installation_uuid": strings.TrimSpace(installationUUID),
	}
	for k, v := range p {
		if s, ok := v.(string); ok && s == "" {
			delete(p, k)
		}
	}
	return p
}

// AccountInfo retrieves the account document used to populate the Premium
// catalog. It intentionally returns the decrypted Gateway JSON unchanged so
// the API layer can keep its existing whitelist projection.
func (c *Client) AccountInfo(ctx context.Context, key AccountKey, installationUUID, version string) ([]byte, error) {
	payload := BasePayload(installationUUID, version)
	payload["user_country_code"] = key.UserCountryCode
	payload["service_type"] = key.ServiceType
	payload["auth_data"] = map[string]string{"api_key": key.APIKey}
	payload["cli_version"] = strings.TrimSpace(version)
	return c.PostJSON(ctx, "v1/account_info", payload)
}

// IssueOptions describes one country/protocol switch.
type IssueOptions struct {
	CountryCode      string
	Protocol         string
	InstallationUUID string
	Version          string
}

// IssuedConfig is the protocol-specific material extracted from the server
// config returned by v1/config.
type IssuedConfig struct {
	CountryCode string
	Protocol    string
	ServerJSON  []byte
	AWGConf     string
	XrayJSON    string
	PublicKey   string
}

// IssueConfig follows AmneziaVPN's updateServiceFromGateway flow. AWG sends a
// freshly generated X25519 public key and substitutes the matching private key
// into the returned config. VLESS sends a fresh UUID.
func (c *Client) IssueConfig(ctx context.Context, key AccountKey, opts IssueOptions) (IssuedConfig, error) {
	country := strings.ToLower(strings.TrimSpace(opts.CountryCode))
	protocol := strings.ToLower(strings.TrimSpace(opts.Protocol))
	if country == "" {
		return IssuedConfig{}, errors.New("amnezia gateway: country is empty")
	}
	if protocol != "awg" && protocol != "vless" {
		return IssuedConfig{}, fmt.Errorf("amnezia gateway: unsupported protocol %q", protocol)
	}

	var publicKey, privateKey string
	switch protocol {
	case "awg":
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return IssuedConfig{}, fmt.Errorf("amnezia gateway: generate X25519 key: %w", err)
		}
		privateKey = base64.StdEncoding.EncodeToString(priv.Bytes())
		publicKey = base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	case "vless":
		id, err := NewUUID()
		if err != nil {
			return IssuedConfig{}, err
		}
		publicKey = id
	}

	payload := BasePayload(opts.InstallationUUID, opts.Version)
	payload["user_country_code"] = key.UserCountryCode
	payload["server_country_code"] = country
	payload["service_type"] = key.ServiceType
	payload["service_protocol"] = protocol
	payload["public_key"] = publicKey
	payload["auth_data"] = map[string]string{"api_key": key.APIKey}

	body, err := c.PostJSON(ctx, "v1/config", payload)
	if err != nil {
		return IssuedConfig{}, err
	}
	var response struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return IssuedConfig{}, fmt.Errorf("amnezia gateway: config response JSON: %w", err)
	}
	if strings.TrimSpace(response.Config) == "" {
		return IssuedConfig{}, errors.New("amnezia gateway: config response has no config")
	}

	serverJSON, err := decodeVPNData(response.Config)
	if err != nil {
		return IssuedConfig{}, fmt.Errorf("amnezia gateway: decode issued config: %w", err)
	}
	if protocol == "awg" {
		serverJSON = []byte(strings.ReplaceAll(string(serverJSON), awgPrivateKeyPlaceholder, privateKey))
	}

	out := IssuedConfig{
		CountryCode: country,
		Protocol:    protocol,
		ServerJSON:  append([]byte(nil), serverJSON...),
		PublicKey:   publicKey,
	}
	switch protocol {
	case "awg":
		out.AWGConf, err = extractProtocolNative(serverJSON, "awg")
	case "vless":
		out.XrayJSON, err = extractProtocolNative(serverJSON, "xray")
	}
	if err != nil {
		return IssuedConfig{}, err
	}
	return out, nil
}

// extractProtocolNative extracts a protocol's last_config from the Gateway
// server document. AWG last_config normally wraps the .conf as {"config":...};
// Xray may store the full native JSON directly.
func extractProtocolNative(serverJSON []byte, protocol string) (string, error) {
	var root map[string]any
	if err := json.Unmarshal(serverJSON, &root); err != nil {
		return "", fmt.Errorf("amnezia gateway: server config JSON: %w", err)
	}
	containers, _ := root["containers"].([]any)
	for _, raw := range containers {
		container, _ := raw.(map[string]any)
		if container == nil {
			continue
		}
		proto, _ := container[protocol].(map[string]any)
		if proto == nil {
			continue
		}
		native := unwrapLastConfig(proto["last_config"], protocol)
		if native != "" {
			return native, nil
		}
	}
	return "", fmt.Errorf("amnezia gateway: %s last_config not found", protocol)
}

func unwrapLastConfig(raw any, protocol string) string {
	switch v := raw.(type) {
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return ""
		}
		if protocol == "awg" && strings.Contains(s, "[Interface]") {
			return s
		}
		var obj map[string]any
		if json.Unmarshal([]byte(s), &obj) == nil {
			if config, _ := obj["config"].(string); strings.TrimSpace(config) != "" {
				return config
			}
			if protocol == "xray" {
				if _, ok := obj["outbounds"]; ok {
					return s
				}
			}
		}
	case map[string]any:
		if config, _ := v["config"].(string); strings.TrimSpace(config) != "" {
			return config
		}
		if protocol == "xray" {
			if _, ok := v["outbounds"]; ok {
				b, _ := json.Marshal(v)
				return string(b)
			}
		}
	}
	return ""
}

// NewUUID returns a RFC 4122 version-4 UUID without adding a dependency.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("amnezia gateway: generate UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
