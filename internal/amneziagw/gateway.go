// Package amneziagw implements the small subset of the Amnezia Gateway
// protocol needed by the Premium integration.
//
// The wire format mirrors AmneziaVPN's GatewayController: an RSA-encrypted
// AES key/IV envelope plus an AES-256-CBC encrypted JSON payload. The gateway
// response body is encrypted with the same AES key and IV.
package amneziagw

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultEndpoint = "http://gw.amnezia.org:80/"
	// Keep this aligned with a currently accepted upstream AmneziaVPN build.
	// It is only client metadata sent to the Gateway, not awg-manager's own
	// version.
	DefaultClientVersion = "5.0.1.5"
	maxDecodedConfig      = 4 << 20
)

// ProductionPublicKeyPEM is the public Gateway RSA key embedded in the
// official AmneziaVPN production client. It is public material and is used
// only to encrypt the per-request AES envelope.
const ProductionPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj5mxl/4DL3Sk89ntxs5G
X3JawGQWIoq6rvNkOzNGuNgedNS2+pi6hZl3Izl1Io9om4KiUlMT6mgLO1hTr9q+
s7CYhlvroFA7ErucF+9L+7FCt0Igi0kIK/R2/vxd/2HaUrorn/aSvvutkYwbfxqW
SwtzE+RuBeDWGvEt937OW0oqYONPYv9E4T56Dz/EZ6v2t8ejAnKLbGD/GocMmipK
7etFSiSMAB2RmaztqTq4NleBepfO80XpYlW9pCSXuHcE8wxHczkzxsbyMAMsG/K3
vUQY6qPtohqqzSSBwa/8u2ptNHBeor7l7DdYXeR/Nqcc4z92VUkZ5lOVR4evkS5V
/wQqp5tnOJEj3NjUhEhXFoNEapbZd1bh6iQoUk7jC1TdvKJ/nPKGZAsHRpr0rNKz
fx/N/Oo6lr2yh/+ps6VxTkbPmB6E85WOO3UvjImZUY0XQdBjWle/4iJLdEC77Nr0
jXhdgeypucy6jkB6iBHMeVMlrNMEV7UxoBR/cCNx55zu/8sml5ByiDvCDT7sRomN
NgVt5S/FaVjYuzFUifJ12ToChXFgESKFmuso7WluEaWvMIGREdrMrKQKHfYLOzWF
2B5ZJDqw4o03fU4J/6rw61M1b+rjVpXMjPnzc2A+RgcjTvXv955gfZkwe4lt5wk/
3j8zMVo3+zLrMTAaEeIUM0UCAwEAAQ==
-----END PUBLIC KEY-----
`

type Subscription struct {
	ServiceType     string
	UserCountryCode string
	AuthData        map[string]any
}

type ConfigRequest struct {
	InstallationUUID string
	UserCountryCode   string
	ServerCountryCode string
	ServiceType       string
	ServiceProtocol   string
	PublicKey         string
	AuthData          map[string]any
}

type GatewayError struct {
	Status  int
	Message string
}

func (e *GatewayError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("amnezia gateway: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("amnezia gateway: HTTP %d", e.Status)
}

type Client struct {
	endpoint string
	pub      *rsa.PublicKey
	http     *http.Client
}

func NewClient(httpClient *http.Client) (*Client, error) {
	block, _ := pem.Decode([]byte(ProductionPublicKeyPEM))
	if block == nil {
		return nil, errors.New("amnezia gateway: invalid production public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: parse public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("amnezia gateway: public key is not RSA")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{endpoint: DefaultEndpoint, pub: pub, http: httpClient}, nil
}

func DecodeSubscriptionKey(input string) (Subscription, error) {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "vpn://")
	if s == "" {
		return Subscription{}, errors.New("amnezia gateway: empty subscription key")
	}
	raw, err := decodeBase64URL(s)
	if err != nil {
		return Subscription{}, fmt.Errorf("amnezia gateway: decode vpn key: %w", err)
	}
	plain, err := decompressQt(raw)
	if err != nil {
		return Subscription{}, err
	}
	var doc struct {
		APIConfig struct {
			ServiceType     string `json:"service_type"`
			UserCountryCode string `json:"user_country_code"`
		} `json:"api_config"`
		AuthData map[string]any `json:"auth_data"`
	}
	if err := json.Unmarshal(plain, &doc); err != nil {
		return Subscription{}, fmt.Errorf("amnezia gateway: decode subscription JSON: %w", err)
	}
	if len(doc.AuthData) == 0 {
		return Subscription{}, errors.New("amnezia gateway: subscription key has no auth_data")
	}
	serviceType := strings.TrimSpace(doc.APIConfig.ServiceType)
	if serviceType == "" {
		serviceType = "amnezia-premium"
	}
	userCountry := strings.ToLower(strings.TrimSpace(doc.APIConfig.UserCountryCode))
	if userCountry == "" {
		userCountry = "ru"
	}
	return Subscription{
		ServiceType:     serviceType,
		UserCountryCode: userCountry,
		AuthData:        doc.AuthData,
	}, nil
}

func (c *Client) Config(ctx context.Context, req ConfigRequest) ([]byte, error) {
	payload := requestPayload(req)
	body, err := c.post(ctx, "v1/config", payload)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("amnezia gateway: decode config response: %w", err)
	}
	if strings.TrimSpace(envelope.Config) == "" {
		return nil, errors.New("amnezia gateway: config response is empty")
	}
	return DecodeVPNPayload(envelope.Config)
}

func (c *Client) NativeConfig(ctx context.Context, req ConfigRequest) (string, error) {
	payload := requestPayload(req)
	body, err := c.post(ctx, "v1/native_config", payload)
	if err != nil {
		return "", err
	}
	var envelope struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("amnezia gateway: decode native config response: %w", err)
	}
	if strings.TrimSpace(envelope.Config) == "" {
		return "", errors.New("amnezia gateway: native config response is empty")
	}
	return envelope.Config, nil
}

func requestPayload(req ConfigRequest) map[string]any {
	serviceType := strings.TrimSpace(req.ServiceType)
	if serviceType == "" {
		serviceType = "amnezia-premium"
	}
	p := map[string]any{
		"os_version":        "linux",
		"app_version":       DefaultClientVersion,
		"cli_name":          "AmneziaVPN",
		"app_language":      "ru",
		"installation_uuid": strings.TrimSpace(req.InstallationUUID),
		"user_country_code": strings.ToLower(strings.TrimSpace(req.UserCountryCode)),
		"server_country_code": strings.ToLower(strings.TrimSpace(req.ServerCountryCode)),
		"service_type":      serviceType,
		"service_protocol":  strings.ToLower(strings.TrimSpace(req.ServiceProtocol)),
		"public_key":        strings.TrimSpace(req.PublicKey),
		"auth_data":         req.AuthData,
	}
	return p
}

func (c *Client) post(ctx context.Context, path string, payload map[string]any) ([]byte, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	iv := make([]byte, 32)
	salt := make([]byte, 8)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	keyPayload, err := json.Marshal(map[string]string{
		"aes_key":  base64.StdEncoding.EncodeToString(key),
		"aes_iv":   base64.StdEncoding.EncodeToString(iv),
		"aes_salt": base64.StdEncoding.EncodeToString(salt),
	})
	if err != nil {
		return nil, err
	}
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, c.pub, keyPayload)
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: RSA encrypt: %w", err)
	}
	encryptedPayload, err := aesEncryptCBC(plain, key, iv[:aes.BlockSize])
	if err != nil {
		return nil, err
	}

	wire, err := json.Marshal(map[string]string{
		"key_payload": base64.StdEncoding.EncodeToString(encryptedKey),
		"api_payload": base64.StdEncoding.EncodeToString(encryptedPayload),
	})
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(c.endpoint, "/") + "/" + strings.TrimLeft(path, "/")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Client-Request-ID", NewUUID())

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDecodedConfig+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDecodedConfig {
		return nil, errors.New("amnezia gateway: response too large")
	}

	decrypted, decErr := aesDecryptCBC(raw, key, iv[:aes.BlockSize])
	if decErr != nil {
		// A few gateway/front-door failures are returned as plain JSON. Keep
		// the body only for extracting the public error message.
		decrypted = raw
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, gatewayHTTPError(resp.StatusCode, decrypted)
	}
	return decrypted, nil
}

func gatewayHTTPError(status int, body []byte) error {
	var msg struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(body, &msg)
	text := strings.TrimSpace(msg.Message)
	if text == "" {
		text = strings.TrimSpace(msg.Error)
	}
	if len(text) > 512 {
		text = text[:512]
	}
	return &GatewayError{Status: status, Message: text}
}

func GenerateAWGKeyPair() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is process-level exceptional. Returning an
		// all-zero UUID would silently merge device identities, so panic.
		panic("amneziagw: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func DecodeVPNPayload(input string) ([]byte, error) {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "vpn://")
	raw, err := decodeBase64URL(s)
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: decode returned vpn config: %w", err)
	}
	return decompressQt(raw)
}

// ExtractAWGConf finds the WireGuard/AmneziaWG client .conf embedded in an
// API-v2 Gateway config and substitutes the locally generated private key.
func ExtractAWGConf(serverConfig []byte, privateKey string) (string, error) {
	replaced := bytes.ReplaceAll(serverConfig, []byte("$WIREGUARD_CLIENT_PRIVATE_KEY"), []byte(privateKey))
	var root map[string]any
	if err := json.Unmarshal(replaced, &root); err != nil {
		return "", fmt.Errorf("amnezia gateway: parse AWG server config: %w", err)
	}
	containers, _ := root["containers"].([]any)
	for _, item := range containers {
		container, _ := item.(map[string]any)
		for _, key := range []string{"awg", "wireguard"} {
			proto, _ := container[key].(map[string]any)
			if proto == nil {
				continue
			}
			if conf := extractLastConfigConf(proto["last_config"]); conf != "" {
				return conf, nil
			}
		}
	}
	return "", errors.New("amnezia gateway: AWG client config not found")
}

func extractLastConfigConf(v any) string {
	switch x := v.(type) {
	case string:
		if strings.Contains(x, "[Interface]") {
			return x
		}
		var obj map[string]any
		if json.Unmarshal([]byte(x), &obj) == nil {
			if conf := asString(obj["config"]); conf != "" {
				return conf
			}
		}
	case map[string]any:
		return asString(x["config"])
	}
	return ""
}

// ExtractXrayClientConfig finds the Xray client JSON embedded in an Amnezia
// API-v2 server config. Gateway VLESS configs keep that JSON in last_config.
func ExtractXrayClientConfig(serverConfig []byte) ([]byte, error) {
	var root any
	if err := json.Unmarshal(serverConfig, &root); err != nil {
		return nil, fmt.Errorf("amnezia gateway: parse VLESS server config: %w", err)
	}
	if raw := findXrayConfig(root); len(raw) > 0 {
		return raw, nil
	}
	return nil, errors.New("amnezia gateway: VLESS/Xray client config not found")
}

func findXrayConfig(v any) []byte {
	switch x := v.(type) {
	case map[string]any:
		if obs, ok := x["outbounds"].([]any); ok && len(obs) > 0 {
			for _, item := range obs {
				if ob, ok := item.(map[string]any); ok {
					if strings.EqualFold(asString(ob["protocol"]), "vless") {
						if raw, err := json.Marshal(x); err == nil {
							return raw
						}
					}
				}
			}
		}
		if last := asString(x["last_config"]); last != "" {
			var parsed any
			if json.Unmarshal([]byte(last), &parsed) == nil {
				if raw := findXrayConfig(parsed); len(raw) > 0 {
					return raw
				}
			}
		}
		if wrapped := asString(x["config"]); wrapped != "" && strings.HasPrefix(strings.TrimSpace(wrapped), "{") {
			var parsed any
			if json.Unmarshal([]byte(wrapped), &parsed) == nil {
				if raw := findXrayConfig(parsed); len(raw) > 0 {
					return raw
				}
			}
		}
		for _, child := range x {
			if raw := findXrayConfig(child); len(raw) > 0 {
				return raw
			}
		}
	case []any:
		for _, child := range x {
			if raw := findXrayConfig(child); len(raw) > 0 {
				return raw
			}
		}
	}
	return nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func decodeBase64URL(s string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func decompressQt(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("amnezia gateway: empty compressed payload")
	}
	candidates := [][]byte{raw}
	if len(raw) > 4 {
		candidates = append([][]byte{raw[4:]}, candidates...)
	}
	for _, in := range candidates {
		zr, err := zlib.NewReader(bytes.NewReader(in))
		if err != nil {
			continue
		}
		out, readErr := io.ReadAll(io.LimitReader(zr, maxDecodedConfig+1))
		_ = zr.Close()
		if readErr == nil && len(out) <= maxDecodedConfig {
			return out, nil
		}
	}
	// Some legacy vpn:// values contain plain JSON rather than qCompress.
	if json.Valid(raw) {
		return raw, nil
	}
	return nil, errors.New("amnezia gateway: cannot decompress vpn payload")
}

func aesEncryptCBC(plain, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, block.BlockSize())
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

func aesDecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("amnezia gateway: invalid AES ciphertext length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return pkcs7Unpad(out, block.BlockSize())
}

func pkcs7Pad(in []byte, blockSize int) []byte {
	n := blockSize - len(in)%blockSize
	out := make([]byte, len(in)+n)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func pkcs7Unpad(in []byte, blockSize int) ([]byte, error) {
	if len(in) == 0 || len(in)%blockSize != 0 {
		return nil, errors.New("amnezia gateway: invalid PKCS#7 payload")
	}
	n := int(in[len(in)-1])
	if n == 0 || n > blockSize || n > len(in) {
		return nil, errors.New("amnezia gateway: invalid PKCS#7 padding")
	}
	for _, b := range in[len(in)-n:] {
		if int(b) != n {
			return nil, errors.New("amnezia gateway: invalid PKCS#7 padding")
		}
	}
	return in[:len(in)-n], nil
}
