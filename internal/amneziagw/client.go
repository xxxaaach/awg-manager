package amneziagw

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	// DefaultEndpoint is the production gateway used by the official
	// AmneziaVPN client. The path passed to PostJSON is appended to it.
	DefaultEndpoint = "http://gw.amnezia.org:80/"

	maxResponseBody = 4 << 20
	aesKeyBytes     = 32
	aesIVBytes      = 32
	aesBlockBytes   = 16
	aesSaltBytes    = 8
)

// ProductionPublicKeyPEM is the public RSA key used by the production
// Amnezia Gateway. It is public material: it encrypts the per-request AES
// envelope and contains no account credentials.
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

// APIError is an application-level error returned inside the decrypted
// Gateway JSON body.
type APIError struct {
	Status  int
	Message string
	Body    []byte
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		if e.Status > 0 {
			return fmt.Sprintf("amnezia gateway: status %d: %s", e.Status, e.Message)
		}
		return "amnezia gateway: " + e.Message
	}
	if e.Status > 0 {
		return fmt.Sprintf("amnezia gateway: status %d", e.Status)
	}
	return "amnezia gateway: request rejected"
}

// Client implements the direct Amnezia Gateway encrypted transport. The
// official client also has S3-discovered proxy failover; that can be layered
// on later without changing this API. Direct transport is deliberately kept
// self-contained so router builds do not need cgo or an extra module.
type Client struct {
	http      *http.Client
	endpoint  string
	publicKey []byte
}

// NewClient creates a production client. httpClient may be nil.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{
		http:      httpClient,
		endpoint:  DefaultEndpoint,
		publicKey: []byte(ProductionPublicKeyPEM),
	}
}

// NewClientForEndpoint is primarily a test seam. It is also useful if the
// production gateway endpoint is ever rotated before a release can be cut.
func NewClientForEndpoint(httpClient *http.Client, endpoint string, publicKeyPEM []byte) *Client {
	c := NewClient(httpClient)
	if strings.TrimSpace(endpoint) != "" {
		c.endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/") + "/"
	}
	if len(publicKeyPEM) != 0 {
		c.publicKey = append([]byte(nil), publicKeyPEM...)
	}
	return c
}

// PostJSON encrypts payload using the same RSA+AES envelope as AmneziaVPN,
// POSTs it to the gateway, decrypts the response and returns the API JSON.
func (c *Client) PostJSON(ctx context.Context, path string, payload any) ([]byte, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: marshal payload: %w", err)
	}
	env, err := buildEnvelope(plain, c.publicKey)
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: build envelope: %w", err)
	}

	url := strings.TrimRight(c.endpoint, "/") + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(env.body))
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return nil, fmt.Errorf("amnezia gateway: read response: %w", err)
	}
	if len(raw) > maxResponseBody {
		return nil, fmt.Errorf("amnezia gateway: response exceeds %d bytes", maxResponseBody)
	}

	plainResp, err := aesDecryptCBC(raw, env.key, env.iv)
	if err != nil {
		// A proxy/WAF may return plaintext HTML. Do not surface the body:
		// it can be arbitrarily large/noisy and is not useful to API callers.
		return nil, fmt.Errorf("amnezia gateway: decrypt response (http %d): %w", resp.StatusCode, err)
	}

	if apiErr := parseAPIError(plainResp); apiErr != nil {
		return nil, apiErr
	}
	return plainResp, nil
}

func parseAPIError(body []byte) error {
	var meta struct {
		HTTPStatus int    `json:"http_status"`
		Message    string `json:"message"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil
	}
	if meta.HTTPStatus >= 400 {
		return &APIError{
			Status:  meta.HTTPStatus,
			Message: strings.TrimSpace(meta.Message),
			Body:    append([]byte(nil), body...),
		}
	}
	return nil
}

type keysPayload struct {
	AESKey  string `json:"aes_key"`
	AESIV   string `json:"aes_iv"`
	AESSalt string `json:"aes_salt"`
}

type requestBody struct {
	KeyPayload string `json:"key_payload"`
	APIPayload string `json:"api_payload"`
}

type envelope struct {
	body []byte
	key  []byte
	iv   []byte
}

// buildEnvelope mirrors libagw / the official AmneziaVPN GatewayController.
// The protocol intentionally transports a 32-byte IV while AES-CBC uses the
// first 16 bytes only; changing that would make requests incompatible.
func buildEnvelope(payload, publicKeyPEM []byte) (envelope, error) {
	pub, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return envelope{}, err
	}

	key := make([]byte, aesKeyBytes)
	iv := make([]byte, aesIVBytes)
	salt := make([]byte, aesSaltBytes)
	for _, dst := range [][]byte{key, iv, salt} {
		if _, err := rand.Read(dst); err != nil {
			return envelope{}, err
		}
	}

	keysJSON, err := json.Marshal(keysPayload{
		AESKey:  base64.StdEncoding.EncodeToString(key),
		AESIV:   base64.StdEncoding.EncodeToString(iv),
		AESSalt: base64.StdEncoding.EncodeToString(salt),
	})
	if err != nil {
		return envelope{}, err
	}
	encryptedKeys, err := rsa.EncryptPKCS1v15(rand.Reader, pub, keysJSON)
	if err != nil {
		return envelope{}, fmt.Errorf("rsa encrypt: %w", err)
	}
	encryptedPayload, err := aesEncryptCBC(payload, key, iv)
	if err != nil {
		return envelope{}, err
	}

	body, err := json.Marshal(requestBody{
		KeyPayload: base64.StdEncoding.EncodeToString(encryptedKeys),
		APIPayload: base64.StdEncoding.EncodeToString(encryptedPayload),
	})
	if err != nil {
		return envelope{}, err
	}
	return envelope{body: body, key: key, iv: iv}, nil
}

func parsePublicKey(src []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(src)
	if block == nil {
		return nil, errors.New("public key PEM decode failed")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("gateway public key is not RSA")
	}
	return pub, nil
}

func aesEncryptCBC(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) < aesBlockBytes {
		return nil, errors.New("iv too short")
	}
	pad := aesBlockBytes - len(data)%aesBlockBytes
	padded := append(append([]byte(nil), data...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv[:aesBlockBytes]).CryptBlocks(out, padded)
	return out, nil
}

func aesDecryptCBC(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) < aesBlockBytes || len(data) == 0 || len(data)%aesBlockBytes != 0 {
		return nil, errors.New("bad ciphertext/iv length")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv[:aesBlockBytes]).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad <= 0 || pad > aesBlockBytes || pad > len(out) {
		return nil, errors.New("bad padding")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errors.New("bad padding")
		}
	}
	return out[:len(out)-pad], nil
}
