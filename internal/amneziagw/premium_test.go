package amneziagw

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func premiumVPNFixture(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	signed := append([]byte{0, 0, 0, 0xff}, compressed.Bytes()...)
	return "vpn://" + base64.RawURLEncoding.EncodeToString(signed)
}

func TestParseVPNKeyPremiumV2(t *testing.T) {
	link := premiumVPNFixture(t, map[string]any{
		"name":           "Premium",
		"description":    "Amnezia Premium",
		"config_version": 2,
		"api_config": map[string]any{
			"service_type":      "premium",
			"service_protocol":  "AWG",
			"user_country_code": "RU",
		},
		"auth_data": map[string]any{
			"api_key": "test-api-key",
		},
	})

	got, err := ParseVPNKey(link)
	if err != nil {
		t.Fatalf("ParseVPNKey: %v", err)
	}
	if got.Name != "Premium" {
		t.Fatalf("Name=%q", got.Name)
	}
	if got.ServiceType != "premium" {
		t.Fatalf("ServiceType=%q", got.ServiceType)
	}
	if got.ServiceProtocol != "awg" {
		t.Fatalf("ServiceProtocol=%q", got.ServiceProtocol)
	}
	if got.UserCountryCode != "ru" {
		t.Fatalf("UserCountryCode=%q", got.UserCountryCode)
	}
	if got.APIKey != "test-api-key" {
		t.Fatalf("APIKey=%q", got.APIKey)
	}
}

func TestParseVPNKeyRejectsMissingCredential(t *testing.T) {
	link := premiumVPNFixture(t, map[string]any{
		"api_config": map[string]any{
			"service_type": "premium",
		},
		"auth_data": map[string]any{},
	})
	if _, err := ParseVPNKey(link); err == nil {
		t.Fatal("expected missing api_key error")
	}
}

func TestExtractProtocolNativeAWG(t *testing.T) {
	root := map[string]any{
		"containers": []any{
			map[string]any{
				"container": "amnezia-awg",
				"awg": map[string]any{
					"last_config": `{"config":"[Interface]\nPrivateKey = test\n\n[Peer]\nPublicKey = server\nEndpoint = example.org:1234\n"}`,
				},
			},
		},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := extractProtocolNative(raw, "awg")
	if err != nil {
		t.Fatalf("extractProtocolNative: %v", err)
	}
	if !strings.Contains(got, "[Interface]") || !strings.Contains(got, "Endpoint = example.org:1234") {
		t.Fatalf("unexpected AWG config: %q", got)
	}
}

func TestExtractProtocolNativeXray(t *testing.T) {
	xray := `{"log":{"loglevel":"warning"},"outbounds":[{"protocol":"vless","settings":{"vnext":[]}}]}`
	root := map[string]any{
		"containers": []any{
			map[string]any{
				"container": "amnezia-xray",
				"xray": map[string]any{
					"last_config": xray,
				},
			},
		},
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := extractProtocolNative(raw, "xray")
	if err != nil {
		t.Fatalf("extractProtocolNative: %v", err)
	}
	if got != xray {
		t.Fatalf("Xray config changed:\n got: %s\nwant: %s", got, xray)
	}
}

func TestNewUUIDV4(t *testing.T) {
	got, err := NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(got, "-")
	if len(parts) != 5 || len(got) != 36 {
		t.Fatalf("bad UUID shape: %q", got)
	}
	if parts[2][0] != '4' {
		t.Fatalf("not UUID v4: %q", got)
	}
	switch parts[3][0] {
	case '8', '9', 'a', 'b':
	default:
		t.Fatalf("bad RFC4122 variant: %q", got)
	}
}
