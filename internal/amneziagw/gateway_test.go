package amneziagw

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func qtCompressed(t *testing.T, plain []byte) string {
	t.Helper()
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 4, 4+compressed.Len())
	binary.BigEndian.PutUint32(raw, uint32(len(plain)))
	raw = append(raw, compressed.Bytes()...)
	return "vpn://" + base64.RawURLEncoding.EncodeToString(raw)
}

func TestDecodeSubscriptionKey(t *testing.T) {
	doc := []byte(`{"api_config":{"service_type":"amnezia-premium","user_country_code":"ru"},"auth_data":{"api_key":"secret"}}`)
	got, err := DecodeSubscriptionKey(qtCompressed(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if got.ServiceType != "amnezia-premium" || got.UserCountryCode != "ru" {
		t.Fatalf("unexpected subscription metadata: %#v", got)
	}
	if got.AuthData["api_key"] != "secret" {
		t.Fatalf("auth_data not decoded: %#v", got.AuthData)
	}
}

func TestExtractAWGConf(t *testing.T) {
	root := map[string]any{
		"containers": []any{
			map[string]any{
				"awg": map[string]any{
					"last_config": `{"config":"[Interface]\nPrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = peer\nEndpoint = vpn.example:443\n"}`,
				},
			},
		},
	}
	raw, _ := json.Marshal(root)
	conf, err := ExtractAWGConf(raw, "private")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "PrivateKey = private") {
		t.Fatalf("private key placeholder was not replaced: %q", conf)
	}
}

func TestExtractXrayClientConfig(t *testing.T) {
	xray := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"vpn.example","port":443,"users":[{"id":"11111111-2222-4333-8444-555555555555"}]}]}}]}`
	root := map[string]any{
		"containers": []any{
			map[string]any{
				"xray": map[string]any{"last_config": xray},
			},
		},
	}
	raw, _ := json.Marshal(root)
	got, err := ExtractXrayClientConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"protocol":"vless"`)) {
		t.Fatalf("unexpected Xray config: %s", got)
	}
}

func TestNewUUID(t *testing.T) {
	u := NewUUID()
	if len(u) != 36 || u[14] != '4' {
		t.Fatalf("not a v4 UUID: %q", u)
	}
}
