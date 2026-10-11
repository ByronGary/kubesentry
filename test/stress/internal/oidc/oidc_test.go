package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMintVerifiesAgainstJWKS(t *testing.T) {
	k, pemBytes, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParseKey(pemBytes)
	if err != nil || k2.ID != k.ID {
		t.Fatalf("parse: %v", err)
	}
	srv := httptest.NewServer(Handler("http://issuer.test", k))
	defer srv.Close()

	var disc map[string]any
	resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if disc["issuer"] != "http://issuer.test" || disc["jwks_uri"] != "http://issuer.test/jwks" {
		t.Fatalf("discovery %v", disc)
	}
	var jwks struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	resp, err = srv.Client().Get(srv.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&jwks)
	resp.Body.Close()
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != k.ID {
		t.Fatalf("jwks %+v", jwks)
	}
	nb, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	eb, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}

	tok, err := k.Mint("http://issuer.test", "kubesentry", Claims{Email: "alice@corp.example", Groups: []string{"a", "b"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", tok)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
	var claims map[string]any
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(body, &claims)
	if claims["email"] != "alice@corp.example" || claims["aud"] != "kubesentry" || claims["email_verified"] != true || len(claims["groups"].([]any)) != 2 {
		t.Errorf("claims %v", claims)
	}
}
