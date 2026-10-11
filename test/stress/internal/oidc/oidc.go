// Package oidc is a tiny OpenID Connect issuer for the stress harness: it
// serves discovery and JWKS so oauth2-proxy can verify bearer JWTs, and it
// mints RS256 ID tokens with email and groups claims for virtual users. It
// never runs an authorization flow. Standard library only.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Defaults shared by the issuer, the chart values and the minting clients.
const (
	Namespace  = "stress-oidc"
	SecretName = "oidc-signing-key"
	SecretKey  = "key.pem"
	Issuer     = "https://oidc.stress-oidc.svc.cluster.local"
	Audience   = "kubesentry"
)

// Key is the issuer's signing key.
type Key struct {
	Priv *rsa.PrivateKey
	ID   string
}

// ParseKey reads a PKCS#1 or PKCS#8 PEM key.
func ParseKey(b []byte) (*Key, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		priv = k
	} else {
		k8, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA key")
		}
		priv = rk
	}
	return newKey(priv), nil
}

func newKey(priv *rsa.PrivateKey) *Key {
	sum := sha256.Sum256(priv.PublicKey.N.Bytes())
	return &Key{Priv: priv, ID: base64.RawURLEncoding.EncodeToString(sum[:8])}
}

// GenerateKey makes a new 2048-bit key.
func GenerateKey() (*Key, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return newKey(priv), b, nil
}

// LoadOrCreate reads the key from its Secret, creating the Secret first if needed.
func LoadOrCreate(ctx context.Context, cs kubernetes.Interface, ns, name string) (*Key, error) {
	s, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return ParseKey(s.Data[SecretKey])
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}
	k, pemBytes, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"kubesentry.io/stress": "true"}},
		Data:       map[string][]byte{SecretKey: pemBytes},
	}
	if _, err := cs.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return LoadOrCreate(ctx, cs, ns, name)
		}
		return nil, err
	}
	return k, nil
}

// Load reads the key from its Secret.
func Load(ctx context.Context, cs kubernetes.Interface, ns, name string) (*Key, error) {
	s, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return ParseKey(s.Data[SecretKey])
}

// Claims are the ID token claims the harness sets.
type Claims struct {
	Email  string
	Groups []string
	// Subject defaults to the email.
	Subject string
	TTL     time.Duration
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Mint signs an RS256 ID token for the issuer and audience.
func (k *Key) Mint(issuer, audience string, c Claims, now time.Time) (string, error) {
	if c.TTL == 0 {
		c.TTL = 12 * time.Hour
	}
	sub := c.Subject
	if sub == "" {
		sub = c.Email
	}
	groups := c.Groups
	if groups == nil {
		groups = []string{}
	}
	head := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": k.ID})
	body := b64(map[string]any{
		"iss": issuer, "sub": sub, "aud": audience, "azp": audience,
		"iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(c.TTL).Unix(),
		"email": c.Email, "email_verified": true, "preferred_username": strings.SplitN(c.Email, "@", 2)[0],
		"groups": groups,
	})
	signing := head + "." + body
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.Priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Handler serves discovery and JWKS for issuer. The authorization, token and
// userinfo endpoints exist only so strict discovery parsers accept the document.
func Handler(issuer string, k *Key) http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks",
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"response_types_supported":              []string{"code", "id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "email", "profile", "groups"},
			"claims_supported":                      []string{"sub", "email", "email_verified", "groups", "preferred_username"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := k.Priv.PublicKey
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.ID,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	for _, p := range []string{"/authorize", "/token", "/userinfo"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "the stress issuer only serves discovery and JWKS; use bearer tokens", http.StatusNotImplemented)
		})
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	return mux
}

// SelfSignedTLS returns a TLS config with a fresh self-signed certificate for
// the issuer's host. The chart accepts only https issuers; oauth2-proxy is told
// to skip verifying this test certificate (--ssl-insecure-skip-verify).
func SelfSignedTLS(hosts ...string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"kubesentry stress"}},
		DNSNames:     hosts,
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}, nil
}

// Bearer is a JWT identity for the ks client: it sends the token, and the
// oauth2-proxy sidecar turns it into X-Forwarded-Email/Groups.
type Bearer struct {
	Email  string
	Groups []string
	Token  string
}

// Name labels results.
func (b Bearer) Name() string { return b.Email }

// Apply sets the bearer token.
func (b Bearer) Apply(r *http.Request) { r.Header.Set("Authorization", "Bearer "+b.Token) }
