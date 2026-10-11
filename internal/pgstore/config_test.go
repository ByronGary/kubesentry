package pgstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// clearPGEnv unsets libpq variables the developer's shell may carry.
func clearPGEnv(t *testing.T) {
	for _, k := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSSLMODE", "PGSSLROOTCERT",
		"PGSSLCERT", "PGSSLKEY", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE", "PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLNEGOTIATION"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

// writeCA writes a self-signed CA certificate in PEM and returns its path.
func writeCA(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test RDS root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	path := filepath.Join(t.TempDir(), "rds-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, cert
}

// The Helm chart sets RDS TLS through PGSSLMODE and PGSSLROOTCERT, not in the
// DSN. The pool config must honour them (no database needed for this test).
func TestPoolConfigHonoursPGEnvironment(t *testing.T) {
	clearPGEnv(t)
	o := Options{}
	if err := o.defaults(); err != nil {
		t.Fatal(err)
	}
	const dsn = "postgres://kubesentry:secret@audit.cluster-abc.eu-west-1.rds.amazonaws.com:5432/kubesentry"

	t.Setenv("PGSSLMODE", "verify-full")
	cfg, err := poolConfig(dsn, o)
	if err != nil {
		t.Fatal(err)
	}
	tc := cfg.ConnConfig.TLSConfig
	if tc == nil {
		t.Fatal("PGSSLMODE=verify-full with no sslmode in the DSN gave no TLS config")
	}
	if tc.InsecureSkipVerify || tc.ServerName != "audit.cluster-abc.eu-west-1.rds.amazonaws.com" {
		t.Errorf("verify-full should verify the certificate and host name: skip=%v serverName=%q", tc.InsecureSkipVerify, tc.ServerName)
	}
	if len(cfg.ConnConfig.Fallbacks) != 0 {
		t.Errorf("verify-full must not fall back to plaintext: %d fallbacks", len(cfg.ConnConfig.Fallbacks))
	}

	caPath, ca := writeCA(t)
	t.Setenv("PGSSLROOTCERT", caPath)
	cfg, err = poolConfig(dsn, o)
	if err != nil {
		t.Fatal(err)
	}
	want := x509.NewCertPool()
	want.AddCert(ca)
	if tc := cfg.ConnConfig.TLSConfig; tc == nil || tc.RootCAs == nil || !tc.RootCAs.Equal(want) {
		t.Error("PGSSLROOTCERT was not used as the root CA pool")
	}

	// The store's own session settings survive, and the DSN still wins over
	// the environment where it says something.
	if rp := cfg.ConnConfig.RuntimeParams; rp["search_path"] != "kubesentry" || rp["timezone"] != "UTC" || rp["application_name"] != "kubesentry" {
		t.Errorf("runtime params = %v", rp)
	}
	cfg, err = poolConfig(dsn+"?sslmode=disable", o)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.TLSConfig != nil {
		t.Error("sslmode=disable in the DSN should override PGSSLMODE")
	}

	// A DSN that only names the database takes host and user from PG*.
	t.Setenv("PGHOST", "db.internal")
	t.Setenv("PGUSER", "audit")
	cfg, err = poolConfig("dbname=kubesentry", o)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.Host != "db.internal" || cfg.ConnConfig.User != "audit" || cfg.ConnConfig.TLSConfig == nil {
		t.Errorf("config from environment = host %q user %q tls %v", cfg.ConnConfig.Host, cfg.ConnConfig.User, cfg.ConnConfig.TLSConfig != nil)
	}
}

func TestResolveDSN(t *testing.T) {
	t.Setenv(DSNEnv, "postgres://from-secret/kubesentry")
	if got := ResolveDSN("postgres://from-flag/kubesentry"); got != "postgres://from-flag/kubesentry" {
		t.Errorf("flag should win, got %q", got)
	}
	if got := ResolveDSN(""); got != "postgres://from-secret/kubesentry" {
		t.Errorf("env fallback = %q", got)
	}
}
