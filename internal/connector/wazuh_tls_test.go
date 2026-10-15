package connector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func newTLSTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	return server
}

func getWith(t *testing.T, config WazuhConfig, url string) error {
	t.Helper()
	tlsConfig, err := wazuhTLSConfig(config)
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestWazuhPinnedCertificateIsAccepted(t *testing.T) {
	server := newTLSTestServer(t)
	if err := getWith(t, WazuhConfig{PinnedCertificatePEM: certPEM(server.Certificate())}, server.URL); err != nil {
		t.Fatalf("pinned certificate refused: %v", err)
	}
}

// selfSignedCert makes a certificate distinct from httptest's, which every
// httptest TLS server shares.
func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wazuh.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestWazuhOtherCertificateIsRefused(t *testing.T) {
	server := newTLSTestServer(t)
	err := getWith(t, WazuhConfig{PinnedCertificatePEM: certPEM(selfSignedCert(t))}, server.URL)
	if err == nil || !strings.Contains(err.Error(), "not the pinned one") {
		t.Fatalf("a different certificate must be refused with the pin named, got %v", err)
	}
}

func TestWazuhSelfSignedIsRefusedWithoutAPin(t *testing.T) {
	server := newTLSTestServer(t)
	if err := getWith(t, WazuhConfig{}, server.URL); err == nil {
		t.Fatal("an unpinned self-signed certificate must be refused by default")
	}
}

func TestWazuhPinAndInsecureAreExclusive(t *testing.T) {
	server := newTLSTestServer(t)
	if _, err := wazuhTLSConfig(WazuhConfig{PinnedCertificatePEM: certPEM(server.Certificate()), InsecureSkipVerify: true}); err == nil {
		t.Fatal("a pin together with InsecureSkipVerify must be rejected")
	}
}

func TestWazuhTLSConfigSetsAMinimumVersion(t *testing.T) {
	for _, config := range []WazuhConfig{{}, {InsecureSkipVerify: true}} {
		tlsConfig, err := wazuhTLSConfig(config)
		if err != nil || tlsConfig.MinVersion == 0 {
			t.Fatalf("config %+v: MinVersion unset (err %v)", config, err)
		}
	}
}

func TestWazuhExpiredPinIsRefused(t *testing.T) {
	cert := newTLSTestServer(t).Certificate()
	err := verifyPinned([]*x509.Certificate{cert}, []*x509.Certificate{cert}, cert.NotAfter.Add(time.Hour))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired pinned certificate must be refused, got %v", err)
	}
}

func TestWazuhPinFileWithoutCertificateIsAnError(t *testing.T) {
	if _, err := wazuhTLSConfig(WazuhConfig{PinnedCertificatePEM: []byte("not a certificate")}); err == nil {
		t.Fatal("a pin file with no CERTIFICATE block must be an error")
	}
}
