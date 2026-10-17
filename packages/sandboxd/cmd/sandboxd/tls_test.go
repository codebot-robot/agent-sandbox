// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// generateTestPKI creates a test CA and a server cert in dir and returns their file paths.
func generateTestPKI(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caFile = filepath.Join(dir, "ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o644))

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test-server",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caTmpl, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	certFile = filepath.Join(dir, "server.crt")
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	require.NoError(t, os.WriteFile(certFile, serverPEM, 0o644))

	keyFile = filepath.Join(dir, "server.key")
	keyBytes, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))

	return caFile, certFile, keyFile
}

func TestBuildTLSConfig(t *testing.T) {
	dir := t.TempDir()
	caFile, certFile, keyFile := generateTestPKI(t, dir)

	t.Run("empty_config_yields_nil", func(t *testing.T) {
		cfg := &config{}
		tlsConfig, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})

	t.Run("cert_without_key_fails", func(t *testing.T) {
		cfg := &config{tlsCertFile: certFile}
		_, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "--tls-cert-file and --tls-key-file must both be specified")
	})

	t.Run("key_without_cert_fails", func(t *testing.T) {
		cfg := &config{tlsKeyFile: keyFile}
		_, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "--tls-cert-file and --tls-key-file must both be specified")
	})

	t.Run("require_client_cert_without_tls_fails", func(t *testing.T) {
		cfg := &config{requireClientCert: true}
		_, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "--require-client-cert requires --tls-cert-file and --tls-key-file")
	})

	t.Run("client_ca_without_tls_fails", func(t *testing.T) {
		cfg := &config{tlsClientCAFile: caFile}
		_, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "--tls-client-ca-file requires --tls-cert-file and --tls-key-file")
	})

	t.Run("require_client_cert_without_ca_fails", func(t *testing.T) {
		cfg := &config{tlsCertFile: certFile, tlsKeyFile: keyFile, requireClientCert: true}
		_, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "--require-client-cert requires --tls-client-ca-file")
	})

	t.Run("server_tls_only", func(t *testing.T) {
		cfg := &config{tlsCertFile: certFile, tlsKeyFile: keyFile}
		tlsConfig, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.Equal(t, tls.NoClientCert, tlsConfig.ClientAuth)
		require.Nil(t, tlsConfig.ClientCAs)
	})

	t.Run("server_tls_with_optional_client_ca", func(t *testing.T) {
		cfg := &config{tlsCertFile: certFile, tlsKeyFile: keyFile, tlsClientCAFile: caFile}
		tlsConfig, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.Equal(t, tls.VerifyClientCertIfGiven, tlsConfig.ClientAuth)
		require.NotNil(t, tlsConfig.ClientCAs)
	})

	t.Run("mutual_tls_required", func(t *testing.T) {
		cfg := &config{tlsCertFile: certFile, tlsKeyFile: keyFile, tlsClientCAFile: caFile, requireClientCert: true}
		tlsConfig, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
		require.NotNil(t, tlsConfig.ClientCAs)
	})
}
