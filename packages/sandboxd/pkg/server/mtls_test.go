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

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	processv1 "sigs.k8s.io/agent-sandbox/packages/sandboxd/spec/process/v1"
)

type pkiBundle struct {
	caCert     *x509.Certificate
	caPool     *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

func generatePKIBundle(t *testing.T) pkiBundle {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "evalrunner-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Server cert with localhost and 127.0.0.1
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "test-sandbox"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "test-sandbox.eval-runner-sandbox.sandbox.evalrunner.local"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)
	serverTLS := tls.Certificate{
		Certificate: [][]byte{serverDER},
		PrivateKey:  serverKey,
	}

	// Client cert
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "evalrunner-controller"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)
	clientTLS := tls.Certificate{
		Certificate: [][]byte{clientDER},
		PrivateKey:  clientKey,
	}

	return pkiBundle{
		caCert:     caCert,
		caPool:     caPool,
		serverCert: serverTLS,
		clientCert: clientTLS,
	}
}

func generateUntrustedClientCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	otherCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		Subject:               pkix.Name{CommonName: "other-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	otherCADER, err := x509.CreateCertificate(rand.Reader, otherCATmpl, otherCATmpl, &otherCAKey.PublicKey, otherCAKey)
	require.NoError(t, err)
	otherCACert, err := x509.ParseCertificate(otherCADER)
	require.NoError(t, err)
	otherPool := x509.NewCertPool()
	otherPool.AddCert(otherCACert)

	untrustedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	untrustedTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(998),
		Subject:      pkix.Name{CommonName: "untrusted-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	untrustedDER, err := x509.CreateCertificate(rand.Reader, untrustedTmpl, otherCACert, &untrustedKey.PublicKey, otherCAKey)
	require.NoError(t, err)
	return tls.Certificate{
		Certificate: [][]byte{untrustedDER},
		PrivateKey:  untrustedKey,
	}, otherPool
}

func TestSandboxdMTLSIntegration(t *testing.T) {
	root := t.TempDir()
	pki := generatePKIBundle(t)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    pki.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	srv, err := New(Options{RootDir: root, MetadataEnvPrefix: "SANDBOX_", Log: logr.Discard()})
	require.NoError(t, err)

	// gRPC listener with TLS
	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLSConfig)))
	srv.RegisterGRPC(grpcServer)
	grpcDone := make(chan struct{})
	go func() {
		defer close(grpcDone)
		_ = grpcServer.Serve(grpcLis)
	}()

	// REST listener with TLS
	restLis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpTLSConfig := serverTLSConfig.Clone()
	httpTLSConfig.NextProtos = []string{"h2", "http/1.1"}
	restTLSListener := tls.NewListener(restLis, httpTLSConfig)
	httpServer := &http.Server{Handler: srv.RESTHandler(), ReadHeaderTimeout: 10 * time.Second}
	httpDone := make(chan struct{})
	go func() {
		defer close(httpDone)
		_ = httpServer.Serve(restTLSListener)
	}()

	// Plaintext Health listener
	healthLis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	healthServer := &http.Server{Handler: srv.HealthHandler(), ReadHeaderTimeout: 10 * time.Second}
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		_ = healthServer.Serve(healthLis)
	}()

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = healthServer.Shutdown(shutdownCtx)
		_ = httpServer.Shutdown(shutdownCtx)
		grpcServer.GracefulStop()
		<-grpcDone
		<-httpDone
		<-healthDone
	})

	// 1. Plaintext health check works without client cert
	healthURL := fmt.Sprintf("http://%s/v1/health", healthLis.Addr())
	resp, err := http.Get(healthURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var healthBody HealthResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&healthBody))
	require.Equal(t, "ok", healthBody.Status)

	// Flip readiness
	srv.SetReady(false)
	resp2, err := http.Get(healthURL)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp2.StatusCode)
	srv.SetReady(true)

	// 2. Client without client certificate is rejected by mTLS
	noCertTLSConfig := &tls.Config{
		RootCAs:    pki.caPool,
		ServerName: "localhost",
	}
	noCertHTTPClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: noCertTLSConfig},
		Timeout:   2 * time.Second,
	}
	restURL := fmt.Sprintf("https://%s/v1/files/test.txt", restLis.Addr())
	_, err = noCertHTTPClient.Get(restURL)
	require.Error(t, err, "REST request without client cert must fail TLS handshake")

	noCertConn, err := grpc.NewClient(grpcLis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(noCertTLSConfig)))
	require.NoError(t, err)
	defer noCertConn.Close()
	processClient := processv1.NewProcessServiceClient(noCertConn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = processClient.Execute(ctx, &processv1.ExecuteRequest{Config: &processv1.ProcessConfig{Command: []string{"echo", "hi"}}})
	require.Error(t, err, "gRPC request without client cert must fail TLS handshake")

	// 3. Client with untrusted client cert is rejected
	untrustedCert, _ := generateUntrustedClientCert(t)
	untrustedTLSConfig := &tls.Config{
		RootCAs:      pki.caPool,
		Certificates: []tls.Certificate{untrustedCert},
		ServerName:   "localhost",
	}
	untrustedHTTPClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: untrustedTLSConfig},
		Timeout:   2 * time.Second,
	}
	_, err = untrustedHTTPClient.Get(restURL)
	require.Error(t, err, "REST request with untrusted cert must fail TLS handshake")

	// 4. Authenticated client with valid cert succeeds
	validTLSConfig := &tls.Config{
		RootCAs:      pki.caPool,
		Certificates: []tls.Certificate{pki.clientCert},
		ServerName:   "localhost",
	}
	validHTTPClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: validTLSConfig},
		Timeout:   5 * time.Second,
	}

	// REST PUT
	putReq, err := http.NewRequest(http.MethodPut, restURL, bytes.NewReader([]byte("mtls-data")))
	require.NoError(t, err)
	putResp, err := validHTTPClient.Do(putReq)
	require.NoError(t, err)
	defer putResp.Body.Close()
	require.Equal(t, http.StatusNoContent, putResp.StatusCode)

	// REST GET
	getResp, err := validHTTPClient.Get(restURL)
	require.NoError(t, err)
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	data, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	require.Equal(t, "mtls-data", string(data))

	// gRPC Execute
	validConn, err := grpc.NewClient(grpcLis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(validTLSConfig)))
	require.NoError(t, err)
	defer validConn.Close()
	validProcessClient := processv1.NewProcessServiceClient(validConn)
	execCtx, execCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer execCancel()
	execResp, err := validProcessClient.Execute(execCtx, &processv1.ExecuteRequest{Config: &processv1.ProcessConfig{Command: []string{"echo", "hello-mtls"}}})
	require.NoError(t, err)
	require.Equal(t, int32(0), execResp.ExitCode)
	require.Contains(t, string(execResp.Stdout), "hello-mtls")
}
