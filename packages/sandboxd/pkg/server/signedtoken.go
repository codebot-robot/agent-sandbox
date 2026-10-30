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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SignedTokenPayload is the JSON payload contained in an asymmetric bearer token.
type SignedTokenPayload struct {
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
}

// SignToken mints an ed25519-signed bearer token in the v1 format:
//
//	v1.<base64url(payload)>.<base64url(signature)>
//
// where payload is JSON {"aud":"<string>","iat":<unix seconds>,"exp":<unix seconds>,"nonce":"<random string>"}
// and signature is ed25519.Sign(priv, payload bytes).
func SignToken(priv ed25519.PrivateKey, aud string, ttl time.Duration) (string, error) {
	return SignTokenAt(priv, aud, ttl, time.Now())
}

// SignTokenAt mints an ed25519-signed bearer token with the specified reference time.
func SignTokenAt(priv ed25519.PrivateKey, aud string, ttl time.Duration, now time.Time) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	payload := SignedTokenPayload{
		Aud:   aud,
		Iat:   now.Unix(),
		Exp:   now.Add(ttl).Unix(),
		Nonce: hex.EncodeToString(nonceBytes),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal signed token payload: %w", err)
	}

	sig := ed25519.Sign(priv, payloadBytes)
	if len(sig) != ed25519.SignatureSize {
		return "", errors.New("failed to generate ed25519 signature")
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	encodedSig := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("v1.%s.%s", encodedPayload, encodedSig), nil
}
