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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthSettings(t *testing.T) {
	sum := sha256.Sum256([]byte("tok"))
	hexSum := hex.EncodeToString(sum[:])
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("tok\n"), 0o600))

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	keyFile := filepath.Join(t.TempDir(), "pubkey")
	require.NoError(t, os.WriteFile(keyFile, []byte(pubB64+"\n"), 0o600))

	// No flags leaves authentication disabled.
	digest, key, aud, err := authSettings(&config{})
	require.NoError(t, err)
	require.Nil(t, digest)
	require.Nil(t, key)
	require.Empty(t, aud)

	// Static token flags.
	digest, key, aud, err = authSettings(&config{authTokenSHA256: hexSum})
	require.NoError(t, err)
	require.Equal(t, sum[:], digest)
	require.Nil(t, key)
	require.Empty(t, aud)

	digest, key, aud, err = authSettings(&config{authTokenFile: tokenFile})
	require.NoError(t, err)
	require.Equal(t, sum[:], digest)
	require.Nil(t, key)
	require.Empty(t, aud)

	// Public key flags.
	digest, key, aud, err = authSettings(&config{authPublicKey: pubB64})
	require.NoError(t, err)
	require.Nil(t, digest)
	require.Equal(t, pub, key)
	require.Empty(t, aud)

	digest, key, aud, err = authSettings(&config{authPublicKeyFile: keyFile})
	require.NoError(t, err)
	require.Nil(t, digest)
	require.Equal(t, pub, key)
	require.Empty(t, aud)

	// Public key with audience.
	digest, key, aud, err = authSettings(&config{authPublicKey: pubB64, authAudience: "my-sandbox"})
	require.NoError(t, err)
	require.Nil(t, digest)
	require.Equal(t, pub, key)
	require.Equal(t, "my-sandbox", aud)

	digest, key, aud, err = authSettings(&config{authPublicKeyFile: keyFile, authAudience: "my-sandbox"})
	require.NoError(t, err)
	require.Nil(t, digest)
	require.Equal(t, pub, key)
	require.Equal(t, "my-sandbox", aud)

	// Audience requires public key flag.
	_, _, _, err = authSettings(&config{authAudience: "my-sandbox"})
	require.Error(t, err)
	_, _, _, err = authSettings(&config{authTokenSHA256: hexSum, authAudience: "my-sandbox"})
	require.Error(t, err)
	_, _, _, err = authSettings(&config{authTokenFile: tokenFile, authAudience: "my-sandbox"})
	require.Error(t, err)

	// Mutually exclusive flag combinations.
	conflicting := []*config{
		{authTokenSHA256: hexSum, authTokenFile: tokenFile},
		{authTokenSHA256: hexSum, authPublicKey: pubB64},
		{authTokenSHA256: hexSum, authPublicKeyFile: keyFile},
		{authTokenFile: tokenFile, authPublicKey: pubB64},
		{authTokenFile: tokenFile, authPublicKeyFile: keyFile},
		{authPublicKey: pubB64, authPublicKeyFile: keyFile},
		{authTokenSHA256: hexSum, authTokenFile: tokenFile, authPublicKey: pubB64},
	}
	for _, cfg := range conflicting {
		_, _, _, err := authSettings(cfg)
		require.Error(t, err)
	}
}
