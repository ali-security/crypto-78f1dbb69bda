// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
)

func TestPublicKeyCallbackLastSeen(t *testing.T) {
	var lastSeenKey PublicKey

	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	serverConf := &ServerConfig{
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			lastSeenKey = key
			fmt.Printf("seen %#v\n", key)
			if _, ok := key.(*dsaPublicKey); !ok {
				return nil, errors.New("nope")
			}
			return nil, nil
		},
	}
	serverConf.AddHostKey(testSigners["ecdsap256"])

	done := make(chan struct{})
	go func() {
		defer close(done)
		NewServerConn(c1, serverConf)
	}()

	clientConf := ClientConfig{
		User: "user",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"], testSigners["dsa"], testSigners["ed25519"]),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	_, _, _, err = NewClientConn(c2, "", &clientConf)
	if err != nil {
		t.Fatal(err)
	}
	<-done

	expectedPublicKey := testSigners["dsa"].PublicKey().Marshal()
	lastSeenMarshalled := lastSeenKey.Marshal()
	if !bytes.Equal(lastSeenMarshalled, expectedPublicKey) {
		t.Errorf("unexpected key: got %#v, want %#v", lastSeenKey, testSigners["dsa"].PublicKey())
	}
}

// skTestSigner is a Signer that produces SK-ECDSA signatures over
// user-auth data, simulating a FIDO/U2F authenticator. The flags
// byte (UP and other bits) is caller-controlled so tests can exercise
// the server's user-presence enforcement and its opt-out paths. This
// is test-only: the real Signer is hardware-backed.
type skTestSigner struct {
	priv        *ecdsa.PrivateKey
	pub         PublicKey
	flags       byte
	application string
}

func (s *skTestSigner) PublicKey() PublicKey { return s.pub }

func (s *skTestSigner) Sign(r io.Reader, data []byte) (*Signature, error) {
	h := sha256.New()
	h.Write([]byte(s.application))
	appDigest := h.Sum(nil)
	h.Reset()
	h.Write(data)
	dataDigest := h.Sum(nil)
	var counter uint32 = 1
	blob := struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{appDigest, s.flags, counter, dataDigest}
	h.Reset()
	h.Write(Marshal(blob))
	digest := h.Sum(nil)
	x, y, err := ecdsa.Sign(r, s.priv, digest)
	if err != nil {
		return nil, err
	}
	return &Signature{
		Format: KeyAlgoSKECDSA256,
		Blob:   Marshal(struct{ R, S *big.Int }{x, y}),
		Rest: Marshal(struct {
			Flags   byte
			Counter uint32
		}{s.flags, counter}),
	}, nil
}

// TestServerAuthSKUserPresence drives the full userAuthLoop with an SK
// public-key client and verifies the server's wiring of the UP check
// and its two opt-out paths: the per-key Permissions.Extensions route
// and (via cert) the cert-level route. It also confirms that non-SK
// clients are unaffected by the new code path.
func TestServerAuthSKUserPresence(t *testing.T) {
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skPub := &skECDSAPublicKey{application: "ssh:", PublicKey: userKey.PublicKey}

	runAuth := func(t *testing.T, signer Signer, perms *Permissions) error {
		t.Helper()
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer c1.Close()
		defer c2.Close()

		serverConf := &ServerConfig{
			PublicKeyCallback: func(ConnMetadata, PublicKey) (*Permissions, error) {
				return perms, nil
			},
		}
		serverConf.AddHostKey(testSigners["ecdsa"])

		serverErr := make(chan error, 1)
		go func() {
			_, _, _, err := NewServerConn(c1, serverConf)
			serverErr <- err
		}()

		clientConf := &ClientConfig{
			User:            "user",
			Auth:            []AuthMethod{PublicKeys(signer)},
			HostKeyCallback: InsecureIgnoreHostKey(),
		}
		_, _, _, clientErr := NewClientConn(c2, "", clientConf)
		<-serverErr
		return clientErr
	}

	optOut := &Permissions{Extensions: map[string]string{noTouchRequiredExtension: ""}}

	t.Run("UP=1, default perms accepts", func(t *testing.T) {
		s := &skTestSigner{priv: userKey, pub: skPub, flags: flagUserPresence, application: "ssh:"}
		if err := runAuth(t, s, nil); err != nil {
			t.Errorf("expected auth to succeed: %v", err)
		}
	})
	t.Run("UP=0, default perms rejects", func(t *testing.T) {
		s := &skTestSigner{priv: userKey, pub: skPub, flags: 0, application: "ssh:"}
		if err := runAuth(t, s, nil); err == nil {
			t.Error("expected auth to fail with UP=0")
		}
	})
	t.Run("UP=0, perms opt-out accepts", func(t *testing.T) {
		s := &skTestSigner{priv: userKey, pub: skPub, flags: 0, application: "ssh:"}
		if err := runAuth(t, s, optOut); err != nil {
			t.Errorf("expected auth to succeed with opt-out: %v", err)
		}
	})
	t.Run("UP=0, perms CriticalOptions does NOT opt out", func(t *testing.T) {
		s := &skTestSigner{priv: userKey, pub: skPub, flags: 0, application: "ssh:"}
		critOnly := &Permissions{CriticalOptions: map[string]string{noTouchRequiredExtension: ""}}
		if err := runAuth(t, s, critOnly); err == nil {
			t.Error("no-touch-required in CriticalOptions must not waive UP")
		}
	})
	t.Run("non-SK RSA signer unaffected", func(t *testing.T) {
		if err := runAuth(t, testSigners["rsa"], nil); err != nil {
			t.Errorf("plain RSA auth must still work: %v", err)
		}
	})
}

// doClientServerAuth runs a handshake with the given server and client
// configs and returns the server side authentication errors, as seen by
// AuthLogCallback, together with the client side error.
func doClientServerAuth(t *testing.T, serverConfig *ServerConfig, clientConfig *ClientConfig) ([]error, error) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	var serverAuthErrors []error

	serverConfig.AddHostKey(testSigners["rsa"])
	serverConfig.AuthLogCallback = func(conn ConnMetadata, method string, err error) {
		serverAuthErrors = append(serverAuthErrors, err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		newServer(c1, serverConfig)
	}()
	c, _, _, err := NewClientConn(c2, "", clientConfig)
	if err == nil {
		c.Close()
	}
	// Wait for the server to finish before reading serverAuthErrors, which
	// is written by the server goroutine.
	c2.Close()
	<-serverDone
	return serverAuthErrors, err
}

func TestAuthCallbacksSourceAddress(t *testing.T) {
	permsWithSourceAddress := func(sourceAddress string) *Permissions {
		return &Permissions{
			CriticalOptions: map[string]string{
				sourceAddressCriticalOption: sourceAddress,
			},
		}
	}
	methods := []struct {
		name         string
		serverConfig func(sourceAddress string) *ServerConfig
		clientAuth   []AuthMethod
	}{
		{
			name: "password",
			serverConfig: func(sourceAddress string) *ServerConfig {
				return &ServerConfig{
					PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
						return permsWithSourceAddress(sourceAddress), nil
					},
				}
			},
			clientAuth: []AuthMethod{Password(clientPassword)},
		},
		{
			name: "keyboard-interactive",
			serverConfig: func(sourceAddress string) *ServerConfig {
				return &ServerConfig{
					KeyboardInteractiveCallback: func(conn ConnMetadata, challenge KeyboardInteractiveChallenge) (*Permissions, error) {
						return permsWithSourceAddress(sourceAddress), nil
					},
				}
			},
			clientAuth: []AuthMethod{
				KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
					return nil, nil
				}),
			},
		},
	}
	for _, method := range methods {
		for _, tc := range []struct {
			name          string
			sourceAddress string
			wantErr       bool
		}{
			{"mismatching", "192.168.99.99", true},
			{"matching", "127.0.0.0/8,::1/128", false},
		} {
			method, tc := method, tc
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				clientConf := &ClientConfig{
					User:            "user",
					Auth:            method.clientAuth,
					HostKeyCallback: InsecureIgnoreHostKey(),
				}
				serverAuthErrors, err := doClientServerAuth(t, method.serverConfig(tc.sourceAddress), clientConf)
				if tc.wantErr {
					if err == nil {
						t.Fatalf("client login succeeded with %s callback returning mismatching source-address", method.name)
					}
					var sourceAddressErrors int
					for _, err := range serverAuthErrors {
						if err != nil && strings.Contains(err.Error(), "source-address restriction") {
							sourceAddressErrors++
						}
					}
					if sourceAddressErrors == 0 {
						t.Fatalf("no server auth error mentions the source-address restriction, got %v", serverAuthErrors)
					}
				} else if err != nil {
					t.Fatalf("client login failed with matching source-address: %v", err)
				}
			})
		}
	}
}

func TestGSSAPIWithMICCallbackSourceAddress(t *testing.T) {
	for _, tc := range []struct {
		name          string
		sourceAddress string
		wantErr       bool
	}{
		{"mismatching", "192.168.99.99", true},
		{"matching", "127.0.0.0/8,::1/128", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := &ServerConfig{
				GSSAPIWithMICConfig: &GSSAPIWithMICConfig{
					AllowLogin: func(conn ConnMetadata, srcName string) (*Permissions, error) {
						return &Permissions{
							CriticalOptions: map[string]string{
								sourceAddressCriticalOption: tc.sourceAddress,
							},
						}, nil
					},
					Server: &FakeServer{
						exchanges: []*exchange{
							{
								outToken:      "server-valid-token-1",
								expectedToken: "client-valid-token-1",
							},
						},
						maxRound:    1,
						expectedMIC: []byte("valid-mic"),
						srcName:     "user@DOMAIN",
					},
				},
			}
			clientConf := &ClientConfig{
				User: "user",
				Auth: []AuthMethod{
					GSSAPIWithMICAuthMethod(
						&FakeClient{
							exchanges: []*exchange{
								{
									outToken: "client-valid-token-1",
								},
								{
									expectedToken: "server-valid-token-1",
								},
							},
							mic:      []byte("valid-mic"),
							maxRound: 2,
						}, "testtarget",
					),
				},
				HostKeyCallback: InsecureIgnoreHostKey(),
			}
			serverAuthErrors, err := doClientServerAuth(t, serverConfig, clientConf)
			if tc.wantErr {
				if err == nil {
					t.Fatal("client login succeeded with gssapi-with-mic AllowLogin returning mismatching source-address")
				}
				var sourceAddressErrors int
				for _, err := range serverAuthErrors {
					if err != nil && strings.Contains(err.Error(), "source-address restriction") {
						sourceAddressErrors++
					}
				}
				if sourceAddressErrors == 0 {
					t.Fatalf("no server auth error mentions the source-address restriction, got %v", serverAuthErrors)
				}
			} else if err != nil {
				t.Fatalf("client login failed with matching source-address: %v", err)
			}
		})
	}
}
