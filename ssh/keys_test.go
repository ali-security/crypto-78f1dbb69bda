// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/testdata"
)

func rawKey(pub PublicKey) interface{} {
	switch k := pub.(type) {
	case *rsaPublicKey:
		return (*rsa.PublicKey)(k)
	case *dsaPublicKey:
		return (*dsa.PublicKey)(k)
	case *ecdsaPublicKey:
		return (*ecdsa.PublicKey)(k)
	case ed25519PublicKey:
		return (ed25519.PublicKey)(k)
	case *Certificate:
		return k
	}
	panic("unknown key type")
}

func TestKeyMarshalParse(t *testing.T) {
	for _, priv := range testSigners {
		pub := priv.PublicKey()
		roundtrip, err := ParsePublicKey(pub.Marshal())
		if err != nil {
			t.Errorf("ParsePublicKey(%T): %v", pub, err)
		}

		k1 := rawKey(pub)
		k2 := rawKey(roundtrip)

		if !reflect.DeepEqual(k1, k2) {
			t.Errorf("got %#v in roundtrip, want %#v", k2, k1)
		}
	}
}

func TestUnsupportedCurves(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if _, err = NewSignerFromKey(raw); err == nil || !strings.Contains(err.Error(), "only P-256") {
		t.Fatalf("NewPrivateKey should not succeed with P-224, got: %v", err)
	}

	if _, err = NewPublicKey(&raw.PublicKey); err == nil || !strings.Contains(err.Error(), "only P-256") {
		t.Fatalf("NewPublicKey should not succeed with P-224, got: %v", err)
	}
}

func TestNewPublicKey(t *testing.T) {
	for _, k := range testSigners {
		raw := rawKey(k.PublicKey())
		// Skip certificates, as NewPublicKey does not support them.
		if _, ok := raw.(*Certificate); ok {
			continue
		}
		pub, err := NewPublicKey(raw)
		if err != nil {
			t.Errorf("NewPublicKey(%#v): %v", raw, err)
		}
		if !reflect.DeepEqual(k.PublicKey(), pub) {
			t.Errorf("NewPublicKey(%#v) = %#v, want %#v", raw, pub, k.PublicKey())
		}
	}
}

func TestKeySignVerify(t *testing.T) {
	for _, priv := range testSigners {
		pub := priv.PublicKey()

		data := []byte("sign me")
		sig, err := priv.Sign(rand.Reader, data)
		if err != nil {
			t.Fatalf("Sign(%T): %v", priv, err)
		}

		if err := pub.Verify(data, sig); err != nil {
			t.Errorf("publicKey.Verify(%T): %v", priv, err)
		}
		sig.Blob[5]++
		if err := pub.Verify(data, sig); err == nil {
			t.Errorf("publicKey.Verify on broken sig did not fail")
		}
	}
}

func TestKeySignWithAlgorithmVerify(t *testing.T) {
	for _, priv := range testSigners {
		if algorithmSigner, ok := priv.(AlgorithmSigner); !ok {
			t.Errorf("Signers constructed by ssh package should always implement the AlgorithmSigner interface: %T", priv)
		} else {
			pub := priv.PublicKey()
			data := []byte("sign me")

			signWithAlgTestCase := func(algorithm string, expectedAlg string) {
				sig, err := algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
				if err != nil {
					t.Fatalf("Sign(%T): %v", priv, err)
				}
				if sig.Format != expectedAlg {
					t.Errorf("signature format did not match requested signature algorithm: %s != %s", sig.Format, expectedAlg)
				}

				if err := pub.Verify(data, sig); err != nil {
					t.Errorf("publicKey.Verify(%T): %v", priv, err)
				}
				sig.Blob[5]++
				if err := pub.Verify(data, sig); err == nil {
					t.Errorf("publicKey.Verify on broken sig did not fail")
				}
			}

			// Using the empty string as the algorithm name should result in the same signature format as the algorithm-free Sign method.
			defaultSig, err := priv.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("Sign(%T): %v", priv, err)
			}
			signWithAlgTestCase("", defaultSig.Format)

			// RSA keys are the only ones which currently support more than one signing algorithm
			if pub.Type() == KeyAlgoRSA {
				for _, algorithm := range []string{SigAlgoRSA, SigAlgoRSASHA2256, SigAlgoRSASHA2512} {
					signWithAlgTestCase(algorithm, algorithm)
				}
			}
		}
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	key := testPrivateKeys["rsa"]

	rsa, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("got %T, want *rsa.PrivateKey", rsa)
	}

	if err := rsa.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestParseECPrivateKey(t *testing.T) {
	key := testPrivateKeys["ecdsa"]

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PrivateKey", ecKey)
	}

	if !validateECPublicKey(ecKey.Curve, ecKey.X, ecKey.Y) {
		t.Fatalf("public key does not validate.")
	}
}

func TestParseEncryptedPrivateKeysWithPassphrase(t *testing.T) {
	data := []byte("sign me")
	for _, tt := range testdata.PEMEncryptedKeys {
		t.Run(tt.Name, func(t *testing.T) {
			_, err := ParsePrivateKeyWithPassphrase(tt.PEMBytes, []byte("incorrect"))
			if err != x509.IncorrectPasswordError {
				t.Errorf("got %v want IncorrectPasswordError", err)
			}

			s, err := ParsePrivateKeyWithPassphrase(tt.PEMBytes, []byte(tt.EncryptionKey))
			if err != nil {
				t.Fatalf("ParsePrivateKeyWithPassphrase returned error: %s", err)
			}

			sig, err := s.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("Signer.Sign: %v", err)
			}
			if err := s.PublicKey().Verify(data, sig); err != nil {
				t.Errorf("Verify failed: %v", err)
			}

			_, err = ParsePrivateKey(tt.PEMBytes)
			if err == nil {
				t.Fatalf("ParsePrivateKey succeeded, expected an error")
			}

			if err, ok := err.(*PassphraseMissingError); !ok {
				t.Errorf("got error %q, want PassphraseMissingError", err)
			} else if tt.IncludesPublicKey {
				if err.PublicKey == nil {
					t.Fatalf("expected PassphraseMissingError.PublicKey not to be nil")
				}
				got, want := err.PublicKey.Marshal(), s.PublicKey().Marshal()
				if !bytes.Equal(got, want) {
					t.Errorf("error field %q doesn't match signer public key %q", got, want)
				}
			}
		})
	}
}

func TestParseDSA(t *testing.T) {
	// We actually exercise the ParsePrivateKey codepath here, as opposed to
	// using the ParseRawPrivateKey+NewSignerFromKey path that testdata_test.go
	// uses.
	s, err := ParsePrivateKey(testdata.PEMBytes["dsa"])
	if err != nil {
		t.Fatalf("ParsePrivateKey returned error: %s", err)
	}

	data := []byte("sign me")
	sig, err := s.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("dsa.Sign: %v", err)
	}

	if err := s.PublicKey().Verify(data, sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

// Tests for authorized_keys parsing.

// getTestKey returns a public key, and its base64 encoding.
func getTestKey() (PublicKey, string) {
	k := testPublicKeys["rsa"]

	b := &bytes.Buffer{}
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(k.Marshal())
	e.Close()

	return k, b.String()
}

func TestMarshalParsePublicKey(t *testing.T) {
	pub, pubSerialized := getTestKey()
	line := fmt.Sprintf("%s %s user@host", pub.Type(), pubSerialized)

	authKeys := MarshalAuthorizedKey(pub)
	actualFields := strings.Fields(string(authKeys))
	if len(actualFields) == 0 {
		t.Fatalf("failed authKeys: %v", authKeys)
	}

	// drop the comment
	expectedFields := strings.Fields(line)[0:2]

	if !reflect.DeepEqual(actualFields, expectedFields) {
		t.Errorf("got %v, expected %v", actualFields, expectedFields)
	}

	actPub, _, _, _, err := ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("cannot parse %v: %v", line, err)
	}
	if !reflect.DeepEqual(actPub, pub) {
		t.Errorf("got %v, expected %v", actPub, pub)
	}
}

type testAuthResult struct {
	pubKey   PublicKey
	options  []string
	comments string
	rest     string
	ok       bool
}

func testAuthorizedKeys(t *testing.T, authKeys []byte, expected []testAuthResult) {
	rest := authKeys
	var values []testAuthResult
	for len(rest) > 0 {
		var r testAuthResult
		var err error
		r.pubKey, r.comments, r.options, rest, err = ParseAuthorizedKey(rest)
		r.ok = (err == nil)
		t.Log(err)
		r.rest = string(rest)
		values = append(values, r)
	}

	if !reflect.DeepEqual(values, expected) {
		t.Errorf("got %#v, expected %#v", values, expected)
	}
}

func TestAuthorizedKeyBasic(t *testing.T) {
	pub, pubSerialized := getTestKey()
	line := "ssh-rsa " + pubSerialized + " user@host"
	testAuthorizedKeys(t, []byte(line),
		[]testAuthResult{
			{pub, nil, "user@host", "", true},
		})
}

func TestAuth(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithOptions := []string{
		`# comments to ignore before any keys...`,
		``,
		`env="HOME=/home/root",no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host`,
		`# comments to ignore, along with a blank line`,
		``,
		`env="HOME=/home/root2" ssh-rsa ` + pubSerialized + ` user2@host2`,
		``,
		`# more comments, plus a invalid entry`,
		`ssh-rsa data-that-will-not-parse user@host3`,
	}
	for _, eol := range []string{"\n", "\r\n"} {
		authOptions := strings.Join(authWithOptions, eol)
		rest2 := strings.Join(authWithOptions[3:], eol)
		rest3 := strings.Join(authWithOptions[6:], eol)
		testAuthorizedKeys(t, []byte(authOptions), []testAuthResult{
			{pub, []string{`env="HOME=/home/root"`, "no-port-forwarding"}, "user@host", rest2, true},
			{pub, []string{`env="HOME=/home/root2"`}, "user2@host2", rest3, true},
			{nil, nil, "", "", false},
		})
	}
}

func TestAuthWithQuotedSpaceInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedSpaceInEnv := []byte(`env="HOME=/home/root dir",no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedSpaceInEnv), []testAuthResult{
		{pub, []string{`env="HOME=/home/root dir"`, "no-port-forwarding"}, "user@host", "", true},
	})
}

func TestAuthWithQuotedCommaInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedCommaInEnv := []byte(`env="HOME=/home/root,dir",no-port-forwarding ssh-rsa ` + pubSerialized + `   user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedCommaInEnv), []testAuthResult{
		{pub, []string{`env="HOME=/home/root,dir"`, "no-port-forwarding"}, "user@host", "", true},
	})
}

func TestAuthWithQuotedQuoteInEnv(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithQuotedQuoteInEnv := []byte(`env="HOME=/home/\"root dir",no-port-forwarding` + "\t" + `ssh-rsa` + "\t" + pubSerialized + `   user@host`)
	authWithDoubleQuotedQuote := []byte(`no-port-forwarding,env="HOME=/home/ \"root dir\"" ssh-rsa ` + pubSerialized + "\t" + `user@host`)
	testAuthorizedKeys(t, []byte(authWithQuotedQuoteInEnv), []testAuthResult{
		{pub, []string{`env="HOME=/home/\"root dir"`, "no-port-forwarding"}, "user@host", "", true},
	})

	testAuthorizedKeys(t, []byte(authWithDoubleQuotedQuote), []testAuthResult{
		{pub, []string{"no-port-forwarding", `env="HOME=/home/ \"root dir\""`}, "user@host", "", true},
	})
}

func TestAuthWithInvalidSpace(t *testing.T) {
	_, pubSerialized := getTestKey()
	authWithInvalidSpace := []byte(`env="HOME=/home/root dir", no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host
#more to follow but still no valid keys`)
	testAuthorizedKeys(t, []byte(authWithInvalidSpace), []testAuthResult{
		{nil, nil, "", "", false},
	})
}

func TestAuthWithMissingQuote(t *testing.T) {
	pub, pubSerialized := getTestKey()
	authWithMissingQuote := []byte(`env="HOME=/home/root,no-port-forwarding ssh-rsa ` + pubSerialized + ` user@host
env="HOME=/home/root",shared-control ssh-rsa ` + pubSerialized + ` user@host`)

	testAuthorizedKeys(t, []byte(authWithMissingQuote), []testAuthResult{
		{pub, []string{`env="HOME=/home/root"`, `shared-control`}, "user@host", "", true},
	})
}

func TestInvalidEntry(t *testing.T) {
	authInvalid := []byte(`ssh-rsa`)
	_, _, _, _, err := ParseAuthorizedKey(authInvalid)
	if err == nil {
		t.Errorf("got valid entry for %q", authInvalid)
	}
}

var knownHostsParseTests = []struct {
	input string
	err   string

	marker  string
	comment string
	hosts   []string
	rest    string
}{
	{
		"",
		"EOF",

		"", "", nil, "",
	},
	{
		"# Just a comment",
		"EOF",

		"", "", nil, "",
	},
	{
		"   \t   ",
		"EOF",

		"", "", nil, "",
	},
	{
		"localhost ssh-rsa {RSAPUB}",
		"",

		"", "", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}",
		"",

		"", "", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}\tcomment comment",
		"",

		"", "comment comment", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}\tcomment comment\n",
		"",

		"", "comment comment", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}\tcomment comment\r\n",
		"",

		"", "comment comment", []string{"localhost"}, "",
	},
	{
		"localhost\tssh-rsa {RSAPUB}\tcomment comment\r\nnext line",
		"",

		"", "comment comment", []string{"localhost"}, "next line",
	},
	{
		"localhost,[host2:123]\tssh-rsa {RSAPUB}\tcomment comment",
		"",

		"", "comment comment", []string{"localhost", "[host2:123]"}, "",
	},
	{
		"@marker \tlocalhost,[host2:123]\tssh-rsa {RSAPUB}",
		"",

		"marker", "", []string{"localhost", "[host2:123]"}, "",
	},
	{
		"@marker \tlocalhost,[host2:123]\tssh-rsa aabbccdd",
		"short read",

		"", "", nil, "",
	},
}

func TestKnownHostsParsing(t *testing.T) {
	rsaPub, rsaPubSerialized := getTestKey()

	for i, test := range knownHostsParseTests {
		var expectedKey PublicKey
		const rsaKeyToken = "{RSAPUB}"

		input := test.input
		if strings.Contains(input, rsaKeyToken) {
			expectedKey = rsaPub
			input = strings.Replace(test.input, rsaKeyToken, rsaPubSerialized, -1)
		}

		marker, hosts, pubKey, comment, rest, err := ParseKnownHosts([]byte(input))
		if err != nil {
			if len(test.err) == 0 {
				t.Errorf("#%d: unexpectedly failed with %q", i, err)
			} else if !strings.Contains(err.Error(), test.err) {
				t.Errorf("#%d: expected error containing %q, but got %q", i, test.err, err)
			}
			continue
		} else if len(test.err) != 0 {
			t.Errorf("#%d: succeeded but expected error including %q", i, test.err)
			continue
		}

		if !reflect.DeepEqual(expectedKey, pubKey) {
			t.Errorf("#%d: expected key %#v, but got %#v", i, expectedKey, pubKey)
		}

		if marker != test.marker {
			t.Errorf("#%d: expected marker %q, but got %q", i, test.marker, marker)
		}

		if comment != test.comment {
			t.Errorf("#%d: expected comment %q, but got %q", i, test.comment, comment)
		}

		if !reflect.DeepEqual(test.hosts, hosts) {
			t.Errorf("#%d: expected hosts %#v, but got %#v", i, test.hosts, hosts)
		}

		if rest := string(rest); rest != test.rest {
			t.Errorf("#%d: expected remaining input to be %q, but got %q", i, test.rest, rest)
		}
	}
}

func TestFingerprintLegacyMD5(t *testing.T) {
	pub, _ := getTestKey()
	fingerprint := FingerprintLegacyMD5(pub)
	want := "fb:61:6d:1a:e3:f0:95:45:3c:a0:79:be:4a:93:63:66" // ssh-keygen -lf -E md5 rsa
	if fingerprint != want {
		t.Errorf("got fingerprint %q want %q", fingerprint, want)
	}
}

func TestFingerprintSHA256(t *testing.T) {
	pub, _ := getTestKey()
	fingerprint := FingerprintSHA256(pub)
	want := "SHA256:Anr3LjZK8YVpjrxu79myrW9Hrb/wpcMNpVvTq/RcBm8" // ssh-keygen -lf rsa
	if fingerprint != want {
		t.Errorf("got fingerprint %q want %q", fingerprint, want)
	}
}

func TestInvalidKeys(t *testing.T) {
	keyTypes := []string{
		"RSA PRIVATE KEY",
		"PRIVATE KEY",
		"EC PRIVATE KEY",
		"DSA PRIVATE KEY",
		"OPENSSH PRIVATE KEY",
	}

	for _, keyType := range keyTypes {
		for _, dataLen := range []int{0, 1, 2, 5, 10, 20} {
			data := make([]byte, dataLen)
			if _, err := io.ReadFull(rand.Reader, data); err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			pem.Encode(&buf, &pem.Block{
				Type:  keyType,
				Bytes: data,
			})

			// This test is just to ensure that the function
			// doesn't panic so the return value is ignored.
			ParseRawPrivateKey(buf.Bytes())
		}
	}
}

func TestSKKeys(t *testing.T) {
	for _, d := range testdata.SKData {
		pk, _, _, _, err := ParseAuthorizedKey(d.PubKey)
		if err != nil {
			t.Fatalf("parseAuthorizedKey returned error: %v", err)
		}

		sigBuf := make([]byte, hex.DecodedLen(len(d.HexSignature)))
		if _, err := hex.Decode(sigBuf, d.HexSignature); err != nil {
			t.Fatalf("hex.Decode() failed: %v", err)
		}

		dataBuf := make([]byte, hex.DecodedLen(len(d.HexData)))
		if _, err := hex.Decode(dataBuf, d.HexData); err != nil {
			t.Fatalf("hex.Decode() failed: %v", err)
		}

		sig, _, ok := parseSignature(sigBuf)
		if !ok {
			t.Fatalf("parseSignature(%v) failed", sigBuf)
		}

		// Test that good data and signature pass verification
		if err := pk.Verify(dataBuf, sig); err != nil {
			t.Errorf("%s: PublicKey.Verify(%v, %v) failed: %v", d.Name, dataBuf, sig, err)
		}

		// Invalid data being passed in
		invalidData := []byte("INVALID DATA")
		if err := pk.Verify(invalidData, sig); err == nil {
			t.Errorf("%s with invalid data: PublicKey.Verify(%v, %v) passed unexpectedly", d.Name, invalidData, sig)
		}

		// Change byte in blob to corrup signature
		sig.Blob[5] = byte('A')
		// Corrupted data being passed in
		if err := pk.Verify(dataBuf, sig); err == nil {
			t.Errorf("%s with corrupted signature: PublicKey.Verify(%v, %v) passed unexpectedly", d.Name, dataBuf, sig)
		}
	}
}

// skTestHarness builds SK-formatted signatures over a fixed payload
// using a caller-supplied signing function, letting tests vary the UP
// flag byte without duplicating the wire-format scaffolding.
type skTestHarness struct {
	format      string
	application string
	data        []byte
	// sign takes the SHA-256 digest of the marshalled SK blob and
	// returns the value to embed in Signature.Blob. For ECDSA keys the
	// helper feeds the digest to ecdsa.Sign; for ed25519 the helper
	// feeds the raw marshalled blob to ed25519.Sign.
	signDigest func(digest []byte) []byte
	signBlob   func(blob []byte) []byte
}

func (h skTestHarness) sign(t *testing.T, flags byte) *Signature {
	t.Helper()
	hsh := sha256.New()
	hsh.Write([]byte(h.application))
	appDigest := hsh.Sum(nil)

	hsh.Reset()
	hsh.Write(h.data)
	dataDigest := hsh.Sum(nil)

	var counter uint32 = 1
	blob := struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{appDigest, flags, counter, dataDigest}
	marshalled := Marshal(blob)

	var sigBlob []byte
	if h.signDigest != nil {
		hsh.Reset()
		hsh.Write(marshalled)
		sigBlob = h.signDigest(hsh.Sum(nil))
	} else {
		sigBlob = h.signBlob(marshalled)
	}

	return &Signature{
		Format: h.format,
		Blob:   sigBlob,
		Rest: Marshal(struct {
			Flags   byte
			Counter uint32
		}{flags, counter}),
	}
}

func TestSKUserPresence(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	h := skTestHarness{
		format:      "sk-ecdsa-sha2-nistp256@openssh.com",
		application: "ssh:",
		data:        []byte("test data"),
		signDigest: func(digest []byte) []byte {
			r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest)
			if err != nil {
				t.Fatal(err)
			}
			return Marshal(struct{ R, S *big.Int }{r, s})
		},
	}

	pk := &skECDSAPublicKey{
		application: h.application,
		PublicKey:   ecKey.PublicKey,
	}

	// Valid signature with UP=1 should pass.
	if err := pk.Verify(h.data, h.sign(t, flagUserPresence)); err != nil {
		t.Errorf("Verify failed with UP=1: %v", err)
	}

	// Valid signature with UP=0 should fail with the user-presence sentinel.
	sigNoUP := h.sign(t, 0)
	if err := pk.Verify(h.data, sigNoUP); !errors.Is(err, errSKMissingUserPresence) {
		t.Errorf("expected errSKMissingUserPresence, got: %v", err)
	}

	// UV set but UP clear must still fail: we only waive UP, never UV-only.
	if err := pk.Verify(h.data, h.sign(t, 0x04)); !errors.Is(err, errSKMissingUserPresence) {
		t.Errorf("UV-only (flags=0x04): expected errSKMissingUserPresence, got: %v", err)
	}

	// With noTouchRequired, UP=0 passes; UP=1+UV=1 also passes.
	pk.noTouchRequired = true
	if err := pk.Verify(h.data, sigNoUP); err != nil {
		t.Errorf("Verify with noTouchRequired failed: %v", err)
	}
	if err := pk.Verify(h.data, h.sign(t, flagUserPresence|0x04)); err != nil {
		t.Errorf("Verify UP|UV with noTouchRequired failed: %v", err)
	}
}

func TestSKKeyWithoutUP(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	skEC := &skECDSAPublicKey{PublicKey: ecKey.PublicKey}
	skED := &skEd25519PublicKey{PublicKey: edPub}
	certEC := &Certificate{Key: &skECDSAPublicKey{PublicKey: ecKey.PublicKey}}
	certED := &Certificate{Key: &skEd25519PublicKey{PublicKey: edPub}}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	certRSA := &Certificate{Key: rsaPub}

	// SK raw keys: return a clone with the flag set, original untouched.
	gotEC := skKeyWithoutUP(skEC)
	if gotEC == skEC {
		t.Error("skECDSAPublicKey: expected a clone, got the original pointer")
	}
	if !gotEC.(*skECDSAPublicKey).noTouchRequired {
		t.Error("skECDSAPublicKey clone: noTouchRequired not set")
	}
	if skEC.noTouchRequired {
		t.Error("skECDSAPublicKey: original mutated")
	}

	gotED := skKeyWithoutUP(skED)
	if gotED == skED {
		t.Error("skEd25519PublicKey: expected a clone, got the original pointer")
	}
	if !gotED.(*skEd25519PublicKey).noTouchRequired {
		t.Error("skEd25519PublicKey clone: noTouchRequired not set")
	}
	if skED.noTouchRequired {
		t.Error("skEd25519PublicKey: original mutated")
	}

	// Certificate wrapping SK: return a clone of the cert with a cloned
	// SK key inside. Neither the original cert nor the original inner
	// key must be mutated.
	originalInnerEC := certEC.Key
	gotCertEC := skKeyWithoutUP(certEC)
	if gotCertEC == certEC {
		t.Error("*Certificate(SK ecdsa): expected a clone, got the original pointer")
	}
	if got := gotCertEC.(*Certificate).Key.(*skECDSAPublicKey); !got.noTouchRequired {
		t.Error("*Certificate(SK ecdsa): inner clone missing noTouchRequired")
	}
	if certEC.Key != originalInnerEC {
		t.Error("*Certificate(SK ecdsa): original cert's Key pointer mutated")
	}
	if originalInnerEC.(*skECDSAPublicKey).noTouchRequired {
		t.Error("*Certificate(SK ecdsa): original inner key mutated")
	}

	gotCertED := skKeyWithoutUP(certED)
	if gotCertED == certED {
		t.Error("*Certificate(SK ed25519): expected a clone, got the original pointer")
	}
	if got := gotCertED.(*Certificate).Key.(*skEd25519PublicKey); !got.noTouchRequired {
		t.Error("*Certificate(SK ed25519): inner clone missing noTouchRequired")
	}

	// Non-SK key inside a cert: return original unchanged (nothing to clone).
	if got := skKeyWithoutUP(certRSA); got != certRSA {
		t.Error("*Certificate(RSA): expected the original pointer back")
	}

	// Plain non-SK key: return original unchanged.
	if got := skKeyWithoutUP(rsaPub); got != rsaPub {
		t.Error("rsaPublicKey: expected the original pointer back")
	}

	// Pathological: *Certificate whose Key is itself a *Certificate.
	// The SSH cert format forbids this and parseCert rejects it, but
	// a Go caller can still construct such a value. skKeyWithoutUP
	// must not recurse into it (or panic); it returns the input
	// unchanged. This also defends against a hypothetical cycle built
	// from hand-constructed Certificate pointers.
	nestedCert := &Certificate{Key: &Certificate{Key: skEC}}
	if got := skKeyWithoutUP(nestedCert); got != nestedCert {
		t.Error("*Certificate wrapping *Certificate: expected the original pointer back")
	}
	selfCycle := &Certificate{}
	selfCycle.Key = selfCycle
	if got := skKeyWithoutUP(selfCycle); got != selfCycle {
		t.Error("self-referential *Certificate: expected the original pointer back")
	}
}

func TestNoTouchAllowed(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sk := &skECDSAPublicKey{PublicKey: ecKey.PublicKey}
	certNoExt := &Certificate{Key: sk}
	certOptOut := &Certificate{
		Key:         sk,
		Permissions: Permissions{Extensions: map[string]string{"no-touch-required": ""}},
	}
	// Non-empty value: OpenSSH writes "" but any value must be accepted
	// because the check is presence-only.
	certOptOutNonEmpty := &Certificate{
		Key:         sk,
		Permissions: Permissions{Extensions: map[string]string{"no-touch-required": "yes"}},
	}
	// no-touch-required belongs in Extensions, never CriticalOptions.
	// Putting it in CriticalOptions must NOT be treated as opt-out.
	certCritOnly := &Certificate{
		Key:         sk,
		Permissions: Permissions{CriticalOptions: map[string]string{"no-touch-required": ""}},
	}

	permsEmpty := &Permissions{}
	permsOptOut := &Permissions{Extensions: map[string]string{"no-touch-required": ""}}
	permsCritOnly := &Permissions{CriticalOptions: map[string]string{"no-touch-required": ""}}

	cases := []struct {
		name  string
		pub   PublicKey
		perms *Permissions
		want  bool
	}{
		{"nil perms, no cert", sk, nil, false},
		{"empty perms, no cert", sk, permsEmpty, false},
		{"perms opt-out, raw key", sk, permsOptOut, true},
		{"nil perms, cert opt-out", certOptOut, nil, true},
		{"nil perms, cert opt-out non-empty value", certOptOutNonEmpty, nil, true},
		{"nil perms, cert no ext", certNoExt, nil, false},
		{"perms opt-out, cert no ext", certNoExt, permsOptOut, true},
		{"empty perms, cert opt-out", certOptOut, permsEmpty, true},
		// Negative controls: CriticalOptions must not waive UP.
		{"critical-options only, raw key", sk, permsCritOnly, false},
		{"critical-options only, cert", certCritOnly, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := noTouchAllowed(tc.pub, tc.perms); got != tc.want {
				t.Errorf("noTouchAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSKUserPresenceEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := skTestHarness{
		format:      "sk-ssh-ed25519@openssh.com",
		application: "ssh:",
		data:        []byte("test data"),
		signBlob: func(blob []byte) []byte {
			return ed25519.Sign(priv, blob)
		},
	}

	pk := &skEd25519PublicKey{
		application: h.application,
		PublicKey:   pub,
	}

	if err := pk.Verify(h.data, h.sign(t, flagUserPresence)); err != nil {
		t.Errorf("Verify failed with UP=1: %v", err)
	}
	sigNoUP := h.sign(t, 0)
	if err := pk.Verify(h.data, sigNoUP); !errors.Is(err, errSKMissingUserPresence) {
		t.Errorf("expected errSKMissingUserPresence, got: %v", err)
	}
	pk.noTouchRequired = true
	if err := pk.Verify(h.data, sigNoUP); err != nil {
		t.Errorf("Verify with noTouchRequired failed: %v", err)
	}
}
