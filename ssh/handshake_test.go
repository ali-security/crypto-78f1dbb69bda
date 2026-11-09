// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type testChecker struct {
	calls []string
}

func (t *testChecker) Check(dialAddr string, addr net.Addr, key PublicKey) error {
	if dialAddr == "bad" {
		return fmt.Errorf("dialAddr is bad")
	}

	if tcpAddr, ok := addr.(*net.TCPAddr); !ok || tcpAddr == nil {
		return fmt.Errorf("testChecker: got %T want *net.TCPAddr", addr)
	}

	t.calls = append(t.calls, fmt.Sprintf("%s %v %s %x", dialAddr, addr, key.Type(), key.Marshal()))

	return nil
}

// netPipe is analogous to net.Pipe, but it uses a real net.Conn, and
// therefore is buffered (net.Pipe deadlocks if both sides start with
// a write.)
func netPipe() (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener, err = net.Listen("tcp", "[::1]:0")
		if err != nil {
			return nil, nil, err
		}
	}
	defer listener.Close()
	c1, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	c2, err := listener.Accept()
	if err != nil {
		c1.Close()
		return nil, nil, err
	}

	return c1, c2, nil
}

// noiseTransport inserts ignore messages to check that the read loop
// and the key exchange filters out these messages.
type noiseTransport struct {
	keyingTransport
}

func (t *noiseTransport) writePacket(p []byte) error {
	ignore := []byte{msgIgnore}
	if err := t.keyingTransport.writePacket(ignore); err != nil {
		return err
	}
	debug := []byte{msgDebug, 1, 2, 3}
	if err := t.keyingTransport.writePacket(debug); err != nil {
		return err
	}

	return t.keyingTransport.writePacket(p)
}

func addNoiseTransport(t keyingTransport) keyingTransport {
	return &noiseTransport{t}
}

// handshakePair creates two handshakeTransports connected with each
// other. If the noise argument is true, both transports will try to
// confuse the other side by sending ignore and debug messages.
func handshakePair(clientConf *ClientConfig, addr string, noise bool) (client *handshakeTransport, server *handshakeTransport, err error) {
	a, b, err := netPipe()
	if err != nil {
		return nil, nil, err
	}

	var trC, trS keyingTransport

	trC = newTransport(a, rand.Reader, true)
	trS = newTransport(b, rand.Reader, false)
	if noise {
		trC = addNoiseTransport(trC)
		trS = addNoiseTransport(trS)
	}
	clientConf.SetDefaults()

	v := []byte("version")
	client = newClientTransport(trC, v, v, clientConf, addr, a.RemoteAddr())

	serverConf := &ServerConfig{}
	serverConf.AddHostKey(testSigners["ecdsa"])
	serverConf.AddHostKey(testSigners["rsa"])
	serverConf.SetDefaults()
	server = newServerTransport(trS, v, v, serverConf)

	if err := server.waitSession(); err != nil {
		return nil, nil, fmt.Errorf("server.waitSession: %v", err)
	}
	if err := client.waitSession(); err != nil {
		return nil, nil, fmt.Errorf("client.waitSession: %v", err)
	}

	return client, server, nil
}

func TestHandshakeBasic(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("see golang.org/issue/7237")
	}

	checker := &syncChecker{
		waitCall: make(chan int, 10),
		called:   make(chan int, 10),
	}

	checker.waitCall <- 1
	trC, trS, err := handshakePair(&ClientConfig{HostKeyCallback: checker.Check}, "addr", false)
	if err != nil {
		t.Fatalf("handshakePair: %v", err)
	}

	defer trC.Close()
	defer trS.Close()

	// Let first kex complete normally.
	<-checker.called

	clientDone := make(chan int, 0)
	gotHalf := make(chan int, 0)
	const N = 20

	go func() {
		defer close(clientDone)
		// Client writes a bunch of stuff, and does a key
		// change in the middle. This should not confuse the
		// handshake in progress. We do this twice, so we test
		// that the packet buffer is reset correctly.
		for i := 0; i < N; i++ {
			p := []byte{msgRequestSuccess, byte(i)}
			if err := trC.writePacket(p); err != nil {
				t.Fatalf("sendPacket: %v", err)
			}
			if (i % 10) == 5 {
				<-gotHalf
				// halfway through, we request a key change.
				trC.requestKeyExchange()

				// Wait until we can be sure the key
				// change has really started before we
				// write more.
				<-checker.called
			}
			if (i % 10) == 7 {
				// write some packets until the kex
				// completes, to test buffering of
				// packets.
				checker.waitCall <- 1
			}
		}
	}()

	// Server checks that client messages come in cleanly
	i := 0
	err = nil
	for ; i < N; i++ {
		var p []byte
		p, err = trS.readPacket()
		if err != nil {
			break
		}
		if (i % 10) == 5 {
			gotHalf <- 1
		}

		want := []byte{msgRequestSuccess, byte(i)}
		if bytes.Compare(p, want) != 0 {
			t.Errorf("message %d: got %v, want %v", i, p, want)
		}
	}
	<-clientDone
	if err != nil && err != io.EOF {
		t.Fatalf("server error: %v", err)
	}
	if i != N {
		t.Errorf("received %d messages, want 10.", i)
	}

	close(checker.called)
	if _, ok := <-checker.called; ok {
		// If all went well, we registered exactly 2 key changes: one
		// that establishes the session, and one that we requested
		// additionally.
		t.Fatalf("got another host key checks after 2 handshakes")
	}
}

func TestForceFirstKex(t *testing.T) {
	// like handshakePair, but must access the keyingTransport.
	checker := &testChecker{}
	clientConf := &ClientConfig{HostKeyCallback: checker.Check}
	a, b, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}

	var trC, trS keyingTransport

	trC = newTransport(a, rand.Reader, true)

	// This is the disallowed packet:
	trC.writePacket(Marshal(&serviceRequestMsg{serviceUserAuth}))

	// Rest of the setup.
	trS = newTransport(b, rand.Reader, false)
	clientConf.SetDefaults()

	v := []byte("version")
	client := newClientTransport(trC, v, v, clientConf, "addr", a.RemoteAddr())

	serverConf := &ServerConfig{}
	serverConf.AddHostKey(testSigners["ecdsa"])
	serverConf.AddHostKey(testSigners["rsa"])
	serverConf.SetDefaults()
	server := newServerTransport(trS, v, v, serverConf)

	defer client.Close()
	defer server.Close()

	// We setup the initial key exchange, but the remote side
	// tries to send serviceRequestMsg in cleartext, which is
	// disallowed.

	if err := server.waitSession(); err == nil {
		t.Errorf("server first kex init should reject unexpected packet")
	}
}

func TestHandshakeAutoRekeyWrite(t *testing.T) {
	checker := &syncChecker{
		called:   make(chan int, 10),
		waitCall: nil,
	}
	clientConf := &ClientConfig{HostKeyCallback: checker.Check}
	clientConf.RekeyThreshold = 500
	trC, trS, err := handshakePair(clientConf, "addr", false)
	if err != nil {
		t.Fatalf("handshakePair: %v", err)
	}
	defer trC.Close()
	defer trS.Close()

	input := make([]byte, 251)
	input[0] = msgRequestSuccess

	done := make(chan int, 1)
	const numPacket = 5
	go func() {
		defer close(done)
		j := 0
		for ; j < numPacket; j++ {
			if p, err := trS.readPacket(); err != nil {
				break
			} else if !bytes.Equal(input, p) {
				t.Errorf("got packet type %d, want %d", p[0], input[0])
			}
		}

		if j != numPacket {
			t.Errorf("got %d, want 5 messages", j)
		}
	}()

	<-checker.called

	for i := 0; i < numPacket; i++ {
		p := make([]byte, len(input))
		copy(p, input)
		if err := trC.writePacket(p); err != nil {
			t.Errorf("writePacket: %v", err)
		}
		if i == 2 {
			// Make sure the kex is in progress.
			<-checker.called
		}

	}
	<-done
}

type syncChecker struct {
	waitCall chan int
	called   chan int
}

func (c *syncChecker) Check(dialAddr string, addr net.Addr, key PublicKey) error {
	c.called <- 1
	if c.waitCall != nil {
		<-c.waitCall
	}
	return nil
}

func TestHandshakeAutoRekeyRead(t *testing.T) {
	sync := &syncChecker{
		called:   make(chan int, 2),
		waitCall: nil,
	}
	clientConf := &ClientConfig{
		HostKeyCallback: sync.Check,
	}
	clientConf.RekeyThreshold = 500

	trC, trS, err := handshakePair(clientConf, "addr", false)
	if err != nil {
		t.Fatalf("handshakePair: %v", err)
	}
	defer trC.Close()
	defer trS.Close()

	packet := make([]byte, 501)
	packet[0] = msgRequestSuccess
	if err := trS.writePacket(packet); err != nil {
		t.Fatalf("writePacket: %v", err)
	}

	// While we read out the packet, a key change will be
	// initiated.
	done := make(chan int, 1)
	go func() {
		defer close(done)
		if _, err := trC.readPacket(); err != nil {
			t.Fatalf("readPacket(client): %v", err)
		}

	}()

	<-done
	<-sync.called
}

// errorKeyingTransport generates errors after a given number of
// read/write operations.
type errorKeyingTransport struct {
	packetConn
	readLeft, writeLeft int
}

func (n *errorKeyingTransport) prepareKeyChange(*algorithms, *kexResult) error {
	return nil
}

func (n *errorKeyingTransport) setStrictMode() error { return nil }

func (n *errorKeyingTransport) setInitialKEXDone() {}

func (n *errorKeyingTransport) getSessionID() []byte {
	return nil
}

func (n *errorKeyingTransport) writePacket(packet []byte) error {
	if n.writeLeft == 0 {
		n.Close()
		return errors.New("barf")
	}

	n.writeLeft--
	return n.packetConn.writePacket(packet)
}

func (n *errorKeyingTransport) readPacket() ([]byte, error) {
	if n.readLeft == 0 {
		n.Close()
		return nil, errors.New("barf")
	}

	n.readLeft--
	return n.packetConn.readPacket()
}

func TestHandshakeErrorHandlingRead(t *testing.T) {
	for i := 0; i < 20; i++ {
		testHandshakeErrorHandlingN(t, i, -1, false)
	}
}

func TestHandshakeErrorHandlingWrite(t *testing.T) {
	for i := 0; i < 20; i++ {
		testHandshakeErrorHandlingN(t, -1, i, false)
	}
}

func TestHandshakeErrorHandlingReadCoupled(t *testing.T) {
	for i := 0; i < 20; i++ {
		testHandshakeErrorHandlingN(t, i, -1, true)
	}
}

func TestHandshakeErrorHandlingWriteCoupled(t *testing.T) {
	for i := 0; i < 20; i++ {
		testHandshakeErrorHandlingN(t, -1, i, true)
	}
}

// testHandshakeErrorHandlingN runs handshakes, injecting errors. If
// handshakeTransport deadlocks, the go runtime will detect it and
// panic.
func testHandshakeErrorHandlingN(t *testing.T, readLimit, writeLimit int, coupled bool) {
	if runtime.GOOS == "js" && runtime.GOARCH == "wasm" {
		t.Skip("skipping on js/wasm; see golang.org/issue/32840")
	}
	msg := Marshal(&serviceRequestMsg{strings.Repeat("x", int(minRekeyThreshold)/4)})

	a, b := memPipe()
	defer a.Close()
	defer b.Close()

	key := testSigners["ecdsa"]
	serverConf := Config{RekeyThreshold: minRekeyThreshold}
	serverConf.SetDefaults()
	serverConn := newHandshakeTransport(&errorKeyingTransport{a, readLimit, writeLimit}, &serverConf, []byte{'a'}, []byte{'b'})
	serverConn.hostKeys = []Signer{key}
	go serverConn.readLoop()
	go serverConn.kexLoop()

	clientConf := Config{RekeyThreshold: 10 * minRekeyThreshold}
	clientConf.SetDefaults()
	clientConn := newHandshakeTransport(&errorKeyingTransport{b, -1, -1}, &clientConf, []byte{'a'}, []byte{'b'})
	clientConn.hostKeyAlgorithms = []string{key.PublicKey().Type()}
	clientConn.hostKeyCallback = InsecureIgnoreHostKey()
	go clientConn.readLoop()
	go clientConn.kexLoop()

	var wg sync.WaitGroup

	for _, hs := range []packetConn{serverConn, clientConn} {
		if !coupled {
			wg.Add(2)
			go func(c packetConn) {
				for i := 0; ; i++ {
					str := fmt.Sprintf("%08x", i) + strings.Repeat("x", int(minRekeyThreshold)/4-8)
					err := c.writePacket(Marshal(&serviceRequestMsg{str}))
					if err != nil {
						break
					}
				}
				wg.Done()
				c.Close()
			}(hs)
			go func(c packetConn) {
				for {
					_, err := c.readPacket()
					if err != nil {
						break
					}
				}
				wg.Done()
			}(hs)
		} else {
			wg.Add(1)
			go func(c packetConn) {
				for {
					_, err := c.readPacket()
					if err != nil {
						break
					}
					if err := c.writePacket(msg); err != nil {
						break
					}

				}
				wg.Done()
			}(hs)
		}
	}
	wg.Wait()
}

func TestDisconnect(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("see golang.org/issue/7237")
	}
	checker := &testChecker{}
	trC, trS, err := handshakePair(&ClientConfig{HostKeyCallback: checker.Check}, "addr", false)
	if err != nil {
		t.Fatalf("handshakePair: %v", err)
	}

	defer trC.Close()
	defer trS.Close()

	trC.writePacket([]byte{msgRequestSuccess, 0, 0})
	errMsg := &disconnectMsg{
		Reason:  42,
		Message: "such is life",
	}
	trC.writePacket(Marshal(errMsg))
	trC.writePacket([]byte{msgRequestSuccess, 0, 0})

	packet, err := trS.readPacket()
	if err != nil {
		t.Fatalf("readPacket 1: %v", err)
	}
	if packet[0] != msgRequestSuccess {
		t.Errorf("got packet %v, want packet type %d", packet, msgRequestSuccess)
	}

	_, err = trS.readPacket()
	if err == nil {
		t.Errorf("readPacket 2 succeeded")
	} else if !reflect.DeepEqual(err, errMsg) {
		t.Errorf("got error %#v, want %#v", err, errMsg)
	}

	_, err = trS.readPacket()
	if err == nil {
		t.Errorf("readPacket 3 succeeded")
	}
}

func TestHandshakeRekeyDefault(t *testing.T) {
	clientConf := &ClientConfig{
		Config: Config{
			Ciphers: []string{"aes128-ctr"},
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}
	trC, trS, err := handshakePair(clientConf, "addr", false)
	if err != nil {
		t.Fatalf("handshakePair: %v", err)
	}
	defer trC.Close()
	defer trS.Close()

	trC.writePacket([]byte{msgRequestSuccess, 0, 0})
	trC.Close()

	rgb := (1024 + trC.readBytesLeft) >> 30
	wgb := (1024 + trC.writeBytesLeft) >> 30

	if rgb != 64 {
		t.Errorf("got rekey after %dG read, want 64G", rgb)
	}
	if wgb != 64 {
		t.Errorf("got rekey after %dG write, want 64G", wgb)
	}
}

// TestNoSHA2Support tests a host key Signer that is not an AlgorithmSigner and
// therefore can't do SHA-2 signatures. Ensures the server does not advertise
// support for them in this case.
func TestNoSHA2Support(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	serverConf := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{}, nil
		},
	}
	serverConf.AddHostKey(&legacyRSASigner{testSigners["rsa"]})
	go func() {
		_, _, _, err := NewServerConn(c1, serverConf)
		if err != nil {
			t.Error(err)
		}
	}()

	clientConf := &ClientConfig{
		User:            "test",
		Auth:            []AuthMethod{Password("testpw")},
		HostKeyCallback: FixedHostKey(testSigners["rsa"].PublicKey()),
	}

	if _, _, _, err := NewClientConn(c2, "", clientConf); err != nil {
		t.Fatal(err)
	}
}

// TestNoSHA2SupportClientForcesSHA2 tests that a client which only offers
// rsa-sha2-256/512 host key algorithms can't make a server with a host key
// Signer that is not an AlgorithmSigner negotiate an algorithm it can't sign
// with. The handshake must fail cleanly instead of crashing the server.
func TestNoSHA2SupportClientForcesSHA2(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	serverConf := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{}, nil
		},
	}
	serverConf.AddHostKey(&legacyRSASigner{testSigners["rsa"]})
	serverErr := make(chan error, 1)
	go func() {
		_, _, _, err := NewServerConn(c1, serverConf)
		serverErr <- err
	}()

	clientConf := &ClientConfig{
		User:              "test",
		Auth:              []AuthMethod{Password("testpw")},
		HostKeyCallback:   FixedHostKey(testSigners["rsa"].PublicKey()),
		HostKeyAlgorithms: []string{SigAlgoRSASHA2256, SigAlgoRSASHA2512},
	}

	_, _, _, err = NewClientConn(c2, "", clientConf)
	if err == nil {
		t.Fatal("NewClientConn succeeded, want host key negotiation failure")
	}
	if !strings.Contains(err.Error(), "no common algorithm for host key") {
		t.Errorf("NewClientConn: got error %q, want host key negotiation failure", err)
	}

	if err := <-serverErr; err == nil {
		t.Error("NewServerConn succeeded, want host key negotiation failure")
	}
}

// TestNoSHA2SupportCert tests a host certificate whose underlying Signer is not
// an AlgorithmSigner and therefore can't do SHA-2 signatures. Ensures the
// server does not advertise the rsa-sha2-256/512 certificate algorithms in
// this case.
func TestNoSHA2SupportCert(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	hostSigner := &legacyRSASigner{testSigners["rsa"]}
	hostCert := &Certificate{
		Key:             hostSigner.PublicKey(),
		CertType:        HostCert,
		ValidPrincipals: []string{"host.example.com"},
		ValidBefore:     CertTimeInfinity,
	}
	if err := hostCert.SignCert(rand.Reader, testSigners["ecdsa"]); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	certSigner, err := NewCertSigner(hostCert, hostSigner)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}
	if _, ok := certSigner.(AlgorithmSigner); ok {
		t.Fatal("NewCertSigner returned an AlgorithmSigner for a non-AlgorithmSigner key")
	}

	serverConf := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{}, nil
		},
	}
	serverConf.AddHostKey(certSigner)
	go func() {
		_, _, _, err := NewServerConn(c1, serverConf)
		if err != nil {
			t.Error(err)
		}
	}()

	var gotHostKey PublicKey
	clientConf := &ClientConfig{
		User: "test",
		Auth: []AuthMethod{Password("testpw")},
		HostKeyCallback: func(hostname string, remote net.Addr, key PublicKey) error {
			gotHostKey = key
			return nil
		},
	}

	if _, _, _, err := NewClientConn(c2, "", clientConf); err != nil {
		t.Fatal(err)
	}
	if gotHostKey == nil || gotHostKey.Type() != CertAlgoRSAv01 {
		t.Errorf("got host key %v, want an %s certificate", gotHostKey, CertAlgoRSAv01)
	}
}

func TestStrictKEXResetSeqFirstKEX(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("see golang.org/issue/7237")
	}

	checker := &syncChecker{
		waitCall: make(chan int, 10),
		called:   make(chan int, 10),
	}

	checker.waitCall <- 1
	trC, trS, err := handshakePair(&ClientConfig{HostKeyCallback: checker.Check}, "addr", false)
	if err != nil {
		t.Fatalf("handshakePair: %v", err)
	}
	<-checker.called

	t.Cleanup(func() {
		trC.Close()
		trS.Close()
	})

	// close the handshake transports before checking the sequence number to
	// avoid races.
	trC.Close()
	trS.Close()

	// Verify the strict-KEX sequence number reset after msgNewKeys. Adapted
	// from upstream: this 2021 base does not implement RFC 8308 ext-info, so
	// the server never sends a post-handshake msgExtInfo packet. Upstream
	// therefore expects client reader 2 / writer 0 and server reader 1 /
	// writer 1 (the extra client read and server write being the ext-info
	// packet). Here, with no ext-info exchanged, both sides settle at
	// reader 1 / writer 0 after the reset. The security property under test is
	// unchanged: after the initial KEX the strict-mode reset drove the
	// sequence numbers back to ~0 (a non-reset run reaches the mid-single
	// digits per packet, see TestSeqNumIncrease).
	if trC.conn.(*transport).reader.seqNum != 1 || trC.conn.(*transport).writer.seqNum != 0 ||
		trS.conn.(*transport).reader.seqNum != 1 || trS.conn.(*transport).writer.seqNum != 0 {
		t.Errorf(
			"unexpected sequence counters:\nclient: reader %d, writer %d\nserver: reader %d, writer %d",
			trC.conn.(*transport).reader.seqNum,
			trC.conn.(*transport).writer.seqNum,
			trS.conn.(*transport).reader.seqNum,
			trS.conn.(*transport).writer.seqNum,
		)
	}
}

func TestStrictKEXResetSeqSuccessiveKEX(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("see golang.org/issue/7237")
	}

	checker := &syncChecker{
		waitCall: make(chan int, 10),
		called:   make(chan int, 10),
	}

	checker.waitCall <- 1
	trC, trS, err := handshakePair(&ClientConfig{HostKeyCallback: checker.Check}, "addr", false)
	if err != nil {
		t.Fatalf("handshakePair: %v", err)
	}
	<-checker.called

	t.Cleanup(func() {
		trC.Close()
		trS.Close()
	})

	// write and read five packets on either side to bump the sequence numbers
	for i := 0; i < 5; i++ {
		if err := trC.writePacket([]byte{msgRequestSuccess}); err != nil {
			t.Fatalf("writePacket failed: %s", err)
		}
		if _, err := trS.readPacket(); err != nil {
			t.Fatalf("readPacket failed: %s", err)
		}
		if err := trS.writePacket([]byte{msgRequestSuccess}); err != nil {
			t.Fatalf("writePacket failed: %s", err)
		}
		if _, err := trC.readPacket(); err != nil {
			t.Fatalf("readPacket failed: %s", err)
		}
	}

	// Request a key exchange, which should cause the sequence numbers to reset
	checker.waitCall <- 1
	trC.requestKeyExchange()
	<-checker.called

	// write a packet on the client, and then read it, to verify the key change has actually happened, since
	// the HostKeyCallback is called _during_ the handshake, so isn't actually indicative of the handshake
	// finishing.
	dummyPacket := []byte{99}
	if err := trS.writePacket(dummyPacket); err != nil {
		t.Fatalf("writePacket failed: %s", err)
	}
	if p, err := trC.readPacket(); err != nil {
		t.Fatalf("readPacket failed: %s", err)
	} else if !bytes.Equal(p, dummyPacket) {
		t.Fatalf("unexpected packet: got %x, want %x", p, dummyPacket)
	}

	// close the handshake transports before checking the sequence number to
	// avoid races.
	trC.Close()
	trS.Close()

	// Adapted from upstream for the no-ext-info 2021 base (see
	// TestStrictKEXResetSeqFirstKEX). After bumping the counters into the
	// mid-single digits and triggering a successive KEX, strict mode resets
	// them; the only post-reset traffic is the single dummy packet write/read
	// plus the (re)KEX accounting, so the client settles at reader 2 / writer 0
	// and the server at reader 1 / writer 1. The reset (vs. the ~6 reached in
	// TestSeqNumIncrease) is the property under test.
	if trC.conn.(*transport).reader.seqNum != 2 || trC.conn.(*transport).writer.seqNum != 0 ||
		trS.conn.(*transport).reader.seqNum != 1 || trS.conn.(*transport).writer.seqNum != 1 {
		t.Errorf(
			"unexpected sequence counters:\nclient: reader %d, writer %d\nserver: reader %d, writer %d",
			trC.conn.(*transport).reader.seqNum,
			trC.conn.(*transport).writer.seqNum,
			trS.conn.(*transport).reader.seqNum,
			trS.conn.(*transport).writer.seqNum,
		)
	}
}

func TestSeqNumIncrease(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("see golang.org/issue/7237")
	}

	checker := &syncChecker{
		waitCall: make(chan int, 10),
		called:   make(chan int, 10),
	}

	checker.waitCall <- 1
	trC, trS, err := handshakePair(&ClientConfig{HostKeyCallback: checker.Check}, "addr", false)
	if err != nil {
		t.Fatalf("handshakePair: %v", err)
	}
	<-checker.called

	t.Cleanup(func() {
		trC.Close()
		trS.Close()
	})

	// write and read five packets on either side to bump the sequence numbers
	for i := 0; i < 5; i++ {
		if err := trC.writePacket([]byte{msgRequestSuccess}); err != nil {
			t.Fatalf("writePacket failed: %s", err)
		}
		if _, err := trS.readPacket(); err != nil {
			t.Fatalf("readPacket failed: %s", err)
		}
		if err := trS.writePacket([]byte{msgRequestSuccess}); err != nil {
			t.Fatalf("writePacket failed: %s", err)
		}
		if _, err := trC.readPacket(); err != nil {
			t.Fatalf("readPacket failed: %s", err)
		}
	}

	// close the handshake transports before checking the sequence number to
	// avoid races.
	trC.Close()
	trS.Close()

	// Adapted from upstream for the no-ext-info 2021 base: upstream expects
	// client reader 7 / server reader 6 / writer 6 because the discarded
	// msgExtInfo packet adds one to several counts. This base sends no
	// ext-info packet, so without any intervening KEX reset all four counters
	// settle symmetrically at reader 6 / writer 5 on the client and reader 6 /
	// writer 5 on the server. The property under test (no strict-KEX reset
	// occurs here, so sequence numbers increase by 1 per packet and reach the
	// mid-single digits) is unchanged.
	if trC.conn.(*transport).reader.seqNum != 6 || trC.conn.(*transport).writer.seqNum != 5 ||
		trS.conn.(*transport).reader.seqNum != 6 || trS.conn.(*transport).writer.seqNum != 5 {
		t.Errorf(
			"unexpected sequence counters:\nclient: reader %d, writer %d\nserver: reader %d, writer %d",
			trC.conn.(*transport).reader.seqNum,
			trC.conn.(*transport).writer.seqNum,
			trS.conn.(*transport).reader.seqNum,
			trS.conn.(*transport).writer.seqNum,
		)
	}
}

func TestStrictKEXUnexpectedMsg(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("see golang.org/issue/7237")
	}

	// Check that unexpected messages during the handshake cause failure
	_, _, err := handshakePair(&ClientConfig{HostKeyCallback: func(hostname string, remote net.Addr, key PublicKey) error { return nil }}, "addr", true)
	if err == nil {
		t.Fatal("handshake should fail when there are unexpected messages during the handshake")
	}

	trC, trS, err := handshakePair(&ClientConfig{HostKeyCallback: func(hostname string, remote net.Addr, key PublicKey) error { return nil }}, "addr", false)
	if err != nil {
		t.Fatalf("handshake failed: %s", err)
	}

	// Check that ignore/debug pacekts are still ignored outside of the handshake
	if err := trC.writePacket([]byte{msgIgnore}); err != nil {
		t.Fatalf("writePacket failed: %s", err)
	}
	if err := trC.writePacket([]byte{msgDebug}); err != nil {
		t.Fatalf("writePacket failed: %s", err)
	}
	dummyPacket := []byte{99}
	if err := trC.writePacket(dummyPacket); err != nil {
		t.Fatalf("writePacket failed: %s", err)
	}

	if p, err := trS.readPacket(); err != nil {
		t.Fatalf("readPacket failed: %s", err)
	} else if !bytes.Equal(p, dummyPacket) {
		t.Fatalf("unexpected packet: got %x, want %x", p, dummyPacket)
	}
}

func TestStrictKEXMixed(t *testing.T) {
	// Test that we still support a mixed connection, where one side sends kex-strict but the other
	// side doesn't.

	a, b, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe failed: %s", err)
	}

	var trC, trS keyingTransport

	trC = newTransport(a, rand.Reader, true)
	trS = newTransport(b, rand.Reader, false)
	trS = addNoiseTransport(trS)

	clientConf := &ClientConfig{HostKeyCallback: func(hostname string, remote net.Addr, key PublicKey) error { return nil }}
	clientConf.SetDefaults()

	v := []byte("version")
	client := newClientTransport(trC, v, v, clientConf, "addr", a.RemoteAddr())

	serverConf := &ServerConfig{}
	serverConf.AddHostKey(testSigners["ecdsa"])
	serverConf.AddHostKey(testSigners["rsa"])
	serverConf.SetDefaults()

	transport := newHandshakeTransport(trS, &serverConf.Config, []byte("version"), []byte("version"))
	transport.hostKeys = serverConf.hostKeys

	readOneFailure := make(chan error, 1)
	go func() {
		if _, err := transport.readOnePacket(true); err != nil {
			readOneFailure <- err
		}
	}()

	// Basically sendKexInit, but without the kex-strict extension algorithm.
	// Adapted from upstream: this 2021 base lacks KeyAlgoRSASHA256/512, so the
	// ServerHostKeyAlgos list uses only KeyAlgoRSA, which this base supports.
	msg := &kexInitMsg{
		KexAlgos:                transport.config.KeyExchanges,
		CiphersClientServer:     transport.config.Ciphers,
		CiphersServerClient:     transport.config.Ciphers,
		MACsClientServer:        transport.config.MACs,
		MACsServerClient:        transport.config.MACs,
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
		ServerHostKeyAlgos:      []string{KeyAlgoRSA},
	}
	packet := Marshal(msg)
	// writePacket destroys the contents, so save a copy.
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)
	if err := transport.pushPacket(packetCopy); err != nil {
		t.Fatalf("pushPacket: %s", err)
	}
	transport.sentInitMsg = msg
	transport.sentInitPacket = packet

	if err := transport.getWriteError(); err != nil {
		t.Fatalf("getWriteError failed: %s", err)
	}
	var request *pendingKex
	select {
	case err = <-readOneFailure:
		t.Fatalf("server readOnePacket failed: %s", err)
	case request = <-transport.startKex:
		break
	}

	// We expect the following calls to fail if the side which does not support
	// kex-strict sends unexpected/ignored packets during the handshake, even if
	// the other side does support kex-strict.

	if err := transport.enterKeyExchange(request.otherInit); err != nil {
		t.Fatalf("enterKeyExchange failed: %s", err)
	}
	if err := client.waitSession(); err != nil {
		t.Fatalf("client.waitSession: %v", err)
	}
}

// kexInitInjectTransport writes a single msgIgnore packet right after the
// first msgKexInit it sends. This mimics an on-path attacker inserting a
// message into the unencrypted part of the initial key exchange to shift
// the peer's receive sequence number (CVE-2023-48795, "Terrapin").
type kexInitInjectTransport struct {
	keyingTransport
	injected bool
}

func (t *kexInitInjectTransport) writePacket(p []byte) error {
	// writePacket destroys the contents, so inspect the type first.
	isKexInit := len(p) > 0 && p[0] == msgKexInit
	if err := t.keyingTransport.writePacket(p); err != nil {
		return err
	}
	if isKexInit && !t.injected {
		t.injected = true
		return t.keyingTransport.writePacket([]byte{msgIgnore})
	}
	return nil
}

func TestStrictKEXInjectedMsgAfterKexInit(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("see golang.org/issue/7237")
	}

	a, b, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe failed: %s", err)
	}

	trC := &kexInitInjectTransport{keyingTransport: newTransport(a, rand.Reader, true)}
	trS := newTransport(b, rand.Reader, false)

	clientConf := &ClientConfig{HostKeyCallback: func(hostname string, remote net.Addr, key PublicKey) error { return nil }}
	clientConf.SetDefaults()

	v := []byte("version")
	client := newClientTransport(trC, v, v, clientConf, "addr", a.RemoteAddr())
	defer client.Close()

	serverConf := &ServerConfig{}
	serverConf.AddHostKey(testSigners["ecdsa"])
	serverConf.AddHostKey(testSigners["rsa"])
	serverConf.SetDefaults()
	server := newServerTransport(trS, v, v, serverConf)
	defer server.Close()

	// Both sides negotiate strict KEX, so the msgIgnore injected between the
	// client's msgKexInit and its key exchange message must abort the
	// handshake instead of being silently dropped.
	if err := server.waitSession(); err == nil {
		t.Fatal("server accepted a message injected during the initial strict key exchange")
	}
}
