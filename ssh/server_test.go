// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"errors"
	"fmt"
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
