// Provides IPv4 ICMP echo round trip time measurements (“ping”).
package ping

// This code is mostly copied from go/src/pkg/net/ipraw_test.go,
// which is published under the following license:
//
// Copyright (c) 2012 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

var (
	seqMu sync.Mutex
	seq   uint
)

func PingUnprivileged(ctx context.Context, host string) (time.Duration, error) {
	const protocol = 1 // iana.ProtocolICMP
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return 0, err
	}
	defer c.Close()

	ips, err := net.LookupIP(host)
	if err != nil {
		return 0, err
	}
	if len(ips) == 0 {
		return 0, fmt.Errorf("Lookup(%v) = no IPs", host)
	}
	addr := &net.UDPAddr{IP: ips[0]}

	seqMu.Lock()
	thisSeq := seq
	seq++
	seqMu.Unlock()
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Data: []byte("HELLO-R-U-THERE"),
			Seq:  1 << uint(thisSeq),
		},
	}

	wb, err := m.Marshal(nil)
	if err != nil {
		return 0, err
	}
	if n, err := c.WriteTo(wb, addr); err != nil {
		return 0, err
	} else if n != len(wb) {
		return 0, fmt.Errorf("got %v; want %v", n, len(wb))
	}

	start := time.Now()
	rb := make([]byte, 1500)
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.SetReadDeadline(deadline); err != nil {
			return 0, err
		}
	}

	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		return 0, err
	}
	rm, err := icmp.ParseMessage(protocol, rb[:n])
	if err != nil {
		return 0, err
	}
	switch {
	case m.Type == ipv4.ICMPTypeEcho && rm.Type == ipv4.ICMPTypeEchoReply:
		fallthrough
	case m.Type == ipv6.ICMPTypeEchoRequest && rm.Type == ipv6.ICMPTypeEchoReply:
		fallthrough
	case m.Type == ipv4.ICMPTypeExtendedEchoRequest && rm.Type == ipv4.ICMPTypeExtendedEchoReply:
		fallthrough
	case m.Type == ipv6.ICMPTypeExtendedEchoRequest && rm.Type == ipv6.ICMPTypeExtendedEchoReply:
		return time.Since(start), nil
	default:
		return 0, fmt.Errorf("got %+v from %v; want echo reply or extended echo reply", rm, peer)
	}
}
