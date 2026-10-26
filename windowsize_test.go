package tftp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func TestParseWindowsize(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"1", 1, true},
		{"65535", 65535, true},
		{"16", 16, true},
		{"0", 0, false},
		{"-1", 0, false},
		{"65536", 0, false},
		{"abc", 0, false},
		{"", 0, false},
		{"16x", 0, false},
	}
	for _, c := range cases {
		got, ok := parseWindowsize(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseWindowsize(%q) = (%d,%v), want (%d,%v)",
				c.in, got, ok, c.want, c.ok)
		}
	}
}

// makeWindowTestServer creates a regular (not single-port) test server
// with windowsize enabled on both sides.
func makeWindowTestServer(serverWin, clientWin int) (*Server, *Client) {
	s, c := makeTestServer(false)
	if serverWin > 0 {
		s.SetWindowsize(serverWin)
	}
	if clientWin > 0 {
		c.SetWindowsize(clientWin)
	}
	s.SetBackoff(func(int) time.Duration { return 0 })
	c.SetBackoff(func(int) time.Duration { return 0 })
	return s, c
}

func TestWindowsizeSendReceive(t *testing.T) {
	pairs := [][2]int{
		{1, 1}, {1, 4}, {2, 2}, {2, 8}, {4, 2}, {8, 4}, {16, 3}, {32, 64},
	}
	for _, p := range pairs {
		s, c := makeWindowTestServer(p[0], p[1])
		for _, n := range []int64{
			0, 1, 100, 511, 512, 513, 1023, 1024, 1025,
			512 * 3, 512*3 + 1, 512*4 - 1, 512 * 4, 512*4 + 1,
			512*7 + 77, 50000,
		} {
			testSendReceive(t, c, n)
		}
		s.Shutdown()
	}
}

func TestWindowsizeRandomLengths(t *testing.T) {
	s, c := makeWindowTestServer(4, 8)
	defer s.Shutdown()
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 60; i++ {
		testSendReceive(t, c, r.Int63n(120000))
	}
}

func TestWindowsizeWithBlockSize(t *testing.T) {
	s, c := makeWindowTestServer(3, 5)
	defer s.Shutdown()
	c.SetBlockSize(1400)
	s.SetBlockSize(2000)
	for _, n := range []int64{0, 1, 1399, 1400, 1401, 1400 * 6, 1400*6 + 5, 60000} {
		testSendReceive(t, c, n)
	}
}

func TestWindowsizeWithTSize(t *testing.T) {
	s, c := makeWindowTestServer(4, 4)
	defer s.Shutdown()
	c.RequestTSize(true)
	testSendReceive(t, c, 640)
	testSendReceive(t, c, 512*9)
}

func TestWindowsizeInvalidClientValues(t *testing.T) {
	for _, n := range []int{0, -1, -65535, 65536, 1000000} {
		s, c := makeWindowTestServer(8, 0)
		c.SetWindowsize(n)
		testSendReceive(t, c, 4096)
		s.Shutdown()
	}
}

func TestWindowsizeInvalidServerValues(t *testing.T) {
	for _, n := range []int{0, -1, 65536} {
		s, c := makeWindowTestServer(0, 0)
		s.SetWindowsize(n)
		c.SetWindowsize(8)
		// Server ignores the option; transfer still completes.
		testSendReceive(t, c, 4096)
		s.Shutdown()
	}
}

// TestWindowsizeServerDisabledIgnoresOption verifies with a raw client
// that a server without SetWindowsize does not mention windowsize in the
// OACK, and that windowsize alone produces no OACK at all.
func TestWindowsizeServerDisabledIgnoresOption(t *testing.T) {
	requests := []options{
		{"windowsize": "4"},
		{"blksize": "512", "windowsize": "4"},
	}
	for _, opts := range requests {
		payload := []byte("12345")
		conn, done := startRawReadServer(t, payload, nil)
		raw, remote := dialRaw(t, conn.LocalAddr().(*net.UDPAddr))
		sendRawRQ(t, raw, opRRQ, "f", opts, remote)

		buf := make([]byte, 70*1024)
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := raw.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read first packet: %v", err)
		}
		p, err := parsePacket(buf[:n])
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		switch pp := p.(type) {
		case pDATA:
			if _, onlyWindow := opts["windowsize"]; !onlyWindow {
				t.Fatalf("unexpected DATA without windowsize-only request")
			}
			if pp.block() != 1 {
				t.Fatalf("want DATA(1), got DATA(%d)", pp.block())
			}
		case pOACK:
			o, err := unpackOACK(pp)
			if err != nil {
				t.Fatalf("unpack OACK: %v", err)
			}
			if _, present := o["windowsize"]; present {
				t.Fatalf("windowsize must not be in OACK: %v", o)
			}
			if o["blksize"] != "512" {
				t.Fatalf("blksize missing from OACK: %v", o)
			}
		default:
			t.Fatalf("unexpected packet %T", p)
		}
		sendRawError(t, raw, addr)
		raw.Close()
		conn.Close()
		waitHandlerDone(t, done)
	}
}

// TestWindowsizeServerClampsToMaximum checks the negotiated window is
// min(request, server maximum) and that the server bursts no more than
// the negotiated number of blocks before an ACK.
func TestWindowsizeServerClampsToMaximum(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 2*512+100) // 3 blocks, last short
	conn, done := startRawReadServer(t, payload, func(s *Server) {
		s.SetWindowsize(2)
		s.SetTimeout(time.Second)
	})
	raw, remote := dialRaw(t, conn.LocalAddr().(*net.UDPAddr))
	sendRawRQ(t, raw, opRRQ, "f", options{"windowsize": "8"}, remote)

	buf := make([]byte, datagramLength)
	oack := readRawPacket(t, raw, buf)
	o, ok := oack.pkt.(pOACK)
	if !ok {
		t.Fatalf("want OACK, got %T", oack.pkt)
	}
	opts, _ := unpackOACK(o)
	if opts["windowsize"] != "2" {
		t.Fatalf("want windowsize=2, got %q", opts["windowsize"])
	}
	sendRawAck(t, raw, 0, oack.addr)

	// Expect exactly DATA(1) and DATA(2) in the burst.
	d1 := readRawPacket(t, raw, buf)
	if block := d1.pkt.(pDATA).block(); block != 1 {
		t.Fatalf("want DATA(1), got %d", block)
	}
	d2 := readRawPacket(t, raw, buf)
	if block := d2.pkt.(pDATA).block(); block != 2 {
		t.Fatalf("want DATA(2), got %d", block)
	}
	// DATA(3) must not arrive before ACK(2).
	_ = raw.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if n, _, err := raw.ReadFromUDP(buf); err == nil {
		t.Fatalf("unexpected packet before ACK(2): %d bytes", n)
	}
	sendRawAck(t, raw, 2, d2.addr)
	d3 := readRawPacket(t, raw, buf)
	if block := d3.pkt.(pDATA).block(); block != 3 {
		t.Fatalf("want DATA(3), got %d", block)
	}
	sendRawAck(t, raw, 3, d3.addr)

	raw.Close()
	conn.Close()
	waitHandlerDone(t, done)
}

// TestWindowsizeServerInvalidRequest verifies illegal windowsize
// values are treated as if the option was absent.
func TestWindowsizeServerInvalidRequest(t *testing.T) {
	for _, bad := range []string{"0", "-1", "65536", "abc", "1.5", ""} {
		payload := []byte("12345")
		conn, done := startRawReadServer(t, payload, func(s *Server) {
			s.SetWindowsize(8)
		})
		raw, remote := dialRaw(t, conn.LocalAddr().(*net.UDPAddr))
		opts := options{"blksize": "512"}
		if bad != "" {
			opts["windowsize"] = bad
		}
		sendRawRQ(t, raw, opRRQ, "f", opts, remote)

		buf := make([]byte, datagramLength)
		pkt := readRawPacket(t, raw, buf)
		o, ok := pkt.pkt.(pOACK)
		if !ok {
			t.Fatalf("bad=%q: want OACK, got %T", bad, pkt.pkt)
		}
		oo, _ := unpackOACK(o)
		if _, present := oo["windowsize"]; present {
			t.Fatalf("bad=%q: windowsize must be dropped, got %v", bad, oo)
		}
		sendRawError(t, raw, pkt.addr)
		raw.Close()
		conn.Close()
		waitHandlerDone(t, done)
	}
}

// TestWindowsizeClientRejectsBadOACK checks that the client aborts the
// transfer when the OACK carries no, or an illegal, windowsize value
// after the client requested one. OACK without windowsize, on the other
// hand, falls back to stop-and-wait and succeeds.
func TestWindowsizeClientRejectsBadOACK(t *testing.T) {
	for _, bad := range []string{"0", "abc", "9", "65536", "-4"} {
		// RRQ (client receives).
		addr, shutdown := startFakeOACKServer(t, options{"windowsize": bad})
		c, err := NewClient(addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetTimeout(time.Second)
		c.SetRetries(1)
		c.SetBackoff(func(int) time.Duration { return 0 })
		c.SetWindowsize(4)
		if wt, err := c.Receive("f", "octet"); err == nil {
			t.Fatalf("bad=%q: Receive must fail", bad)
			wt.WriteTo(io.Discard)
		}
		shutdown()

		// WRQ (client sends).
		addr, shutdown = startFakeOACKServer(t, options{"windowsize": bad})
		c, err = NewClient(addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetTimeout(time.Second)
		c.SetRetries(1)
		c.SetBackoff(func(int) time.Duration { return 0 })
		c.SetWindowsize(4)
		if rf, err := c.Send("f", "octet"); err == nil {
			t.Fatalf("bad=%q: Send must fail", bad)
			rf.ReadFrom(bytes.NewReader([]byte("x")))
		}
		shutdown()
	}
}

// TestWindowsizeClientFallbackStopAndWait verifies that an OACK without
// windowsize makes the windowed client fall back to one-block-one-ACK.
func TestWindowsizeClientFallbackStopAndWait(t *testing.T) {
	payload := bytes.Repeat([]byte{0x33}, 1300) // 3 blocks, last short
	addr, shutdown := startFakeStopWaitServer(t, payload)
	defer shutdown()

	c, err := NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetWindowsize(8)
	c.SetBackoff(func(int) time.Duration { return 0 })
	wt, err := c.Receive("f", "octet")
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	var got bytes.Buffer
	n, err := wt.WriteTo(&got)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != int64(len(payload)) || !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("data mismatch: got %d bytes, want %d", n, len(payload))
	}
}

// lossyBackend is a read/write backend that only holds its lock while
// touching the map (not for the whole transfer), so duplicate request
// handlers caused by dropped requests do not serialize.
type lossyBackend struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (b *lossyBackend) handleRead(filename string, rf io.ReaderFrom) error {
	b.mu.Lock()
	data, ok := b.m[filename]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("file %q not found", filename)
	}
	_, err := rf.ReadFrom(bytes.NewReader(data))
	return err
}

func (b *lossyBackend) handleWrite(filename string, wt io.WriterTo) error {
	var buf bytes.Buffer
	if _, err := wt.WriteTo(&buf); err != nil {
		return err
	}
	b.mu.Lock()
	b.m[filename] = buf.Bytes()
	b.mu.Unlock()
	return nil
}

// TestWindowsizeLossyLink routes a windowed transfer through a UDP proxy
// that drops a fixed fraction of packets in both directions.
func TestWindowsizeLossyLink(t *testing.T) {
	b := &lossyBackend{m: make(map[string][]byte)}
	s := NewServer(b.handleRead, b.handleWrite)
	s.SetWindowsize(4)
	s.SetTimeout(200 * time.Millisecond)
	s.SetRetries(12)
	s.SetBackoff(func(int) time.Duration { return 0 })

	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(conn)
	defer s.Shutdown()

	proxy := newLossyProxy(t, loopback(conn.LocalAddr().(*net.UDPAddr)), 10, 42)
	defer proxy.close()

	c, err := NewClient(localSystem(proxy.conn))
	if err != nil {
		t.Fatal(err)
	}
	c.SetWindowsize(8)
	c.SetTimeout(200 * time.Millisecond)
	c.SetRetries(12)
	c.SetBackoff(func(int) time.Duration { return 0 })

	for _, length := range []int64{0, 512, 512 * 40, 33333} {
		filename := fmt.Sprintf("lossy-%d-%d", length, time.Now().UnixNano())
		rf, err := c.Send(filename, "octet")
		if err != nil {
			t.Fatalf("requesting write: %v", err)
		}
		r := io.LimitReader(newRandReader(rand.NewSource(42)), length)
		if n, err := rf.ReadFrom(r); err != nil || n != length {
			t.Fatalf("write over lossy link (len=%d): n=%d err=%v", length, n, err)
		}
		wt, err := c.Receive(filename, "octet")
		if err != nil {
			t.Fatalf("requesting read: %v", err)
		}
		var got bytes.Buffer
		if n, err := wt.WriteTo(&got); err != nil || n != length {
			t.Fatalf("read over lossy link (len=%d): n=%d err=%v", length, n, err)
		}
		want, _ := io.ReadAll(io.LimitReader(newRandReader(rand.NewSource(42)), length))
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("lossy transfer data mismatch (len=%d)", length)
		}
	}
}

// TestWindowsizeSinglePortIgnored verifies windowsize is ignored in
// single-port mode (both at negotiation and transfer level).
func TestWindowsizeSinglePortIgnored(t *testing.T) {
	s, c := makeTestServer(true)
	defer s.Shutdown()
	s.SetWindowsize(8)
	c.SetWindowsize(8)
	testSendReceive(t, c, 5000)

	// Upload a known file for the raw request below.
	rf, err := c.Send("sp-raw", "octet")
	if err != nil {
		t.Fatalf("send setup: %v", err)
	}
	if _, err := rf.ReadFrom(bytes.NewReader([]byte("hello windowsize"))); err != nil {
		t.Fatalf("upload setup: %v", err)
	}

	// Raw check: windowsize-only RRQ against a single-port server must
	// produce DATA(1), not an OACK.
	raw, remote := dialRaw(t, c.addr)
	defer raw.Close()
	sendRawRQ(t, raw, opRRQ, "sp-raw", options{"windowsize": "4"}, remote)
	buf := make([]byte, datagramLength)
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addr, err := raw.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	p, err := parsePacket(buf[:n])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d, ok := p.(pDATA); !ok || d.block() != 1 {
		t.Fatalf("want DATA(1), got %T", p)
	}
	sendRawError(t, raw, addr)
}

//
// Helpers
//

type rawPacket struct {
	pkt  interface{}
	addr *net.UDPAddr
}

func readRawPacket(t *testing.T, conn *net.UDPConn, buf []byte) rawPacket {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	p, err := parsePacket(buf[:n])
	if err != nil {
		t.Fatalf("parse packet: %v", err)
	}
	return rawPacket{pkt: p, addr: addr}
}

func sendRawRQ(t *testing.T, conn *net.UDPConn, op uint16, filename string, opts options, addr *net.UDPAddr) {
	t.Helper()
	b := make([]byte, datagramLength)
	n := packRQ(b, op, filename, "octet", opts)
	if _, err := conn.WriteToUDP(b[:n], addr); err != nil {
		t.Fatalf("send request: %v", err)
	}
}

func sendRawAck(t *testing.T, conn *net.UDPConn, block uint16, addr *net.UDPAddr) {
	t.Helper()
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], opACK)
	binary.BigEndian.PutUint16(b[2:4], block)
	if _, err := conn.WriteToUDP(b, addr); err != nil {
		t.Fatalf("send ACK(%d): %v", block, err)
	}
}

func sendRawError(t *testing.T, conn *net.UDPConn, addr *net.UDPAddr) {
	t.Helper()
	b := make([]byte, datagramLength)
	n := packERROR(b, 1, "test abort")
	_, _ = conn.WriteToUDP(b[:n], addr)
}

func dialRaw(t *testing.T, target *net.UDPAddr) (*net.UDPConn, *net.UDPAddr) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("listen raw: %v", err)
	}
	return conn, loopback(target)
}

// loopback returns a reachable loopback address for targets whose IP is
// unspecified (e.g. sockets listening on [::]).
func loopback(a *net.UDPAddr) *net.UDPAddr {
	if a.IP.IsUnspecified() {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: a.Port}
	}
	return a
}

// startRawReadServer starts a server serving payload from its read
// handler. configure may tune the server before serving. It returns the
// listening connection and a channel receiving the handler result.
func startRawReadServer(t *testing.T, payload []byte, configure func(*Server)) (*net.UDPConn, chan error) {
	t.Helper()
	done := make(chan error, 1)
	s := NewServer(func(filename string, rf io.ReaderFrom) error {
		_, err := rf.ReadFrom(bytes.NewReader(payload))
		done <- err
		return err
	}, nil)
	s.SetTimeout(500 * time.Millisecond)
	s.SetRetries(6)
	s.SetBackoff(func(int) time.Duration { return 0 })
	if configure != nil {
		configure(s)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	go s.Serve(conn)
	return conn, done
}

func waitHandlerDone(t *testing.T, done chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("server handler did not finish")
	}
}

// startFakeOACKServer runs a minimal UDP server that answers the first
// request with the given OACK options and then reads one more packet
// (typically the client ERROR). It returns the server address and a
// shutdown function.
func startFakeOACKServer(t *testing.T, oack options) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("listen fake: %v", err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		buf := make([]byte, datagramLength)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if _, err := parsePacket(buf[:n]); err != nil {
			return
		}
		ob := make([]byte, datagramLength)
		m := packOACK(ob, oack)
		_, _ = conn.WriteToUDP(ob[:m], addr)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _, _ = conn.ReadFromUDP(buf) // ERROR or aborting client
	}()
	return localSystem(conn), func() {
		conn.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
		}
	}
}

// startFakeStopWaitServer runs a minimal standard (stop-and-wait) read
// server that OACKs blksize but not windowsize, then sends payload one
// 512-byte block per ACK.
func startFakeStopWaitServer(t *testing.T, payload []byte) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("listen fake: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, datagramLength)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if _, err := parsePacket(buf[:n]); err != nil {
			return
		}
		ob := make([]byte, datagramLength)
		m := packOACK(ob, options{"blksize": "512"})
		_, _ = conn.WriteToUDP(ob[:m], addr)
		// Wait for ACK(0).
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, addr, err = conn.ReadFromUDP(buf); err != nil {
			return
		}
		for block := uint16(1); ; block++ {
			start := int(block-1) * 512
			end := start + 512
			if end > len(payload) {
				end = len(payload)
			}
			pkt := make([]byte, 4+(end-start))
			binary.BigEndian.PutUint16(pkt[0:2], opDATA)
			binary.BigEndian.PutUint16(pkt[2:4], block)
			copy(pkt[4:], payload[start:end])
			for attempt := 0; attempt < 10; attempt++ {
				_, _ = conn.WriteToUDP(pkt, addr)
				_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				an, aaddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				ap, err := parsePacket(buf[:an])
				if err != nil {
					continue
				}
				if ack, ok := ap.(pACK); ok && ack.block() == block {
					addr = aaddr
					break
				}
			}
			if end-start < 512 {
				return
			}
		}
	}()
	return localSystem(conn), func() {
		conn.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

// lossyProxy is a tiny UDP NAT relay that forwards packets between a
// client and the real server, dropping a percentage of them in both
// directions.
type lossyProxy struct {
	conn        *net.UDPConn
	target      *net.UDPAddr
	rnd         *rand.Rand
	dropPercent int
	mu          sync.Mutex
	stop        chan struct{}
}

func newLossyProxy(t *testing.T, target *net.UDPAddr, dropPercent int, seed int64) *lossyProxy {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	p := &lossyProxy{
		conn:        conn,
		target:      target,
		rnd:         rand.New(rand.NewSource(seed)),
		dropPercent: dropPercent,
		stop:        make(chan struct{}),
	}
	go p.run()
	return p
}

// proxySession tracks one NATed client session. serverTID is the
// transfer TID the server uses once it answers (the server forks a new
// socket per transfer in standard mode).
type proxySession struct {
	up        *net.UDPConn
	client    *net.UDPAddr
	mu        sync.Mutex
	serverTID *net.UDPAddr
}

func (p *lossyProxy) run() {
	sessions := make(map[string]*proxySession)
	buf := make([]byte, 70*1024)
	for {
		n, src, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		select {
		case <-p.stop:
			return
		default:
		}
		key := src.String()
		sess, ok := sessions[key]
		if !ok {
			// Use an unconnected socket: the TFTP server answers each
			// new transfer from a freshly bound port, so a connected
			// socket would discard those replies.
			up, uerr := net.ListenUDP("udp", &net.UDPAddr{})
			if uerr != nil {
				continue
			}
			sess = &proxySession{up: up, client: src}
			sessions[key] = sess
			go p.pump(sess)
		}
		if p.drop() {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		target := p.target
		sess.mu.Lock()
		if sess.serverTID != nil {
			target = sess.serverTID
		}
		sess.mu.Unlock()
		_, _ = sess.up.WriteToUDP(pkt, target)
	}
}

func (p *lossyProxy) pump(sess *proxySession) {
	buf := make([]byte, 70*1024)
	for {
		_ = sess.up.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, rsrc, err := sess.up.ReadFromUDP(buf)
		if err != nil {
			return
		}
		select {
		case <-p.stop:
			return
		default:
		}
		sess.mu.Lock()
		sess.serverTID = &net.UDPAddr{IP: rsrc.IP, Port: rsrc.Port, Zone: rsrc.Zone}
		sess.mu.Unlock()
		if p.drop() {
			continue
		}
		_, _ = p.conn.WriteToUDP(buf[:n], sess.client)
	}
}

func (p *lossyProxy) drop() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rnd.Intn(100) < p.dropPercent
}

func (p *lossyProxy) close() {
	close(p.stop)
	p.conn.Close()
}
