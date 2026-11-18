package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}
func pipe(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if c, ok := dst.(*net.TCPConn); ok {
		_ = c.CloseWrite()
	}
}

type countingWriter struct {
	w     io.Writer
	count *atomic.Int64
}

func (x countingWriter) Write(p []byte) (int, error) {
	n, e := x.w.Write(p)
	x.count.Add(int64(n))
	return n, e
}
func fakeEngine(t *testing.T, relay string, traffic *atomic.Int64) string {
	t.Helper()
	l := listen(t)
	go func() {
		for {
			client, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer client.Close()
				remote, e := net.Dial("tcp", relay)
				if e != nil {
					return
				}
				defer remote.Close()
				go pipe(remote, client)
				_, _ = io.Copy(countingWriter{w: client, count: traffic}, remote)
			}()
		}
	}()
	return l.Addr().String()
}
func TestTwoPathsOneSOCKSStream(t *testing.T) {
	echo := listen(t)
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	secret := make([]byte, 32)
	if _, e := rand.Read(secret); e != nil {
		t.Fatal(e)
	}
	relay := listen(t)
	srv := &server{secret: secret, direct: true, sessions: make(map[string]*session)}
	go func() {
		for {
			c, e := relay.Accept()
			if e != nil {
				return
			}
			go srv.acceptPath(c)
		}
	}()
	var a, b atomic.Int64
	p1 := fakeEngine(t, relay.Addr().String(), &a)
	p2 := fakeEngine(t, relay.Addr().String(), &b)
	app := listen(t)
	go func() {
		for {
			c, e := app.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _ = serveClient(c, []string{p1, p2}, secret) }()
		}
	}()
	c, e := net.Dial("tcp", app.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		t.Fatal(e)
	}
	resp := make([]byte, 2)
	if _, e = io.ReadFull(c, resp); e != nil || !bytes.Equal(resp, []byte{5, 0}) {
		t.Fatalf("greeting: %v %v", resp, e)
	}
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	pn, _ := strconv.Atoi(port)
	if _, e = c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(pn >> 8), byte(pn)}); e != nil {
		t.Fatal(e)
	}
	socksReplyBytes := make([]byte, 10)
	if _, e = io.ReadFull(c, socksReplyBytes); e != nil || socksReplyBytes[1] != 0 {
		t.Fatalf("connect: %v %v", socksReplyBytes, e)
	}
	payload := bytes.Repeat([]byte("multipath-works-"), 256)
	for i := 0; i < 4; i++ {
		if _, e = c.Write(payload); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(payload))
		if _, e = io.ReadFull(c, got); e != nil {
			t.Fatalf("read: %v", e)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("data corruption or wrong reassembly")
		}
	}
	if a.Load() == 0 || b.Load() == 0 {
		t.Fatalf("both engine paths were not exercised: first=%d second=%d", a.Load(), b.Load())
	}
}
func TestJoinMAC(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	j := makeJoin(key, "0123456789abcdef0123456789abcdef", "example.org:443", 1)
	if err := checkJoin(key, j); err != nil {
		t.Fatal(err)
	}
	j.Target = "example.org:444"
	if err := checkJoin(key, j); err == nil {
		t.Fatal("tampered join accepted")
	}
}
