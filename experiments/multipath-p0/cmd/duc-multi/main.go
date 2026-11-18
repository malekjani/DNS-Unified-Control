// DUC Multi P0: experimental bidirectional stream striping over multiple
// independent native DNS tunnel TCP listeners. NOT production safe:
// no connection-level ACK/retransmission/failover, and no traffic encryption
// beyond the selected native DNS engine. Keep listeners on loopback only.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/malekjani/duc-multi-p0/internal/bond"
)

type join struct {
	ID        string `json:"id"`
	Target    string `json:"target"`
	Path      int    `json:"path"`
	Timestamp int64  `json:"ts"`
	MAC       string `json:"mac"`
}
type link struct {
	conn  net.Conn
	mu    sync.Mutex
	index int
}

func (l *link) send(f bond.Frame) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	return bond.WriteFrame(l.conn, f)
}

type session struct {
	id, target string
	mu         sync.RWMutex
	links      map[int]*link
	rr         atomic.Uint64
	dest       net.Conn
	recv       *bond.OrderedReceiver
	ready      chan struct{}
	dialErr    error
	done       chan struct{}
	closeOnce  sync.Once
	sendDone   atomic.Bool
	recvDone   atomic.Bool
	onClose    func()
}

func newSession(id, target string, done func()) *session {
	return &session{id: id, target: target, links: make(map[int]*link), ready: make(chan struct{}), done: make(chan struct{}), onClose: done}
}
func (s *session) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.dest != nil {
			_ = s.dest.Close()
		}
		s.mu.Lock()
		for _, l := range s.links {
			_ = l.conn.Close()
		}
		s.mu.Unlock()
		if s.onClose != nil {
			s.onClose()
		}
	})
}
func (s *session) finishSend() { s.sendDone.Store(true); s.maybeFinish() }
func (s *session) finishRecv() { s.recvDone.Store(true); s.maybeFinish() }
func (s *session) maybeFinish() {
	if s.sendDone.Load() && s.recvDone.Load() {
		s.close()
	}
}
func (s *session) attach(l *link) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.links[l.index]; exists {
		return errors.New("duplicate path index")
	}
	if len(s.links) >= 7 {
		return errors.New("too many paths")
	}
	s.links[l.index] = l
	return nil
}
func (s *session) transmit(f bond.Frame) error {
	s.mu.RLock()
	if len(s.links) == 0 {
		s.mu.RUnlock()
		return errors.New("no paths")
	}
	// Engine path order is stable (0..6). Do not depend on Go map iteration.
	var slots [7]*link
	for idx, l := range s.links {
		if idx >= 0 && idx < 7 {
			slots[idx] = l
		}
	}
	n := len(s.links)
	i := int(s.rr.Add(1)-1) % n
	var chosen *link
	for _, l := range slots {
		if l != nil {
			if i == 0 {
				chosen = l
				break
			}
			i--
		}
	}
	s.mu.RUnlock()
	if chosen == nil {
		return errors.New("path schedule failure")
	}
	return chosen.send(f)
}
func halfCloseWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}
func (s *session) initReceiver() {
	s.recv = bond.NewOrderedReceiver(s.dest, func() { halfCloseWrite(s.dest); s.finishRecv() })
}
func (s *session) pump() {
	defer s.finishSend()
	var off uint64
	buf := make([]byte, 2048)
	for {
		n, err := s.dest.Read(buf)
		if n > 0 {
			b := append([]byte(nil), buf[:n]...)
			if e := s.transmit(bond.Frame{Type: 'D', Offset: off, Payload: b}); e != nil {
				s.close()
				return
			}
			off += uint64(n)
		}
		if err != nil {
			if err == io.EOF {
				if e := s.transmit(bond.Frame{Type: 'F', Offset: off}); e != nil {
					s.close()
				}
			} else {
				s.close()
			}
			return
		}
	}
}
func (s *session) receiveLoop(l *link) {
	defer s.close() // P0 fail-closed: a lost link can leave bytes unacknowledged.
	for {
		f, err := bond.ReadFrame(l.conn)
		if err != nil {
			return
		}
		if f.Type != 'D' && f.Type != 'F' {
			return
		}
		if err = s.recv.Push(f); err != nil {
			return
		}
		select {
		case <-s.done:
			return
		default:
		}
	}
}
func makeJoin(secret []byte, id, target string, path int) join {
	j := join{ID: id, Target: target, Path: path, Timestamp: time.Now().Unix()}
	j.MAC = joinMAC(secret, j)
	return j
}
func joinMAC(secret []byte, j join) string {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "DUC-P0\x00%s\x00%s\x00%d\x00%d", j.ID, j.Target, j.Path, j.Timestamp)
	return hex.EncodeToString(h.Sum(nil))
}
func checkJoin(secret []byte, j join) error {
	if len(j.ID) != 32 || j.Path < 0 || j.Path >= 7 {
		return errors.New("invalid join identity/path")
	}
	if _, err := hex.DecodeString(j.ID); err != nil {
		return errors.New("bad session id")
	}
	if time.Since(time.Unix(j.Timestamp, 0)) > time.Minute || time.Until(time.Unix(j.Timestamp, 0)) > time.Minute {
		return errors.New("stale join timestamp")
	}
	if len(j.Target) > 260 {
		return errors.New("target too long")
	}
	host, port, err := net.SplitHostPort(j.Target)
	if err != nil || host == "" {
		return errors.New("invalid target")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("invalid target port")
	}
	observed, err := hex.DecodeString(j.MAC)
	if err != nil || !hmac.Equal(observed, mustDecodeHex(joinMAC(secret, j))) {
		return errors.New("bad join MAC")
	}
	return nil
}
func mustDecodeHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

// Dante password may have any RFC1929-supported length; unlike the bond PSK,
// it is not required to be 32 bytes. Read only from a private file.
func readPassword(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("--egress-pass-file required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Dante password file must be owner-only (chmod 600)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || len(b) > 255 {
		return nil, errors.New("Dante password must be 1..255 bytes")
	}
	return b, nil
}

func readSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("--secret-file required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret file must be owner-only (chmod 600)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) < 32 {
		return nil, errors.New("secret must have at least 32 characters")
	}
	return b, nil
}

type server struct {
	secret   []byte
	egress   string
	username string
	password []byte
	direct   bool
	mu       sync.Mutex
	sessions map[string]*session
}

func (srv *server) getOrCreate(j join) (*session, bool, error) {
	srv.mu.Lock()
	s := srv.sessions[j.ID]
	created := false
	if s == nil {
		created = true
		s = newSession(j.ID, j.Target, func() { srv.mu.Lock(); delete(srv.sessions, j.ID); srv.mu.Unlock() })
		srv.sessions[j.ID] = s
	}
	srv.mu.Unlock()
	if s.target != j.Target {
		return nil, false, errors.New("session target mismatch")
	}
	if created {
		s.dest, s.dialErr = srv.dialTarget(j.Target)
		if s.dialErr == nil {
			s.initReceiver()
		} else {
			s.close()
		}
		close(s.ready)
	}
	<-s.ready
	if s.dialErr != nil {
		return nil, false, s.dialErr
	}
	select {
	case <-s.done:
		return nil, false, errors.New("session closed")
	default:
	}
	return s, created, nil
}
func (srv *server) dialTarget(target string) (net.Conn, error) {
	if srv.direct {
		return net.DialTimeout("tcp", target, 10*time.Second)
	}
	c, err := net.DialTimeout("tcp", srv.egress, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if err = socksConnect(c, target, srv.username, srv.password); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}
func (srv *server) acceptPath(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	f, err := bond.ReadFrame(c)
	if err != nil || f.Type != 'H' {
		return
	}
	var j join
	if json.Unmarshal(f.Payload, &j) != nil || checkJoin(srv.secret, j) != nil {
		return
	}
	s, created, err := srv.getOrCreate(j)
	if err != nil {
		return
	}
	l := &link{conn: c, index: j.Path}
	if err := s.attach(l); err != nil {
		return
	}
	if err := l.send(bond.Frame{Type: 'R', Payload: []byte("ok")}); err != nil {
		s.close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if created {
		go s.pump()
	}
	s.receiveLoop(l)
}
func runServer(addr string, srv *server) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("experimental multipath server listening on %s", ln.Addr())
	for {
		c, e := ln.Accept()
		if e != nil {
			return e
		}
		go srv.acceptPath(c)
	}
}
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listener must bind an explicit loopback IP")
	}
	return nil
}
func readSocksRequest(c net.Conn) (string, error) {
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 5 || hdr[1] < 1 || hdr[1] > 32 {
		return "", errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	allowed := false
	for _, x := range methods {
		if x == 0 {
			allowed = true
		}
	}
	if !allowed {
		_, _ = c.Write([]byte{5, 255})
		return "", errors.New("SOCKS no-auth method required")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var r [4]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return "", err
	}
	if r[0] != 5 || r[1] != 1 || r[2] != 0 {
		return "", errors.New("only SOCKS CONNECT is supported")
	}
	var host string
	switch r[3] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case 3:
		var b [1]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return "", errors.New("empty domain")
		}
		s := make([]byte, int(b[0]))
		if _, err := io.ReadFull(c, s); err != nil {
			return "", err
		}
		host = string(s)
	default:
		return "", errors.New("invalid SOCKS address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", err
	}
	_ = c.SetDeadline(time.Time{})
	return net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1]))), nil
}
func socksReply(c net.Conn, success bool) {
	result := byte(5)
	if success {
		result = 0
	}
	_, _ = c.Write([]byte{5, result, 0, 1, 127, 0, 0, 1, 0, 0})
}
func socksConnect(c net.Conn, target, username string, password []byte) error {
	if username == "" || len(username) > 255 || len(password) == 0 || len(password) > 255 {
		return errors.New("invalid Dante credentials")
	}
	_ = c.SetDeadline(time.Now().Add(12 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp != [2]byte{5, 2} {
		return errors.New("Dante refused username/password auth")
	}
	auth := []byte{1, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := c.Write(auth); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp != [2]byte{1, 0} {
		return errors.New("Dante authentication failed")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	request := []byte{5, 1, 0}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		request = append(request, 1)
		request = append(request, ip4...)
	} else if ip != nil {
		request = append(request, 4)
		request = append(request, ip.To16()...)
	} else {
		if len(host) > 255 {
			return errors.New("long domain")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	p, _ := strconv.Atoi(port)
	request = append(request, byte(p>>8), byte(p))
	if _, err := c.Write(request); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 0 {
		return errors.New("Dante CONNECT refused")
	}
	n := 0
	switch header[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var a [1]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return err
		}
		n = int(a[0])
	default:
		return errors.New("invalid Dante reply")
	}
	_, err = io.CopyN(io.Discard, c, int64(n+2))
	return err
}
func runClient(listen string, paths []string, secret []byte) error {
	if err := requireLoopback(listen); err != nil {
		return err
	}
	if len(paths) < 2 || len(paths) > 7 {
		return errors.New("Multi P0 requires 2..7 path listeners")
	}
	for _, p := range paths {
		if err := requireLoopback(p); err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("experimental multi SOCKS5 on %s; paths=%d", ln.Addr(), len(paths))
	for {
		c, e := ln.Accept()
		if e != nil {
			return e
		}
		go func() {
			defer c.Close()
			if err := serveClient(c, paths, secret); err != nil {
				log.Printf("client session closed: %v", err)
			}
		}()
	}
}
func serveClient(c net.Conn, paths []string, secret []byte) error {
	target, err := readSocksRequest(c)
	if err != nil {
		return err
	}
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		return err
	}
	id := hex.EncodeToString(raw)
	s := newSession(id, target, nil)
	s.dest = c
	s.initReceiver()
	close(s.ready)
	for i, p := range paths {
		conn, e := net.DialTimeout("tcp", p, 12*time.Second)
		if e != nil {
			continue
		}
		j := makeJoin(secret, id, target, i)
		body, _ := json.Marshal(j)
		if e = bond.WriteFrame(conn, bond.Frame{Type: 'H', Payload: body}); e != nil {
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, e := bond.ReadFrame(conn)
		if e != nil || f.Type != 'R' || string(f.Payload) != "ok" {
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})
		l := &link{conn: conn, index: i}
		if e = s.attach(l); e != nil {
			_ = conn.Close()
			continue
		}
		go s.receiveLoop(l)
	}
	s.mu.RLock()
	n := len(s.links)
	s.mu.RUnlock()
	if n == 0 {
		s.close()
		socksReply(c, false)
		return errors.New("no usable DNS paths")
	}
	socksReply(c, true)
	// The same application stream is striped in both directions across all
	// active links. P0 deliberately closes on link failure (no data-level ACK).
	go s.pump()
	<-s.done
	return nil
}
func main() {
	mode := flag.String("mode", "", "client or server")
	listen := flag.String("listen", "", "client: 127.0.0.1:2080; server: 127.0.0.1:2090")
	pathsArg := flag.String("paths", "", "comma-separated local raw TCP engine listeners (client)")
	secretFile := flag.String("secret-file", "", "0600 shared >=32-character secret file")
	egress := flag.String("egress-socks", "127.0.0.1:1080", "shared Dante SOCKS5 (server)")
	egressUser := flag.String("egress-user", "", "Dante username (server)")
	egressPass := flag.String("egress-pass-file", "", "0600 Dante password file (server)")
	direct := flag.Bool("test-direct-egress", false, "TEST ONLY bypass Dante")
	flag.Parse()
	secret, err := readSecret(*secretFile)
	if err != nil {
		log.Fatal(err)
	}
	switch *mode {
	case "server":
		addr := *listen
		if addr == "" {
			addr = "127.0.0.1:2090"
		}
		srv := &server{secret: secret, egress: *egress, username: *egressUser, direct: *direct, sessions: make(map[string]*session)}
		if !srv.direct {
			srv.password, err = readPassword(*egressPass)
			if err != nil {
				log.Fatal("Dante password: ", err)
			}
		}
		err = runServer(addr, srv)
	case "client":
		addr := *listen
		if addr == "" {
			addr = "127.0.0.1:2080"
		}
		parts := strings.Split(*pathsArg, ",")
		err = runClient(addr, parts, secret)
	default:
		err = errors.New("select --mode client or --mode server")
	}
	if err != nil {
		log.Fatal(err)
	}
}
