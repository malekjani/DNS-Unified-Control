// Native single-binary Soar client powered by official getlantern/soar Go library.
// This is the tunnel client itself (not a SOCKS gateway or secondary proxy).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/getlantern/soar"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	zone := flag.String("zone", "", "delegated Soar zone")
	pub := flag.String("pubkey", "", "server public key (base64)")
	resolver := flag.String("resolver", "1.1.1.1:53", "comma-separated recursive resolvers")
	listen := flag.String("listen", "127.0.0.1:2080", "local TCP endpoint")
	forward := flag.String("forward", "127.0.0.1:1080", "fixed remote Dante endpoint")
	flag.Parse()
	if *zone == "" || *pub == "" || *forward != "127.0.0.1:1080" {
		fail(errors.New("zone and pubkey required; forward must target shared Dante"))
	}
	key, err := base64.StdEncoding.DecodeString(*pub)
	if err != nil || len(key) != ed25519.PublicKeySize {
		fail(errors.New("invalid Soar public key"))
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		fail(err)
	}
	if host != "127.0.0.1" && host != "localhost" {
		fail(errors.New("listen must be local loopback"))
	}
	rs := strings.Split(*resolver, ",")
	for i := range rs {
		rs[i] = strings.TrimSpace(rs[i])
		if rs[i] == "" {
			fail(errors.New("empty resolver"))
		}
	}
	cl, err := soar.NewClient(soar.Config{Zone: *zone, ServerKey: ed25519.PublicKey(key), Resolvers: rs})
	if err != nil {
		fail(err)
	}
	defer cl.Close()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fail(err)
	}
	defer ln.Close()
	fmt.Fprintln(os.Stderr, "soar-client: listening", ln.Addr().String(), "(raw TCP to authenticated Dante)")
	for {
		local, err := ln.Accept()
		if err != nil {
			fail(err)
		}
		go func() {
			defer local.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
			defer cancel()
			tunneled, err := cl.DialContext(ctx, "tcp", *forward)
			if err != nil {
				fmt.Fprintln(os.Stderr, "soar-client dial:", err)
				return
			}
			defer tunneled.Close()
			done := make(chan struct{}, 1)
			go func() {
				io.Copy(tunneled, local)
				if cw, ok := tunneled.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
				done <- struct{}{}
			}()
			io.Copy(local, tunneled)
			if cw, ok := local.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
			<-done
		}()
	}
}
func fail(e error) { fmt.Fprintln(os.Stderr, "soar-client:", e); os.Exit(1) }
