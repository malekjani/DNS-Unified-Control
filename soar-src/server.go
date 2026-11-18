// DNS Unified Control Soar fixed-backend server. Upstream protocol: getlantern/soar.
// Unlike upstream's public-destination CLI, THIS endpoint ONLY dials Dante.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/getlantern/soar"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const onlyBackend = "127.0.0.1:1080"

func fatal(err error) { fmt.Fprintln(os.Stderr, "duc-soar-server:", err); os.Exit(1) }
func main() {
	if len(os.Args) == 2 && os.Args[1] == "keygen" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fatal(err)
		}
		fmt.Println("private", base64.StdEncoding.EncodeToString(priv.Seed()))
		fmt.Println("public", base64.StdEncoding.EncodeToString(pub))
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "pubkey" {
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fatal(err)
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(seed) != ed25519.SeedSize {
			fatal(errors.New("invalid Ed25519 private seed"))
		}
		fmt.Println(base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)))
		return
	}
	zone := flag.String("zone", "", "delegated Soar domain")
	keyfile := flag.String("key-file", "", "private Ed25519 seed")
	listen := flag.String("listen", ":53", "UDP listener")
	backend := flag.String("backend", onlyBackend, "ONLY authenticated Dante loopback backend")
	flag.Parse()
	if *zone == "" || *keyfile == "" {
		fatal(errors.New("missing zone or key file"))
	}
	// No -allow-private, no public destination mode and no customizable backend here.
	if *backend != onlyBackend {
		fatal(errors.New("only shared authenticated Dante at " + onlyBackend + " is permitted"))
	}
	raw, err := os.ReadFile(*keyfile)
	if err != nil {
		fatal(err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fatal(errors.New("invalid private seed"))
	}
	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		fatal(err)
	}
	defer pc.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	fixedDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != onlyBackend {
			return nil, errors.New("destination denied; only authenticated Dante allowed")
		}
		return dialer.DialContext(ctx, "tcp", onlyBackend)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info("Soar restricted service", "listen", pc.LocalAddr(), "backend", "loopback Dante only")
	if err := soar.Serve(ctx, pc, soar.ServerConfig{Zone: *zone, PrivateKey: ed25519.NewKeyFromSeed(seed), Dial: fixedDial,
		MaxSessions: 256, MaxTotalStreams: 1024, MaxStreams: 32, Logger: log}); err != nil {
		fatal(err)
	}
}
