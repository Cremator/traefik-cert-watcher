package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/zeebo/blake3"
)

var (
	traefikFile = flag.String("traefik-file", "/traefik/acme.json", "Traefik acme.json")
	certDir     = flag.String("cert-dir", "/certs", "Certificate output dir")
	dockerLabel = flag.String("docker-label", "traefik.acme.cert", "Container domain label")
	stateFile   = flag.String("state-file", "/certs/app_state.json", "State file")
)

/* ==================== CERT STORE ==================== */

type CertInfo struct {
	Domain     string    `json:"domain"`
	Sans       []string  `json:"sans,omitempty"`
	IsWildcard bool      `json:"is_wildcard"`
	NotAfter   time.Time `json:"not_after"`
	CertHash   string    `json:"cert_hash"`
	KeyHash    string    `json:"key_hash"`
	Provider   string    `json:"provider"`
}

type CertStore struct {
	Certs map[string]CertInfo `json:"certs"`
	Path  string              `json:"-"`
	mu    sync.Mutex
}

func NewCertStore(path string) *CertStore {
	return &CertStore{
		Certs: make(map[string]CertInfo),
		Path:  path,
	}
}

func (cs *CertStore) Load() {
	b, err := os.ReadFile(cs.Path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info().Msg("state file not found, starting fresh")
			return
		}
		log.Warn().Err(err).Msg("failed to read state file")
		return
	}
	if err := json.Unmarshal(b, cs); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal state file")
	}
}

func (cs *CertStore) Save() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	b, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("state marshal failed")
		return
	}
	if err := os.WriteFile(cs.Path, b, 0644); err != nil {
		log.Error().Err(err).Msg("state write failed")
	}
}

func (cs *CertStore) Update(key string, sans []string, cert *x509.Certificate, certPEM, keyPEM []byte) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	certHash := fmt.Sprintf("%x", blake3.Sum256(certPEM))
	keyHash := fmt.Sprintf("%x", blake3.Sum256(keyPEM))

	if old, ok := cs.Certs[key]; ok &&
		old.CertHash == certHash &&
		old.KeyHash == keyHash {
		return false
	}

	provider, domain := splitProviderKey(key)

	isWC := strings.HasPrefix(domain, "*.")
	if !isWC && len(sans) > 0 {
		for _, s := range sans {
			if strings.HasPrefix(s, "*.") {
				isWC = true
			}
		}
	}

	cs.Certs[key] = CertInfo{
		Domain:     domain,
		Sans:       sans,
		IsWildcard: isWC,
		NotAfter:   cert.NotAfter,
		CertHash:   certHash,
		KeyHash:    keyHash,
		Provider:   provider,
	}

	log.Info().
		Str("provider", provider).
		Str("domain", domain).
		Time("expires", cert.NotAfter).
		Bool("wildcard", isWC).
		Msg("certificate updated")

	return true
}

/* ==================== CONTAINER MONITOR ==================== */

type ContainerInfo struct {
	ID        string
	Domains   []string
	StartTime time.Time
}

type ContainerMonitor struct {
	Docker     *client.Client
	Label      string
	Containers map[string]ContainerInfo
	RestartQ   map[string]struct{}
	mu         sync.Mutex
}

func NewContainerMonitor(cli *client.Client, label string) *ContainerMonitor {
	return &ContainerMonitor{
		Docker:     cli,
		Label:      label,
		Containers: make(map[string]ContainerInfo),
		RestartQ:   make(map[string]struct{}),
	}
}

func (cm *ContainerMonitor) Scan(ctx context.Context) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.Containers = make(map[string]ContainerInfo)

	f := filters.NewArgs()
	f.Add("status", "running")
	f.Add("label", cm.Label)

	list, err := cm.Docker.ContainerList(ctx, container.ListOptions{Filters: f})
	if err != nil {
		log.Error().Err(err).Msg("container list failed")
		return
	}

	for _, c := range list {
		info, err := cm.Docker.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}

		start, err := time.Parse(time.RFC3339Nano, info.State.StartedAt)
		if err != nil {
			continue
		}

		domains := splitDomains(c.Labels[cm.Label])
		if len(domains) == 0 {
			continue
		}

		cm.Containers[c.ID] = ContainerInfo{
			ID:        c.ID,
			Domains:   domains,
			StartTime: start,
		}

		log.Info().
			Str("container", c.ID).
			Strs("domains", domains).
			Msg("tracking container")
	}
}

func (cm *ContainerMonitor) QueueRestart(id string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.RestartQ[id]; !ok {
		log.Warn().Str("container", id).Msg("queued for restart")
	}
	cm.RestartQ[id] = struct{}{}
}

func (cm *ContainerMonitor) ProcessQueue(ctx context.Context) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for id := range cm.RestartQ {
		log.Warn().Str("container", id).Msg("restarting container")
		if err := cm.Docker.ContainerRestart(ctx, id, container.StopOptions{}); err != nil {
			log.Error().Err(err).Str("container", id).Msg("restart failed")
		}
		delete(cm.RestartQ, id)
	}
}

/* ==================== DOCKER EVENTS ==================== */

func watchDockerEvents(ctx context.Context, cm *ContainerMonitor) {
	f := filters.NewArgs()
	f.Add("type", "container")
	f.Add("label", cm.Label)
	f.Add("event", "start")
	f.Add("event", "die")
	f.Add("event", "destroy")

	eventsCh, errCh := cm.Docker.Events(ctx, events.ListOptions{Filters: f})

	log.Info().
		Str("label", cm.Label).
		Msg("watching docker events for labeled containers")

	for {
		select {
		case e := <-eventsCh:
			if e.Type != events.ContainerEventType {
				continue
			}

			log.Debug().
				Str("action", string(e.Action)).
				Str("container", e.Actor.ID).
				Msg("docker event")

			// Any lifecycle change → rescan tracked containers
			cm.Scan(ctx)

		case err := <-errCh:
			if err != nil {
				log.Error().Err(err).Msg("docker event stream error")
				return
			}

		case <-ctx.Done():
			log.Info().Msg("docker event watcher stopped")
			return
		}
	}
}

/* ==================== ACME ==================== */

type TraefikACME map[string]struct {
	Certificates []struct {
		Domain struct {
			Main string   `json:"main"`
			SANs []string `json:"sans"`
		} `json:"domain"`
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
	} `json:"Certificates"`
}

func processACME(cs *CertStore, cm *ContainerMonitor) {
	raw, err := os.ReadFile(*traefikFile)
	if err != nil {
		log.Error().Err(err).Msg("acme read failed")
		return
	}

	var acme TraefikACME
	if err := json.Unmarshal(raw, &acme); err != nil {
		log.Error().Err(err).Msg("acme parse failed")
		return
	}

	for provider, p := range acme {
		for _, c := range p.Certificates {
			certPEM, err := base64.StdEncoding.DecodeString(c.Certificate)
			if err != nil {
				continue
			}
			keyPEM, err := base64.StdEncoding.DecodeString(c.Key)
			if err != nil {
				continue
			}

			var parsed []*x509.Certificate

			rest := certPEM
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" {
					continue
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					log.Warn().Err(err).Msg("failed to parse certificate block")
					continue
				}
				parsed = append(parsed, cert)
			}

			if len(parsed) == 0 {
				log.Warn().
					Str("provider", provider).
					Str("domain", c.Domain.Main).
					Msg("no valid certificates parsed")
				continue
			}

			var leaf *x509.Certificate
			for _, x := range parsed {
				if !x.IsCA {
					leaf = x
					break
				}
			}
			if leaf == nil {
				continue
			}

			domain := c.Domain.Main
			sans := c.Domain.SANs
			storeKey := provider + ":" + domain

			if cs.Update(storeKey, sans, leaf, certPEM, keyPEM) {
				writeCertFiles(provider, domain, certPEM, keyPEM)

				for _, d := range append([]string{domain}, sans...) {
					checkContainers(d, leaf.NotAfter, cm)
				}
			}
		}
	}
}

/* ==================== FILE EXPORT ==================== */

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}

	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func writeCertFiles(provider, domain string, certPEM, keyPEM []byte) {
	dir := filepath.Join(*certDir, provider, strings.ReplaceAll(domain, "*", "_"))
	_ = os.MkdirAll(dir, 0755)

	_ = atomicWriteFile(filepath.Join(dir, "fullchain.pem"), certPEM, 0644)
	_ = atomicWriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0600)
}

/* ==================== MATCHING ==================== */

func domainMatches(certDomain, containerDomain string) bool {
	if after, ok := strings.CutPrefix(certDomain, "*."); ok {
		base := after
		return strings.HasSuffix(containerDomain, "."+base) &&
			strings.Count(containerDomain, ".") == strings.Count(base, ".")+1
	}
	return certDomain == containerDomain
}

func checkContainers(domain string, certTime time.Time, cm *ContainerMonitor) {
	for id, c := range cm.Containers {
		for _, d := range c.Domains {
			if domainMatches(domain, d) && certTime.After(c.StartTime) {
				cm.QueueRestart(id)
			}
		}
	}
}

/* ==================== FSNOTIFY ==================== */

func watchACME(ctx context.Context, cs *CertStore, cm *ContainerMonitor) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal().Err(err).Msg("fsnotify init failed")
	}
	defer watcher.Close()

	dir := filepath.Dir(*traefikFile)
	if err := watcher.Add(dir); err != nil {
		log.Fatal().Err(err).Str("dir", dir).Msg("failed to watch acme.json directory")
	}

	var debounceMu sync.Mutex
	var debounceTimer *time.Timer

	resetDebounce := func() {
		debounceMu.Lock()
		defer debounceMu.Unlock()
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.AfterFunc(time.Minute, func() {
			cm.Scan(ctx)
			processACME(cs, cm)
			cs.Save()
			cm.ProcessQueue(ctx)
		})
	}

	for {
		select {
		case ev := <-watcher.Events:
			if filepath.Base(ev.Name) == filepath.Base(*traefikFile) &&
				ev.Op&(fsnotify.Write|fsnotify.Rename) != 0 {
				resetDebounce()
			}

		case <-ctx.Done():
			// stop any running timer
			debounceMu.Lock()
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceMu.Unlock()
			return
		}
	}
}

/* ==================== UTIL ==================== */

func splitDomains(s string) []string {
	var out []string
	for d := range strings.SplitSeq(s, ",") {
		if v := strings.TrimSpace(d); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func splitProviderKey(s string) (string, string) {
	p := strings.SplitN(s, ":", 2)
	return p[0], p[1]
}

/* ==================== MAIN ==================== */

func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})

	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Warn().Msg("shutdown signal received")
		cancel()
	}()

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal().Err(err).Msg("docker client init failed")
	}

	cs := NewCertStore(*stateFile)
	cs.Load()

	cm := NewContainerMonitor(cli, *dockerLabel)
	cm.Scan(ctx)
	processACME(cs, cm)
	cs.Save()
	cm.ProcessQueue(ctx)

	go watchDockerEvents(ctx, cm)
	go watchACME(ctx, cs, cm)

	<-ctx.Done()
	log.Info().Msg("exiting cleanly")
}
