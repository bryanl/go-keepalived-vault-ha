package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"
)

var (
	version = "dev"
)

func main() {
	c := Configuration{}
	flag.BoolVar(&c.Debug, "debug", false, "Enable debug mode")
	flag.DurationVar(&c.Timeout, "timeout", 10*time.Second, "Time to wait for a response in seconds")
	flag.StringVar(&c.URL, "url", "", "Vault server URL")
	flag.StringVar(&c.CertFile, "cert", "", "Path to Vault server TLS certificate (optional)")
	flag.StringVar(&c.KeyFile, "key", "", "Path to Vault server private key (optional)")
	flag.StringVar(&c.CaCert, "ca-cert", "", "Path to Vault server CA certificate (optional)")
	flag.BoolVar(&c.Insecure, "insecure", false, "Skip TLS checks")

	flag.Parse()

	if c.Version {
		fmt.Println(version)
		os.Exit(1)
	}

	checker := NewChecker(c)

	if err := checker.Check(); err != nil {
		if c.Debug {
			log.Println(err)
		}
		os.Exit(1)
	}
}

// Configuration is configuration for the application.
type Configuration struct {
	// Debug enables debug mode.
	Debug bool
	// Timeout is how long to wait for a response.
	Timeout time.Duration
	// URL is URL for the server.
	URL string
	// Version sets if the version is displayed.
	Version bool
	// CertFile is a path to a TLS certificate.
	CertFile string
	// KeyFile is a path to a TLS private key.
	KeyFile string
	// CaCert is a path to CA certificate.
	CaCert string
	// Insecure skips TLS checks.
	Insecure bool
}

// Checker checks if a vault instance is leader.
type Checker struct {
	config Configuration
}

// NewChecker creates an instance of Checker.
func NewChecker(config Configuration) *Checker {
	return &Checker{config: config}
}

// Check checks an instance.
func (c *Checker) Check() error {
	u, err := url.Parse(c.config.URL)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}

	u.Path = path.Join("v1", "sys/leader")

	c.log("URL: %s", u.String())

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create HTTP request: %w", err)
	}

	client, err := c.createClient()
	if err != nil {
		return fmt.Errorf("create HTTP client: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("perform HTTP request: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	r := &leaderResponse{}
	if err := json.NewDecoder(resp.Body).Decode(r); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	c.log("ha_enabled: %t", r.HAEnabled)
	c.log("is_self: %t", r.IsSelf)

	if r.HAEnabled && r.IsSelf {
		return nil
	}

	return fmt.Errorf("not leader")
}

func (c *Checker) createClient() (*http.Client, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if caCert := c.config.CaCert; caCert != "" {
		certs, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}

		rootCAs.AppendCertsFromPEM(certs)
	}

	certificates, err := c.loadCertificates()
	if err != nil {
		return nil, fmt.Errorf("load certificates: %w", err)
	}

	config := &tls.Config{
		InsecureSkipVerify: c.config.Insecure,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}
	transport := &http.Transport{TLSClientConfig: config}

	client := &http.Client{
		Transport: transport,
		Timeout:   c.config.Timeout,
	}

	return client, nil
}

func (c *Checker) loadCertificates() ([]tls.Certificate, error) {
	if c.config.CertFile == "" && c.config.KeyFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(c.config.CertFile, c.config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	return []tls.Certificate{cert}, nil
}

func (c *Checker) log(format string, args ...any) {
	if c.config.Debug {
		log.Printf(format, args...)
	}
}

type leaderResponse struct {
	HAEnabled bool `json:"ha_enabled"`
	IsSelf    bool `json:"is_self"`
}
