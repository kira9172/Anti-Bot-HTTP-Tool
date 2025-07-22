package main

import (
	"context"
	
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"gopkg.in/yaml.v3"
)

// --- Configuration Structs ---

type Config struct {
	Targets  []string `yaml:"targets"`
	Proxies  []string `yaml:"proxies"`
	Settings Settings `yaml:"settings"`
}

type Settings struct {
	RequestCount int    `yaml:"request_count"`
	MaxRetries   int    `yaml:"max_retries"`
	TlsProfile   string `yaml:"tls_profile"`
	Delay        Delay  `yaml:"delay_ms"`
}

type Delay struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

// --- Proxy Manager ---

type ProxyManager struct {
	proxies []*url.URL
	index   int
	mutex   sync.Mutex
}

// NewProxyManager creates and initializes a proxy manager.
func NewProxyManager(proxyStrings []string) (*ProxyManager, error) {
	if len(proxyStrings) == 0 {
		return nil, fmt.Errorf("proxy list cannot be empty")
	}

	proxies := make([]*url.URL, 0, len(proxyStrings))
	for _, pStr := range proxyStrings {
		parsedURL, err := url.Parse(fmt.Sprintf("http://%s", pStr))
		if err != nil {
			log.Printf("Warning: Skipping invalid proxy '%s': %v", pStr, err)
			continue
		}
		proxies = append(proxies, parsedURL)
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("no valid proxies found in the list")
	}

	return &ProxyManager{proxies: proxies}, nil
}

// GetNextProxy rotates proxies in a round-robin fashion.
func (pm *ProxyManager) GetNextProxy() *url.URL {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	proxy := pm.proxies[pm.index]
	pm.index = (pm.index + 1) % len(pm.proxies)
	return proxy
}

// --- TLS Profile & Header Definitions ---

var (
	// Map human-readable names to uTLS ClientHelloID
	browserProfiles = map[string]utls.ClientHelloID{
		"chrome":  utls.HelloChrome_120,
		"firefox": utls.HelloFirefox_120,
		"safari":  utls.HelloSafari_16_0,
	}

	// Map ClientHelloID to a consistent set of browser headers
	browserHeaders = map[utls.ClientHelloID]http.Header{
		utls.HelloChrome_120: {
			"sec-ch-ua":                 {`"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`},
			"sec-ch-ua-mobile":          {`?0`},
			"sec-ch-ua-platform":        {`"Windows"`},
			"upgrade-insecure-requests": {`1`},
			"user-agent":                {`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`},
			"accept":                    {`text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`},
			"sec-fetch-site":            {`none`},
			"sec-fetch-mode":            {`Maps`},
			"sec-fetch-user":            {`?1`},
			"sec-fetch-dest":            {`document`},
			"accept-encoding":           {`gzip, deflate, br`},
			"accept-language":           {`en-US,en;q=0.9`},
		},
		utls.HelloFirefox_120: {
			"user-agent":                {`Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0`},
			"accept":                    {`text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8`},
			"accept-language":           {`en-US,en;q=0.5`},
			"accept-encoding":           {`gzip, deflate, br`},
			"upgrade-insecure-requests": {`1`},
			"sec-fetch-dest":            {`document`},
			"sec-fetch-mode":            {`Maps`},
			"sec-fetch-site":            {`none`},
			"sec-fetch-user":            {`?1`},
		},
		utls.HelloSafari_16_0: {
			"user-agent":      {`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15`},
			"accept":          {`text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`},
			"accept-language": {`en-US,en;q=0.9`},
			"accept-encoding": {`gzip, deflate, br`},
			"sec-fetch-dest":  {`document`},
			"sec-fetch-mode":  {`Maps`},
			"sec-fetch-site":  {`none`},
			"sec-fetch-user":  {`?1`},
		},
	}
)

// selectClientProfile randomly selects a profile if "random" is specified.
func selectClientProfile(profileName string) (utls.ClientHelloID, http.Header) {
	profileName = strings.ToLower(profileName)

	if profileName == "random" {
		keys := make([]utls.ClientHelloID, 0, len(browserHeaders))
		for k := range browserHeaders {
			keys = append(keys, k)
		}
		selectedKey := keys[rand.Intn(len(keys))]
		return selectedKey, browserHeaders[selectedKey]
	}

	if profile, ok := browserProfiles[profileName]; ok {
		return profile, browserHeaders[profile]
	}

	log.Printf("Warning: Unknown profile '%s', defaulting to random.", profileName)
	return selectClientProfile("random")
}

// --- Core Logic ---

func main() {
	// Step 1: Load Configuration from YAML
	configFile, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("Error reading config.yaml: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Error parsing config.yaml: %v", err)
	}

	// Step 2: Initialize Proxy Manager
	proxyManager, err := NewProxyManager(config.Proxies)
	if err != nil {
		log.Fatalf("Failed to initialize proxy manager: %v", err)
	}
	log.Printf("Successfully loaded %d proxies.", len(proxyManager.proxies))

	// Step 3: Main Request Loop
	jar, _ := cookiejar.New(nil)
	successCount := 0

	for successCount < config.Settings.RequestCount {
		targetURL := config.Targets[rand.Intn(len(config.Targets))]
		var resp *http.Response
		var ja3 string
		var finalProxy string

		// Step 4: Retry Logic Loop
		for i := 0; i < config.Settings.MaxRetries; i++ {
			proxyURL := proxyManager.GetNextProxy()
			finalProxy = proxyURL.Host // For logging

			// Select a new TLS fingerprint and header set for each attempt
			clientProfile, headers := selectClientProfile(config.Settings.TlsProfile)

			// Create a uTLS-powered HTTP client
			client := &http.Client{
				Jar: jar, // Manage cookies and redirects across session
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
					// Inside the http.Transport struct
					DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
    					dialer := &net.Dialer{Timeout: 30 * time.Second}
    					tcpConn, err := dialer.DialContext(ctx, network, addr)
    					if err != nil {
        					return nil, err
    					}

    					config := &utls.Config{ServerName: strings.Split(addr, ":")[0]}
    					uTLSConn := utls.UClient(tcpConn, config, clientProfile)

    					if err := uTLSConn.HandshakeContext(ctx); err != nil {
        					return nil, fmt.Errorf("uTLS handshake failed: %w", err)
    					}

    					var ja3Err error
    					ja3, ja3Err = uTLSConn.JA3()
    					if ja3Err != nil {
        					// The handshake succeeded, but we couldn't get the JA3.
        					// Log it as a warning but don't fail the whole request.
        					log.Printf("Warning: Could not get JA3 hash: %v", ja3Err)
    					}

    					return uTLSConn, nil
					},
					// Add a timeout for the entire request including response
					ResponseHeaderTimeout: 30 * time.Second,
				},
				// Stop client from following redirects automatically so we can log them
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// Create and send the request
			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header = headers

			resp, err = client.Do(req)
			if err != nil {
				log.Printf("[ATTEMPT %d/%d] FAILED (Proxy: %s): Request error: %v", i+1, config.Settings.MaxRetries, finalProxy, err)
				time.Sleep(1 * time.Second) // Wait a bit before retrying
				continue
			}

			// Step 5: Analyze Response
			status := analyzeResponse(resp)
			log.Printf("[ATTEMPT %d/%d] STATUS: %s | URL: %s | PROXY: %s | JA3: %s", i+1, config.Settings.MaxRetries, status, targetURL, finalProxy, ja3)

			if status == "SUCCESS" {
				break // Exit retry loop on success
			}

			// Handle redirects manually
			// Handle redirects manually
			if status == "REDIRECT" {
    			locationHeader := resp.Header.Get("Location")
    			if locationHeader == "" {
        			log.Printf("[ATTEMPT %d/%d] FAILED: Redirect status but no Location header.", i+1, config.Settings.MaxRetries)
        			resp.Body.Close()
        			continue // Treat as a failed attempt
    			}

    			redirectURL, err := resp.Request.URL.Parse(locationHeader)
    			if err != nil {
        			log.Printf("[ATTEMPT %d/%d] FAILED: Could not parse redirect URL '%s'", i+1, config.Settings.MaxRetries, locationHeader)
        			resp.Body.Close()
        			continue // Treat as a failed attempt
    			}
    
    			// This correctly resolves the redirect URL
    			targetURL = redirectURL.String()

    			log.Printf("--> Redirecting to: %s", targetURL)
    			i = -1 // Reset retry counter for the new URL
    			resp.Body.Close()
    			continue
			}

			// If blocked or failed, the loop will continue to the next retry
			resp.Body.Close()
		}

		// Check final status after retries
		if resp != nil {
			finalStatus := analyzeResponse(resp)
			if finalStatus == "SUCCESS" {
				successCount++
				log.Printf("--- SUCCESS (%d/%d) ---", successCount, config.Settings.RequestCount)
				// You can process the successful response body here if needed
				// body, _ := io.ReadAll(resp.Body)
				// fmt.Println(string(body[:100])) // Print first 100 chars

			} else {
				log.Printf("--- FAILED after %d retries ---", config.Settings.MaxRetries)
			}
			resp.Body.Close()
		}

		// Step 6: Randomized Delay
		if successCount < config.Settings.RequestCount {
			delay := rand.Intn(config.Settings.Delay.Max-config.Settings.Delay.Min+1) + config.Settings.Delay.Min
			log.Printf("Waiting for %dms...", delay)
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}

	log.Printf("Completed %d successful requests. Exiting.", config.Settings.RequestCount)
}

// analyzeResponse categorizes the HTTP response.
func analyzeResponse(resp *http.Response) string {
	// Redirects
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return "REDIRECT"
	}

	// Blocked/Challenged
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		return "BLOCKED"
	}

	// Check body for common challenge keywords
	bodyBytes, err := io.ReadAll(resp.Body)
	if err == nil {
		bodyString := string(bodyBytes)
		// Restore body for further processing
		resp.Body = io.NopCloser(strings.NewReader(bodyString))

		challengeWords := []string{"captcha", "challenge", "verify you are human", "are you a robot"}
		for _, word := range challengeWords {
			if strings.Contains(strings.ToLower(bodyString), word) {
				return "BLOCKED"
			}
		}
	}

	// Success
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return "SUCCESS"
	}

	return fmt.Sprintf("FAILED_HTTP_%d", resp.StatusCode)
}
