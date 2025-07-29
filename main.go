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
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
	
)

// --- Configuration Structs ---

// Config holds all configuration from the yaml file.
type Config struct {
	Targets  []string `yaml:"targets"`
	Proxies  []string `yaml:"proxies"`
	Settings Settings `yaml:"settings"`
}

// Settings define the operational parameters for requests.
type Settings struct {
	RequestCount  int               `yaml:"request_count"`
	MaxRetries    int               `yaml:"max_retries"`
	TlsProfile    string            `yaml:"tls_profile"`
	UseCookies    bool              `yaml:"use_cookies"`
	CustomHeaders map[string]string `yaml:"custom_headers"`
	Delay         Delay             `yaml:"delay_ms"`
}

// Delay specifies the min/max wait time between requests.
type Delay struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

// --- Proxy Manager ---

// ProxyInfo stores details for a single proxy.
type ProxyInfo struct {
	URL    *url.URL
	Scheme string
}

// ProxyManager handles thread-safe, round-robin proxy rotation.
type ProxyManager struct {
	proxies []ProxyInfo
	index   int
	mutex   sync.Mutex
}

// NewProxyManager creates and initializes a proxy manager, parsing and validating proxy strings.
func NewProxyManager(proxyStrings []string) (*ProxyManager, error) {
	if len(proxyStrings) == 0 {
		return nil, fmt.Errorf("proxy list cannot be empty")
	}

	proxies := make([]ProxyInfo, 0, len(proxyStrings))
	for _, pStr := range proxyStrings {
		// Default to http scheme if not specified for backward compatibility
		if !strings.Contains(pStr, "://") {
			pStr = "http://" + pStr
		}
		parsedURL, err := url.Parse(pStr)
		if err != nil {
			log.Printf("Warning: Skipping invalid proxy URL '%s': %v", pStr, err)
			continue
		}
		proxies = append(proxies, ProxyInfo{URL: parsedURL, Scheme: parsedURL.Scheme})
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("no valid proxies found in the list")
	}

	return &ProxyManager{proxies: proxies}, nil
}

// GetNextProxy safely rotates to the next proxy.
func (pm *ProxyManager) GetNextProxy() ProxyInfo {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	proxy := pm.proxies[pm.index]
	pm.index = (pm.index + 1) % len(pm.proxies)
	return proxy
}

// --- TLS Profile & Header Definitions ---

var (
	// browserProfiles maps readable names to uTLS ClientHelloIDs.
	browserProfiles = map[string]utls.ClientHelloID{
		"chrome":  utls.HelloChrome_120,
		"firefox": utls.HelloFirefox_120,
		"safari":  utls.HelloSafari_16_0,
	}
	// browserHeaders maps ClientHelloIDs to consistent browser headers.
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
		},
	}
)

// selectClientProfile chooses a TLS fingerprint and matching headers, randomizing if requested.
func selectClientProfile(profileName string) (utls.ClientHelloID, http.Header) {
	profileName = strings.ToLower(profileName)
	if profileName == "random" {
		keys := make([]utls.ClientHelloID, 0, len(browserHeaders))
		for k := range browserHeaders {
			keys = append(keys, k)
		}
		selectedKey := keys[rand.Intn(len(keys))]
		return selectedKey, browserHeaders[selectedKey].Clone() // Clone to prevent race conditions
	}
	if profile, ok := browserProfiles[profileName]; ok {
		return profile, browserHeaders[profile].Clone()
	}
	log.Printf("Warning: Unknown profile '%s', defaulting to random.", profileName)
	return selectClientProfile("random")
}



// --- Core Logic ---

func main() {
	// 1. Load Configuration
	configFile, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("Error reading config.yaml: %v", err)
	}
	var config Config
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Error parsing config.yaml: %v", err)
	}

	// 2. Initialize Proxy Manager
	proxyManager, err := NewProxyManager(config.Proxies)
	if err != nil {
		log.Fatalf("Failed to initialize proxy manager: %v", err)
	}
	log.Printf("Successfully loaded %d proxies.", len(proxyManager.proxies))

	// 3. Setup Session (Cookie Jar)
	var jar http.CookieJar
	if config.Settings.UseCookies {
		jar, _ = cookiejar.New(nil)
	}

	// 4. Main Request Loop
	successCount := 0
	for successCount < config.Settings.RequestCount {
		targetURL := config.Targets[rand.Intn(len(config.Targets))]
		var resp *http.Response
		var ja3, finalProxyHost string

		// 5. Retry Logic Loop
		for i := 0; i < config.Settings.MaxRetries; i++ {
			proxyInfo := proxyManager.GetNextProxy()
			finalProxyHost = proxyInfo.URL.Host

			// Select new identity for each attempt
			clientProfile, headers := selectClientProfile(config.Settings.TlsProfile)
			for key, val := range config.Settings.CustomHeaders {
				headers.Set(key, val)
			}

			// Create a uTLS-powered HTTP client with proxy support
			client := &http.Client{
				Jar: jar,
				Transport: &http.Transport{
					// This function dials the proxy and wraps the connection with uTLS
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						var dialer proxy.Dialer = &net.Dialer{Timeout: 30 * time.Second}
						var conn net.Conn
						var err error

						// Dial through the appropriate proxy type
						switch proxyInfo.Scheme {
						case "socks5":
							var auth *proxy.Auth
							if user := proxyInfo.URL.User; user != nil {
								password, _ := user.Password()
								auth = &proxy.Auth{User: user.Username(), Password: password}
							}
							dialer, err = proxy.SOCKS5("tcp", proxyInfo.URL.Host, auth, dialer)
							if err != nil {
								return nil, fmt.Errorf("failed to create socks5 dialer: %w", err)
							}
							conn, err = dialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
						default: // http/https
							conn, err = dialer.Dial(network, addr)
						}
						if err != nil {
							return nil, fmt.Errorf("proxy dial failed: %w", err)
						}

						// Wrap the connection with uTLS
						config := &utls.Config{ServerName: strings.Split(addr, ":")[0]}
						uTLSConn := utls.UClient(conn, config, clientProfile)
						
						if err := uTLSConn.HandshakeContext(ctx); err != nil {
							return nil, fmt.Errorf("uTLS handshake failed: %w", err)
						}

						// Log the JA3 hash but don't fail the request if it's unavailable
						ja3 = uTLSConn.HandshakeState.JA3
						return uTLSConn, nil
					},
					Proxy:                 http.ProxyURL(proxyInfo.URL), // Only used for http/https proxies
					ResponseHeaderTimeout: 30 * time.Second,
				},
				// Disable automatic redirects to handle them manually
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			// For SOCKS5, the transport's Proxy field must be nil
			if proxyInfo.Scheme == "socks5" {
				client.Transport.(*http.Transport).Proxy = nil
			}

			// Create and send the request
			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header = headers

			resp, err = client.Do(req)
			if err != nil {
				log.Printf("[ATTEMPT %d/%d] FAILED (Proxy: %s): Request error: %v", i+1, config.Settings.MaxRetries, finalProxyHost, err)
				time.Sleep(1 * time.Second)
				continue
			}

			// 6. Analyze Response
			status := analyzeResponse(resp)
			log.Printf("[ATTEMPT %d/%d] STATUS: %s | URL: %s | PROXY: %s | JA3: %s", i+1, config.Settings.MaxRetries, status, targetURL, finalProxyHost, ja3)

			if status == "SUCCESS" {
				break // Exit retry loop
			}

			// Handle redirects manually to maintain control
			if status == "REDIRECT" {
				locationHeader := resp.Header.Get("Location")
				if locationHeader == "" {
					log.Printf("[ATTEMPT %d/%d] FAILED: Redirect status but no Location header.", i+1, config.Settings.MaxRetries)
				} else if newURL, err := resp.Request.URL.Parse(locationHeader); err != nil {
					log.Printf("[ATTEMPT %d/%d] FAILED: Could not parse redirect URL '%s'", i+1, config.Settings.MaxRetries, locationHeader)
				} else {
					targetURL = newURL.String()
					log.Printf("--> Redirecting to: %s", targetURL)
					i = -1 // Reset retry counter for the new URL
				}
				resp.Body.Close()
				continue
			}

			// If blocked or failed, the loop will continue to the next retry
			resp.Body.Close()
		}

		// Check final status after all retries
		if resp != nil {
			if analyzeResponse(resp) == "SUCCESS" {
				successCount++
				log.Printf("--- SUCCESS (%d/%d) ---", successCount, config.Settings.RequestCount)
			} else {
				log.Printf("--- FAILED after %d retries ---", config.Settings.MaxRetries)
			}
			resp.Body.Close()
		}

		// 7. Randomized Delay
		if successCount < config.Settings.RequestCount {
			delay := rand.Intn(config.Settings.Delay.Max-config.Settings.Delay.Min+1) + config.Settings.Delay.Min
			log.Printf("Waiting for %dms...", delay)
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
	log.Printf("Completed %d successful requests. Exiting.", config.Settings.RequestCount)
}

// analyzeResponse categorizes the HTTP response status.
func analyzeResponse(resp *http.Response) string {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return "SUCCESS"
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return "REDIRECT"
	}
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		return "BLOCKED"
	}

	// Read body to check for challenge keywords without consuming it
	bodyBytes, err := io.ReadAll(resp.Body)
	if err == nil {
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes))) // Restore body
		bodyString := strings.ToLower(string(bodyBytes))
		challengeWords := []string{"captcha", "challenge", "verify you are human", "are you a robot"}
		for _, word := range challengeWords {
			if strings.Contains(bodyString, word) {
				return "BLOCKED"
			}
		}
	}
	return fmt.Sprintf("FAILED_HTTP_%d", resp.StatusCode)
}
