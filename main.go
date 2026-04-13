package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	maxConcurrent = 10
	timeout       = 15 * time.Second
	retryDelay    = 3 * time.Second
)

var userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

var retryableErrors = []string{
	"EOF",
	"connection reset by peer",
	"connection refused",
	"context deadline exceeded",
}

type SiteEntry struct {
	URL     string
	SkipTLS bool
}

type Result struct {
	URL          string
	Status       int
	ResponseMs   int64
	CertExpiry   string
	Error        string
	Unverifiable bool
}

var httpClient = &http.Client{
	Timeout: timeout,
	Transport: &http.Transport{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		req.Header.Set("User-Agent", userAgent)
		return nil
	},
}

var httpClientInsecure = &http.Client{
	Timeout: timeout,
	Transport: &http.Transport{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		req.Header.Set("User-Agent", userAgent)
		return nil
	},
}

func isRetryable(errStr string) bool {
	for _, e := range retryableErrors {
		if strings.Contains(errStr, e) {
			return true
		}
	}
	return false
}

func doRequest(method, url string, skipTLS bool) (*http.Response, int64, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	client := httpClient
	if skipTLS {
		client = httpClientInsecure
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	return resp, elapsed, err
}

func checkSite(entry SiteEntry) Result {
	result := Result{URL: entry.URL}

	var resp *http.Response
	var elapsed int64
	var err error

	// Attempt 1: normal GET with browser headers
	resp, elapsed, err = doRequest("GET", entry.URL, entry.SkipTLS)

	// Attempt 2: GET with TLS skip — rules out cert issues causing EOF
	if err != nil && isRetryable(err.Error()) && !entry.SkipTLS {
		time.Sleep(retryDelay)
		resp, elapsed, err = doRequest("GET", entry.URL, true)
		if err == nil {
			result.Unverifiable = true
		}
	}

	// Attempt 3: HEAD request — some servers drop GET but respond to HEAD
	if err != nil && isRetryable(err.Error()) {
		time.Sleep(retryDelay)
		resp, elapsed, err = doRequest("HEAD", entry.URL, true)
		if err == nil {
			result.Unverifiable = true
		}
	}

	// All three attempts failed — genuinely down
	if err != nil {
		result.Error = err.Error()
		return result
	}

	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	result.Status = resp.StatusCode
	result.ResponseMs = elapsed

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		expiry := resp.TLS.PeerCertificates[0].NotAfter
		daysLeft := int(time.Until(expiry).Hours() / 24)
		result.CertExpiry = fmt.Sprintf("%s (%d days)", expiry.Format("2006-01-02"), daysLeft)
	}

	return result
}

func statusLabel(r Result) string {
	if r.Unverifiable {
		return "UNVERIFIABLE"
	}
	switch {
	case r.Status >= 200 && r.Status < 300:
		return "UP"
	case r.Status >= 300 && r.Status < 400:
		return "REDIRECT"
	case r.Status >= 400:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

func main() {
	sitesFile := "sites.txt"
	if len(os.Args) > 1 {
		sitesFile = os.Args[1]
	}

	f, err := os.Open(sitesFile)
	if err != nil {
		log.Fatalf("Could not open sites file: %v", err)
	}
	defer f.Close()

	var entries []SiteEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		skipTLS := false
		if strings.Contains(line, "#skip-tls") {
			skipTLS = true
			line = strings.TrimSpace(strings.Split(line, "#")[0])
		}

		if !strings.HasPrefix(line, "http") {
			line = "https://" + line
		}

		entries = append(entries, SiteEntry{URL: line, SkipTLS: skipTLS})
	}

	if len(entries) == 0 {
		log.Fatal("No URLs found in sites file.")
	}

	fmt.Printf("Checking %d sites (max %d concurrent)...\n", len(entries), maxConcurrent)

	sem := make(chan struct{}, maxConcurrent)
	results := make([]Result, len(entries))
	var wg sync.WaitGroup

	for i, entry := range entries {
		wg.Add(1)
		go func(idx int, e SiteEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkSite(e)
			fmt.Printf("  [%d/%d] %s\n", idx+1, len(entries), e.URL)
		}(i, entry)
	}
	wg.Wait()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	dateStamp := time.Now().Format("2006-01-02")

	fmt.Printf("\n=== Uptime Check: %s ===\n\n", timestamp)
	fmt.Printf("%-50s %-14s %-6s %-10s %s\n", "URL", "STATUS", "CODE", "RESP(ms)", "SSL EXPIRY")
	fmt.Println(strings.Repeat("-", 115))

	upCount, downCount, errCount, unverCount := 0, 0, 0, 0

	for _, r := range results {
		label := statusLabel(r)
		if r.Error != "" {
			fmt.Printf("%-50s %-14s %-6s %-10s %s\n", r.URL, "DOWN", "-", "-", r.Error)
			downCount++
		} else {
			cert := r.CertExpiry
			if cert == "" {
				cert = "N/A"
			}
			fmt.Printf("%-50s %-14s %-6d %-10d %s\n", r.URL, label, r.Status, r.ResponseMs, cert)
			switch label {
			case "UP":
				upCount++
			case "UNVERIFIABLE":
				unverCount++
			default:
				errCount++
			}
		}
	}

	fmt.Println(strings.Repeat("-", 115))
	fmt.Printf("Summary: %d UP | %d ERROR | %d DOWN | %d UNVERIFIABLE\n\n", upCount, errCount, downCount, unverCount)

	os.MkdirAll("logs", 0755)
	logFile := fmt.Sprintf("logs/uptime-%s.log", dateStamp)
	lf, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Warning: could not write log: %v", err)
		return
	}
	defer lf.Close()

	logger := log.New(lf, "", 0)
	logger.Printf("=== %s ===", timestamp)
	for _, r := range results {
		label := statusLabel(r)
		if r.Error != "" {
			logger.Printf("DOWN         | %s | ERROR: %s", r.URL, r.Error)
		} else {
			logger.Printf("%-12s | %s | HTTP %d | %dms | SSL: %s", label, r.URL, r.Status, r.ResponseMs, r.CertExpiry)
		}
	}
	logger.Printf("Summary: %d UP | %d ERROR | %d DOWN | %d UNVERIFIABLE\n", upCount, errCount, downCount, unverCount)

	fmt.Printf("Log saved: %s\n", logFile)
}
