package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
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
	CertDaysLeft int
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
		result.CertDaysLeft = daysLeft
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

// friendlyLabel returns plain-English status for non-technical readers.
func friendlyLabel(r Result) string {
	if r.Error != "" {
		return "Offline"
	}
	switch statusLabel(r) {
	case "UP":
		return "Online"
	case "UNVERIFIABLE":
		return "Unverified"
	default:
		return "Has Issues"
	}
}

func badgeHTML(r Result) string {
	label := friendlyLabel(r)
	var class string
	switch label {
	case "Online":
		class = "badge-green"
	case "Offline":
		class = "badge-red"
	case "Has Issues":
		class = "badge-yellow"
	default:
		class = "badge-blue"
	}
	return fmt.Sprintf(`<span class="badge %s">%s</span>`, class, label)
}

func sslHTML(r Result) string {
	if r.CertExpiry == "" {
		return `<span class="ssl-na">N/A</span>`
	}
	days := r.CertDaysLeft
	switch {
	case days <= 0:
		return `<span class="ssl-urgent">EXPIRED</span>`
	case days <= 14:
		return fmt.Sprintf(`<span class="ssl-urgent">%d days — Renew Now</span>`, days)
	case days <= 30:
		return fmt.Sprintf(`<span class="ssl-warn">%d days — Renew Soon</span>`, days)
	default:
		return fmt.Sprintf(`<span class="ssl-ok">%d days</span>`, days)
	}
}

func displayURL(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	return s
}

func writeHTMLReport(results []Result, timestamp string) {
	os.MkdirAll("docs", 0755)
	f, err := os.Create("docs/index.html")
	if err != nil {
		log.Printf("Warning: could not write HTML report: %v", err)
		return
	}
	defer f.Close()

	// Tally counts and collect issues / SSL warnings
	up, down, issues, unver := 0, 0, 0, 0
	var attention []Result
	var sslSoon []Result

	for _, r := range results {
		label := friendlyLabel(r)
		switch label {
		case "Online":
			up++
		case "Offline":
			down++
			attention = append(attention, r)
		case "Has Issues":
			issues++
			attention = append(attention, r)
		default:
			unver++
			attention = append(attention, r)
		}
		if r.CertDaysLeft > 0 && r.CertDaysLeft <= 30 {
			sslSoon = append(sslSoon, r)
		}
	}

	// Sort SSL warnings by days left ascending
	sort.Slice(sslSoon, func(i, j int) bool {
		return sslSoon[i].CertDaysLeft < sslSoon[j].CertDaysLeft
	})

	// Sort all results: issues first, then alphabetically
	sorted := make([]Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		li, lj := friendlyLabel(sorted[i]), friendlyLabel(sorted[j])
		if li != lj {
			order := map[string]int{"Offline": 0, "Has Issues": 1, "Unverified": 2, "Online": 3}
			return order[li] < order[lj]
		}
		return sorted[i].URL < sorted[j].URL
	})

	w := bufio.NewWriter(f)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Website Status Report</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#111827;line-height:1.5}
    .wrap{max-width:1000px;margin:0 auto;padding:32px 16px}
    header{margin-bottom:28px}
    header h1{font-size:26px;font-weight:700;color:#111827}
    header p{color:#6b7280;margin-top:4px;font-size:14px}
    .cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:28px}
    .card{flex:1;min-width:120px;border-radius:12px;padding:18px 16px;text-align:center}
    .card .num{font-size:42px;font-weight:700;line-height:1}
    .card .lbl{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;margin-top:6px;opacity:.75}
    .c-green{background:#dcfce7;color:#15803d}
    .c-red{background:#fee2e2;color:#b91c1c}
    .c-yellow{background:#fef9c3;color:#92400e}
    .c-blue{background:#dbeafe;color:#1d4ed8}
    .panel{background:#fff;border-radius:12px;padding:22px 20px;margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
    .panel h2{font-size:16px;font-weight:600;margin-bottom:4px}
    .panel .sub{font-size:13px;color:#6b7280;margin-bottom:16px}
    table{width:100%;border-collapse:collapse;font-size:14px}
    th{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;padding:8px 10px;border-bottom:1px solid #f3f4f6}
    td{padding:11px 10px;border-bottom:1px solid #f9fafb;vertical-align:middle}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#fafafa}
    .site-name{font-weight:500;color:#111827;word-break:break-all}
    .site-url{font-size:12px;color:#9ca3af;margin-top:2px}
    .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
    .badge-green{background:#dcfce7;color:#15803d}
    .badge-red{background:#fee2e2;color:#b91c1c}
    .badge-yellow{background:#fef9c3;color:#92400e}
    .badge-blue{background:#dbeafe;color:#1d4ed8}
    .ssl-ok{color:#9ca3af}
    .ssl-warn{color:#d97706;font-weight:600}
    .ssl-urgent{color:#dc2626;font-weight:700}
    .ssl-na{color:#d1d5db}
    .err-msg{font-size:12px;color:#ef4444;margin-top:3px}
    .all-good{padding:20px;text-align:center;color:#15803d;font-size:15px;font-weight:500}
    details{margin-bottom:18px}
    details>summary{list-style:none;background:#fff;border-radius:12px;padding:16px 20px;font-size:15px;font-weight:600;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.08);display:flex;justify-content:space-between;align-items:center;color:#374151}
    details>summary::-webkit-details-marker{display:none}
    details[open]>summary{border-radius:12px 12px 0 0;border-bottom:1px solid #f3f4f6}
    details .panel{border-radius:0 0 12px 12px;margin-bottom:18px;box-shadow:0 2px 4px rgba(0,0,0,.08)}
    .chevron{transition:transform .2s;color:#9ca3af;font-size:18px}
    details[open] .chevron{transform:rotate(90deg)}
    footer{text-align:center;color:#9ca3af;font-size:12px;margin-top:32px;padding-bottom:16px}
  </style>
</head>
<body>
<div class="wrap">

<header>
  <h1>Website Status Report</h1>
  <p>Last checked: %s</p>
</header>

<div class="cards">
  <div class="card c-green"><div class="num">%d</div><div class="lbl">Online</div></div>
  <div class="card c-red"><div class="num">%d</div><div class="lbl">Offline</div></div>
  <div class="card c-yellow"><div class="num">%d</div><div class="lbl">Has Issues</div></div>
  <div class="card c-blue"><div class="num">%d</div><div class="lbl">Unverified</div></div>
</div>

`, timestamp, up, down, issues, unver)

	// --- Needs Attention panel ---
	fmt.Fprintf(w, `<div class="panel">
  <h2>⚠ Needs Attention</h2>
  <p class="sub">Sites that are offline or have a problem right now.</p>
`)
	if len(attention) == 0 {
		fmt.Fprintf(w, `  <div class="all-good">✓ All websites are online and running normally.</div>`)
	} else {
		fmt.Fprintf(w, `  <table>
    <thead><tr><th>Website</th><th>Status</th><th>Details</th></tr></thead>
    <tbody>
`)
		for _, r := range attention {
			detail := ""
			if r.Error != "" {
				detail = "Could not connect to the website"
			} else if r.Status >= 400 {
				detail = fmt.Sprintf("Server returned an error (code %d)", r.Status)
			} else if r.Unverifiable {
				detail = "Site responded but security could not be verified"
			}
			fmt.Fprintf(w, "      <tr><td><div class=\"site-name\">%s</div></td><td>%s</td><td><span class=\"err-msg\">%s</span></td></tr>\n",
				html.EscapeString(displayURL(r.URL)),
				badgeHTML(r),
				html.EscapeString(detail),
			)
		}
		fmt.Fprintf(w, "    </tbody></table>\n")
	}
	fmt.Fprintf(w, "</div>\n\n")

	// --- SSL panel ---
	fmt.Fprintf(w, `<div class="panel">
  <h2>🔒 Security Certificates (SSL)</h2>
  <p class="sub">SSL certificates keep websites secure. If one expires, visitors will see a security warning and may not be able to access the site.</p>
`)
	if len(sslSoon) == 0 {
		fmt.Fprintf(w, `  <div class="all-good">✓ All certificates are valid for more than 30 days.</div>`)
	} else {
		fmt.Fprintf(w, `  <table>
    <thead><tr><th>Website</th><th>Expires In</th></tr></thead>
    <tbody>
`)
		for _, r := range sslSoon {
			fmt.Fprintf(w, "      <tr><td class=\"site-name\">%s</td><td>%s</td></tr>\n",
				html.EscapeString(displayURL(r.URL)),
				sslHTML(r),
			)
		}
		fmt.Fprintf(w, "    </tbody></table>\n")
	}
	fmt.Fprintf(w, "</div>\n\n")

	// --- All sites (collapsed) ---
	fmt.Fprintf(w, "<details>\n  <summary>All Websites (%d total) <span class=\"chevron\">›</span></summary>\n  <div class=\"panel\">\n", len(results))
	fmt.Fprintf(w, `    <table>
      <thead><tr><th>Website</th><th>Status</th><th>Certificate</th></tr></thead>
      <tbody>
`)
	for _, r := range sorted {
		fmt.Fprintf(w, "        <tr><td class=\"site-name\">%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(displayURL(r.URL)),
			badgeHTML(r),
			sslHTML(r),
		)
	}
	fmt.Fprintf(w, "      </tbody></table>\n  </div>\n</details>\n\n")

	fmt.Fprintf(w, "<footer>Generated automatically every day &middot; %s</footer>\n", html.EscapeString(timestamp))
	fmt.Fprintf(w, "</div>\n</body>\n</html>\n")

	w.Flush()
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
	} else {
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

	writeHTMLReport(results, timestamp)
	fmt.Println("Report saved: docs/index.html")
}
