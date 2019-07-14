package httpstatus

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// TODO: Remove Logging - Return errors

type HttpStatusTester struct {
	HTTPMethod          string
	RequestBody         string
	FollowRedirects     bool
	MaxRedirects        int
	OnlyHeader          bool
	Insecure            bool
	HTTPHeaders         headers
	ClientCertFile      string
	FourOnly            bool
	SixOnly             bool
	DiscardResponseBody bool

	uri string
	url *url.URL

	Statistics []*HTTPStatistics

	redirectsFollowed int
}

type HTTPStatistics struct {
	Seq int

	ConnectedTo string

	URL      *url.URL
	Location *url.URL

	Response *http.Response // TODO: HTTPX.X 200 OK TODO: Headers

	ResponseHeaders   headers
	ResponseBody      string
	ResponseBodyBytes int

	TLSHandshakeComplete bool

	DNSLookup        time.Duration
	TCPConnection    time.Duration 
	TLSHandshake     time.Duration
	ServerProcessing time.Duration
	ContentTransfer  time.Duration
	NameLookup       time.Duration
	Connect          time.Duration
	PreTransfer      time.Duration
	Starttransfer    time.Duration
	Total            time.Duration

	SkippedDNS bool

	Err error
}

func NewHttpStatusTester(uri string) (*HttpStatusTester, error) {
	url, err := parseURL(uri)
	if err != nil {
		return nil, err
	}

	return &HttpStatusTester{
		uri:                 uri,
		url:                 url,
		HTTPMethod:          "GET",
		FollowRedirects:     true,
		MaxRedirects:        10,
		Insecure:            false,
		DiscardResponseBody: true,
	}, nil
}

func (c *HttpStatusTester) Run() error {
	if c.FourOnly && c.SixOnly {
		return errors.New("cannot specify ipv4 only and ipv6 only together")
	}

	if (c.HTTPMethod == "POST" || c.HTTPMethod == "PUT") && c.RequestBody == "" {
		return errors.New("must specify request body when POST or PUT method is used")
	}

	if c.OnlyHeader {
		c.HTTPMethod = "HEAD"
	}

	c.visit(c.url, 1)

	return nil

}

// readClientCert - helper function to read client certificate
// from pem formatted file
func readClientCert(filename string) ([]tls.Certificate, error) {
	if filename == "" {
		return nil, nil
	}
	var (
		pkeyPem []byte
		certPem []byte
	)

	// read client certificate file (must include client private key and certificate)
	certFileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate file: %v", err)
	}

	for {
		block, rest := pem.Decode(certFileBytes)
		if block == nil {
			break
		}
		certFileBytes = rest

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			pkeyPem = pem.EncodeToMemory(block)
		}
		if strings.HasSuffix(block.Type, "CERTIFICATE") {
			certPem = pem.EncodeToMemory(block)
		}
	}

	cert, err := tls.X509KeyPair(certPem, pkeyPem)
	if err != nil {
		return nil, fmt.Errorf("unable to load client cert and key pair: %v", err)
	}
	return []tls.Certificate{cert}, nil
}

func parseURL(uri string) (*url.URL, error) {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	url, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("could not parse url %q: %v", uri, err)
	}

	if url.Scheme == "" {
		url.Scheme = "http"
		if !strings.HasSuffix(url.Host, ":80") {
			url.Scheme += "s"
		}
	}
	return url, nil
}

func headerKeyValue(h string) (string, string, error) {
	i := strings.Index(h, ":")
	if i == -1 {
		return "", "", fmt.Errorf("Header '%s' has invalid format, missing ':'", h)
	}
	return strings.TrimRight(h[:i], " "), strings.TrimLeft(h[i:], " :"), nil
}

func dialContext(network string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		}).DialContext(ctx, network, addr)
	}
}

// visit visits a url and times the interaction.
// If the response is a 30x, visit follows the redirect.
func (c *HttpStatusTester) visit(url *url.URL, seq int) {
	stat := &HTTPStatistics{
		Seq: seq,
		URL: url,
	}

	req, err := c.newRequest(c.HTTPMethod, url, c.RequestBody)
	if err != nil {
		stat.Err = err
		c.Statistics = append(c.Statistics, stat)
		return
	}

	var t0, t1, t2, t3, t4, t5, t6 time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { t0 = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { t1 = time.Now() },
		ConnectStart: func(_, _ string) {
			if t1.IsZero() {
				// connecting to IP
				t1 = time.Now()
			}
		},
		ConnectDone: func(net, addr string, err error) {
			if err != nil {
				stat.Err = fmt.Errorf("unable to connect to host %v: %v", addr, err)
			}
			t2 = time.Now()
			stat.ConnectedTo = addr
		},
		GotConn:              func(_ httptrace.GotConnInfo) { t3 = time.Now() },
		GotFirstResponseByte: func() { t4 = time.Now() },
		TLSHandshakeStart:    func() { t5 = time.Now() },
		TLSHandshakeDone: func(t tls.ConnectionState, _ error) {
			t6 = time.Now()
			stat.TLSHandshakeComplete = t.HandshakeComplete
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	switch {
	case c.FourOnly:
		tr.DialContext = dialContext("tcp4")
	case c.SixOnly:
		tr.DialContext = dialContext("tcp6")
	}

	switch c.url.Scheme {
	case "https":
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
		}

		cert, err := readClientCert(c.ClientCertFile)
		if err != nil {
			stat.Err = err
			c.Statistics = append(c.Statistics, stat)
		}

		tr.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: c.Insecure,
			Certificates:       cert,
		}

		// Because we create a custom TLSClientConfig, we have to opt-in to HTTP/2.
		// See https://github.com/golang/go/issues/14275
		err = http2.ConfigureTransport(tr)
		if err != nil {
			stat.Err = fmt.Errorf("failed to prepare transport for HTTP/2: %v", err)
			c.Statistics = append(c.Statistics, stat)
			return
		}
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// always refuse to follow redirects, visit does that
			// manually if required.
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		stat.Err = err
		c.Statistics = append(c.Statistics, stat)
		return
	}

	body, err := readResponseBody(req, resp)
	defer resp.Body.Close()
	if err != nil {
		stat.Err = err
		c.Statistics = append(c.Statistics, stat)
		return
	}
	if c.DiscardResponseBody {
		stat.ResponseBodyBytes = len(body)
		stat.ResponseBody = "Body Discarded"
	} else {
		stat.ResponseBodyBytes = len(body)
		stat.ResponseBody = string(body)
	}

	t7 := time.Now() // after read body
	if t0.IsZero() {
		// we skipped DNS
		t0 = t1
		stat.SkippedDNS = true
	}

	names := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		names = append(names, k)
	}
	sort.Sort(headers(names))

	stat.ResponseHeaders = names

	stat.Response = resp

	switch c.url.Scheme {
	case "https":
		stat.DNSLookup = t1.Sub(t0)
		stat.TCPConnection = t2.Sub(t1)
		stat.TLSHandshake = t6.Sub(t5)
		stat.ServerProcessing = t4.Sub(t3)
		stat.ContentTransfer = t7.Sub(t4)
		stat.NameLookup = t1.Sub(t0)
		stat.Connect = t2.Sub(t0)
		stat.PreTransfer = t3.Sub(t0)
		stat.Starttransfer = t4.Sub(t0)
		stat.Total = t7.Sub(t0)
	case "http":
		stat.DNSLookup = t1.Sub(t0)
		stat.TCPConnection = t3.Sub(t1)
		stat.ServerProcessing = t4.Sub(t3)
		stat.ContentTransfer = t7.Sub(t4)
		stat.NameLookup = t1.Sub(t0)
		stat.Connect = t3.Sub(t0)
		stat.Starttransfer = t4.Sub(t0)
		stat.Total = t7.Sub(t0)
	}

	if c.FollowRedirects && isRedirect(resp) {
		loc, err := resp.Location()
		if err != nil {
			if err == http.ErrNoLocation {
				// 30x but no Location to follow, give up.
				stat.Err = fmt.Errorf("redirect but no location to follow")
				c.Statistics = append(c.Statistics, stat)
				return
			}
		}
		stat.Location = loc

		c.redirectsFollowed++
		if c.redirectsFollowed > c.MaxRedirects {
			// maximum number of redirects followed
			stat.Err = fmt.Errorf("maximum number of redirects followed")
			c.Statistics = append(c.Statistics, stat)
			return
		}

		c.visit(loc, seq+1)
	}

	c.Statistics = append(c.Statistics, stat)

}

func isRedirect(resp *http.Response) bool {
	return resp.StatusCode > 299 && resp.StatusCode < 400
}

func (c *HttpStatusTester) newRequest(method string, url *url.URL, body string) (*http.Request, error) {
	req, err := http.NewRequest(method, url.String(), createBody(body))
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %v", err)
	}
	for _, h := range c.HTTPHeaders {
		k, v, _ := headerKeyValue(h)
		if strings.EqualFold(k, "host") {
			req.Host = v
			continue
		}
		req.Header.Add(k, v)
	}
	return req, nil
}

func createBody(body string) io.Reader {
	return strings.NewReader(body)
}

// readResponseBody consumes the body of the response.
// readResponseBody returns an informational message about the
// disposition of the response body's contents.
func readResponseBody(req *http.Request, resp *http.Response) ([]byte, error) {
	if isRedirect(resp) || req.Method == http.MethodHead {
		return []byte{}, nil
	}

	msg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read response body: %v", err)
	}

	return msg, nil
}

type headers []string

func (h headers) String() string {
	var o []string
	for _, v := range h {
		o = append(o, "-H "+v)
	}
	return strings.Join(o, " ")
}

func (h *headers) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func (h headers) Len() int      { return len(h) }
func (h headers) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h headers) Less(i, j int) bool {
	a, b := h[i], h[j]

	// server always sorts at the top
	if a == "Server" {
		return true
	}
	if b == "Server" {
		return false
	}

	endtoend := func(n string) bool {
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
		switch n {
		case "Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"TE",
			"Trailers",
			"Transfer-Encoding",
			"Upgrade":
			return false
		default:
			return true
		}
	}

	x, y := endtoend(a), endtoend(b)
	if x == y {
		// both are of the same class
		return a < b
	}
	return x
}
