package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func resetPrivateDestinationPolicy(t *testing.T) {
	t.Helper()
	previousAllowPrivateIPs := AllowPrivateIPs
	AllowPrivateIPs = false
	require.NoError(t, ConfigurePrivateDestinationAllowlist(nil))
	t.Cleanup(func() {
		AllowPrivateIPs = previousAllowPrivateIPs
		require.NoError(t, ConfigurePrivateDestinationAllowlist(nil))
	})
}

func TestConfigurePrivateDestinationAllowlist(t *testing.T) {
	t.Run("exact hostname is normalized", func(t *testing.T) {
		resetPrivateDestinationPolicy(t)
		require.NoError(t, ConfigurePrivateDestinationAllowlist([]string{" LOCALHOST. "}))
		require.NoError(t, ValidateURL("http://localhost:8080/hook"))
	})

	t.Run("exact IP is allowed", func(t *testing.T) {
		resetPrivateDestinationPolicy(t)
		require.NoError(t, ConfigurePrivateDestinationAllowlist([]string{"127.0.0.42"}))
		require.NoError(t, ValidateURL("http://127.0.0.42/hook"))
		require.Error(t, ValidateURL("http://127.0.0.43/hook"))
	})

	t.Run("CGNAT requires an explicit allowlist entry", func(t *testing.T) {
		resetPrivateDestinationPolicy(t)
		require.Error(t, ValidateURL("http://100.100.100.200/hook"))
		require.NoError(t, ConfigurePrivateDestinationAllowlist([]string{"100.100.100.200"}))
		require.NoError(t, ValidateURL("http://100.100.100.200/hook"))
		require.Error(t, ValidateURL("http://100.100.100.201/hook"))
	})

	t.Run("CIDR is normalized and allowed", func(t *testing.T) {
		resetPrivateDestinationPolicy(t)
		require.NoError(t, ConfigurePrivateDestinationAllowlist([]string{"127.0.0.99/24"}))
		require.NoError(t, ValidateURL("http://127.0.0.42/hook"))
		require.Error(t, ValidateURL("http://127.0.1.42/hook"))
	})

	t.Run("invalid entry leaves prior policy intact", func(t *testing.T) {
		resetPrivateDestinationPolicy(t)
		require.NoError(t, ConfigurePrivateDestinationAllowlist([]string{"localhost"}))

		invalidEntries := []string{
			"",
			"http://localhost",
			"localhost:8080",
			"*.example.com",
			"bad_name",
			"127.0.0.1/999",
			"-invalid.example",
		}
		for _, entry := range invalidEntries {
			require.Error(t, ConfigurePrivateDestinationAllowlist([]string{entry}), entry)
			require.NoError(t, ValidateURL("http://localhost/hook"), "failed configuration must not replace the active policy")
		}
	})

	t.Run("nonmatching private target remains blocked", func(t *testing.T) {
		resetPrivateDestinationPolicy(t)
		require.NoError(t, ConfigurePrivateDestinationAllowlist([]string{"10.0.0.0/8", "hooks.internal"}))
		require.Error(t, ValidateURL("http://127.0.0.1/hook"))
	})

	t.Run("public target remains allowed", func(t *testing.T) {
		resetPrivateDestinationPolicy(t)
		require.False(t, isBlockedDestination("dns.google", net.ParseIP("8.8.8.8")))
	})
}

func TestPrivateDestinationPolicyConcurrentAccess(t *testing.T) {
	resetPrivateDestinationPolicy(t)

	privateIP := net.ParseIP("127.0.0.1")
	var waitGroup sync.WaitGroup
	for range 8 {
		waitGroup.Go(func() {
			for range 100 {
				_ = isPrivateDestinationAllowed("localhost", privateIP)
			}
		})
		waitGroup.Go(func() {
			for range 100 {
				if err := ConfigurePrivateDestinationAllowlist([]string{"localhost", "127.0.0.0/8"}); err != nil {
					t.Errorf("ConfigurePrivateDestinationAllowlist() error = %v", err)
				}
			}
		})
	}
	waitGroup.Wait()
}

func TestAllowPrivateIPsCompatibility(t *testing.T) {
	resetPrivateDestinationPolicy(t)
	AllowPrivateIPs = true
	require.NoError(t, ValidateURL("http://127.0.0.1/hook"))
}

func TestPostChecksRedirectDestinationAtDialTime(t *testing.T) {
	resetPrivateDestinationPolicy(t)
	require.NoError(t, ConfigurePrivateDestinationAllowlist([]string{"localhost"}))

	var redirectedRequestReceived atomic.Bool
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedRequestReceived.Store(true)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer redirectTarget.Close()

	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", redirectTarget.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer redirectSource.Close()

	sourceURL := strings.Replace(redirectSource.URL, "127.0.0.1", "localhost", 1)
	err := Post(&Request{URL: sourceURL})
	require.ErrorContains(t, err, "connection to reserved/private IP address is not allowed")
	require.False(t, redirectedRequestReceived.Load())
}

func TestPostAllowsExplicitPrivateIPPolicyAtDialTime(t *testing.T) {
	tests := []struct {
		name      string
		allowlist []string
	}{
		{name: "exact IP", allowlist: []string{"127.0.0.1"}},
		{name: "CIDR", allowlist: []string{"127.0.0.99/8"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetPrivateDestinationPolicy(t)
			require.NoError(t, ConfigurePrivateDestinationAllowlist(tc.allowlist))

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"code":0}`))
			}))
			defer server.Close()

			require.NoError(t, Post(&Request{URL: server.URL}))
		})
	}
}

func TestPostAsyncNilPayloadDoesNotPanic(t *testing.T) {
	require.NotPanics(t, func() {
		PostAsync(nil)
	})
}

func TestResolveSigningKey(t *testing.T) {
	rawKey := []byte("0123456789abcdef")
	whsec := "whsec_" + base64.StdEncoding.EncodeToString(rawKey)

	t.Run("plain secret used as-is", func(t *testing.T) {
		key, err := resolveSigningKey("my-plain-secret")
		require.NoError(t, err)
		require.Equal(t, []byte("my-plain-secret"), key)
	})

	t.Run("whsec_ prefix is base64-decoded", func(t *testing.T) {
		key, err := resolveSigningKey(whsec)
		require.NoError(t, err)
		require.Equal(t, rawKey, key)
	})

	t.Run("whsec_ with invalid base64 fails loudly", func(t *testing.T) {
		_, err := resolveSigningKey("whsec_not!valid!base64!")
		require.Error(t, err)
	})
}

func TestGenerateSigningSecret(t *testing.T) {
	secret, err := GenerateSigningSecret()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(secret, "whsec_"), "generated secret must use the whsec_ prefix")
	require.NoError(t, ValidateSigningSecret(secret), "generated secret must pass validation")

	key, err := resolveSigningKey(secret)
	require.NoError(t, err)
	require.Len(t, key, 32, "generated secret must decode to 32 raw bytes")

	other, err := GenerateSigningSecret()
	require.NoError(t, err)
	require.NotEqual(t, secret, other, "each generated secret must be unique")
}

func TestValidateSigningSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{name: "empty is allowed", secret: "", wantErr: false},
		{name: "printable ascii", secret: "abcDEF123!@#", wantErr: false},
		{name: "valid whsec_", secret: "whsec_" + base64.StdEncoding.EncodeToString([]byte("key")), wantErr: false},
		{name: "newline rejected", secret: "abc\ndef", wantErr: true},
		{name: "carriage return rejected", secret: "abc\rdef", wantErr: true},
		{name: "tab rejected", secret: "abc\tdef", wantErr: true},
		{name: "non-ascii rejected", secret: "abc€def", wantErr: true},
		{name: "whsec_ with invalid base64 rejected", secret: "whsec_not!base64", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSigningSecret(tc.secret)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestPostSignsRequest verifies the end-to-end Standard Webhooks signature so a
// receiver following the documented verification recipe will accept our requests.
func TestPostSignsRequest(t *testing.T) {
	// httptest listens on 127.0.0.1, which the SSRF guard blocks by default.
	prev := AllowPrivateIPs
	AllowPrivateIPs = true
	defer func() { AllowPrivateIPs = prev }()

	rawKey := []byte("0123456789abcdef0123456789abcdef")
	cases := []struct {
		name   string
		secret string
		key    []byte
	}{
		{name: "plain secret", secret: "plain-secret-value", key: []byte("plain-secret-value")},
		{name: "whsec_ secret", secret: "whsec_" + base64.StdEncoding.EncodeToString(rawKey), key: rawKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotID, gotTimestamp, gotSignature string
			var gotBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotID = r.Header.Get("webhook-id")
				gotTimestamp = r.Header.Get("webhook-timestamp")
				gotSignature = r.Header.Get("webhook-signature")
				gotBody, _ = io.ReadAll(r.Body)
				_, _ = w.Write([]byte(`{"code":0}`))
			}))
			defer server.Close()

			err := Post(&Request{
				URL:           server.URL,
				Label:         "memos.memo.created",
				SigningSecret: tc.secret,
			})
			require.NoError(t, err)

			require.True(t, strings.HasPrefix(gotID, "msg_"), "webhook-id should be prefixed with msg_")
			require.NotEmpty(t, gotTimestamp)
			require.True(t, strings.HasPrefix(gotSignature, "v1,"), "signature should carry the v1 version tag")

			// Recompute the signature the way a receiver would and confirm it matches.
			mac := hmac.New(sha256.New, tc.key)
			mac.Write([]byte(gotID + "." + gotTimestamp + "."))
			mac.Write(gotBody)
			want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
			require.Equal(t, "v1,"+want, gotSignature)
		})
	}
}

// TestPostWithoutSecretSetsNoSignatureHeaders ensures unsigned webhooks stay unsigned.
func TestPostWithoutSecretSetsNoSignatureHeaders(t *testing.T) {
	prev := AllowPrivateIPs
	AllowPrivateIPs = true
	defer func() { AllowPrivateIPs = prev }()

	var hasSignatureHeaders bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasSignatureHeaders = r.Header.Get("webhook-id") != "" ||
			r.Header.Get("webhook-timestamp") != "" ||
			r.Header.Get("webhook-signature") != ""
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer server.Close()

	err := Post(&Request{
		URL:   server.URL,
		Label: "memos.memo.created",
	})
	require.NoError(t, err)
	require.False(t, hasSignatureHeaders, "no signature headers should be set when no secret is configured")
}

func TestIsReservedIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		reserved bool
	}{
		{name: "loopback", ip: "127.0.0.1", reserved: true},
		{name: "private 10", ip: "10.0.0.1", reserved: true},
		{name: "private 172", ip: "172.16.0.1", reserved: true},
		{name: "private 192", ip: "192.168.1.1", reserved: true},
		{name: "link local imds", ip: "169.254.169.254", reserved: true},
		{name: "cgnat lower bound", ip: "100.64.0.1", reserved: true},
		{name: "cgnat alibaba metadata", ip: "100.100.100.200", reserved: true},
		{name: "cgnat upper bound", ip: "100.127.255.255", reserved: true},
		{name: "mapped ipv6 cgnat", ip: "::ffff:100.100.100.200", reserved: true},
		{name: "ipv6 loopback", ip: "::1", reserved: true},
		{name: "below cgnat", ip: "100.63.255.255", reserved: false},
		{name: "above cgnat", ip: "100.128.0.0", reserved: false},
		{name: "public dns", ip: "8.8.8.8", reserved: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.reserved, isReservedIP(net.ParseIP(test.ip)))
		})
	}
}

func TestValidateURLRejectsCGNAT(t *testing.T) {
	resetPrivateDestinationPolicy(t)
	require.Error(t, ValidateURL("http://100.100.100.200/hook"))
}

// TestPostRejectsUnspecifiedAddressDestination pins that a webhook URL pointing at the
// unspecified address is refused at dial time, bcs the kernel treats it as the local host.
func TestPostRejectsUnspecifiedAddressDestination(t *testing.T) {
	resetPrivateDestinationPolicy(t)

	var receivedRequest atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		receivedRequest.Store(true)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer server.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	require.NoError(t, err)

	err = Post(&Request{
		URL:   "http://0.0.0.0:" + port,
		Label: "memos.memo.created",
	})
	require.Error(t, err)
	require.False(t, receivedRequest.Load(), "the webhook must not reach a local service through the unspecified address")
}

// TestValidateURLRejectsUnspecifiedAddress ensures webhook URL validation also refuses
// the unspecified address, so such URLs never even reach the dispatch path.
func TestValidateURLRejectsUnspecifiedAddress(t *testing.T) {
	resetPrivateDestinationPolicy(t)

	require.Error(t, ValidateURL("http://0.0.0.0:8080/hook"))
	require.Error(t, ValidateURL("http://[::]:8080/hook"))
}

func TestValidateURLCGNAT(t *testing.T) {
	resetPrivateDestinationPolicy(t)
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"100.63.255.255", false},
		{"100.64.0.0", true},
		{"100.100.100.200", true},
		{"100.127.255.255", true},
		{"100.128.0.0", false},
		{"::ffff:100.64.0.0", true},
		{"::ffff:100.100.100.200", true},
		{"::ffff:100.127.255.255", true},
		{"::ffff:100.128.0.0", false},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			address := net.JoinHostPort(tc.ip, "80")
			err := ValidateURL("http://" + address + "/hook")
			if tc.blocked {
				require.ErrorContains(t, err, "must not resolve to a reserved or private IP address")
				// Cancellation prevents any network connection if the guard regresses.
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_, err = safeDialContext(ctx, "tcp", address)
				require.ErrorContains(t, err, "connection to reserved/private IP address is not allowed")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPostRetriesTransientFailures(t *testing.T) {
	resetPrivateDestinationPolicy(t)
	AllowPrivateIPs = true
	previousBaseDelay := retryBaseDelay
	retryBaseDelay = 2 * time.Millisecond
	t.Cleanup(func() { retryBaseDelay = previousBaseDelay })

	testCases := []struct {
		name         string
		statuses     []int
		wantAttempts int32
		wantErr      string
	}{
		{name: "recovers after a 503", statuses: []int{503, 200}, wantAttempts: 2},
		{name: "recovers after a 429", statuses: []int{429, 200}, wantAttempts: 2},
		{name: "returns the last status after exhausting attempts", statuses: []int{500, 502, 503, 200}, wantAttempts: 3, wantErr: "status code: 503"},
		{name: "does not retry a client error", statuses: []int{404, 200}, wantAttempts: 1, wantErr: "status code: 404"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.JSONEq(t, `{"hello":"world"}`, string(body))
				w.WriteHeader(tc.statuses[attempts.Add(1)-1])
				_, _ = w.Write([]byte(`{"code":0}`))
			}))
			defer server.Close()

			err := Post(&Request{URL: server.URL, Payload: map[string]string{"hello": "world"}})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantAttempts, attempts.Load())
		})
	}
}

type webhookRoundTripFunc func(*http.Request) (*http.Response, error)

func (f webhookRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	defer r.Body.Close()
	return f(r)
}

func stubWebhookTransport(t *testing.T, f webhookRoundTripFunc) {
	t.Helper()
	previousClient := safeClient
	safeClient = &http.Client{Transport: f}
	t.Cleanup(func() { safeClient = previousClient })
}

func TestPostSignsEveryRetryWithCurrentTimestamp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			secret = "test-signing-secret"
			target = "https://receiver.example/hook"
		)
		var attemptTimes []time.Time
		ids := make(map[string]bool)
		stubWebhookTransport(t, func(r *http.Request) (*http.Response, error) {
			now := time.Now()
			attemptTimes = append(attemptTimes, now)
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, target, r.URL.String())
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.JSONEq(t, `{"hello":"world"}`, string(body))

			id := r.Header.Get("webhook-id")
			require.NotEmpty(t, id)
			require.False(t, ids[id], "retry reused webhook ID %q", id)
			ids[id] = true
			timestamp := r.Header.Get("webhook-timestamp")
			require.Equal(t, strconv.FormatInt(now.Unix(), 10), timestamp)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(id + "." + timestamp + "."))
			mac.Write(body)
			require.Equal(t, "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)), r.Header.Get("webhook-signature"))

			switch len(attemptTimes) {
			case 1:
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": {"8"}},
					Body:       io.NopCloser(strings.NewReader("rate limited")),
				}, nil
			case 2:
				return nil, errors.New("connection reset")
			default:
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"code":0}`))}, nil
			}
		})

		require.NoError(t, Post(&Request{
			URL: target, Payload: map[string]string{"hello": "world"}, SigningSecret: secret,
		}))
		require.Len(t, attemptTimes, 3)
		require.GreaterOrEqual(t, attemptTimes[1].Sub(attemptTimes[0]), 8*time.Second)
		require.Less(t, attemptTimes[1].Sub(attemptTimes[0]), 12*time.Second)
		require.GreaterOrEqual(t, attemptTimes[2].Sub(attemptTimes[1]), 4*time.Second)
		require.Less(t, attemptTimes[2].Sub(attemptTimes[1]), 6*time.Second)
	})
}

func TestPostReturnsLastTransportErrorWithoutWaitingAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		failures := []error{
			errors.New("first connection failure"),
			errors.New("second connection failure"),
			errors.New("third connection failure"),
		}
		var attempts int
		var lastAttempt time.Time
		stubWebhookTransport(t, func(_ *http.Request) (*http.Response, error) {
			require.Less(t, attempts, len(failures), "delivery exceeded the retry limit")
			err := failures[attempts]
			attempts++
			lastAttempt = time.Now()
			return nil, err
		})

		err := Post(&Request{URL: "https://receiver.example/hook"})
		require.ErrorIs(t, err, failures[2])
		require.Equal(t, len(failures), attempts)
		require.Zero(t, time.Since(lastAttempt), "delivery should return immediately after the final failure")
	})
}

func TestPostStopsOnFinalResponseAfterRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		err    string
	}{
		{name: "client error", status: http.StatusBadRequest, body: "bad request", err: "status code: 400"},
		{name: "application rejection", status: http.StatusOK, body: `{"code":7,"message":"rejected"}`, err: "code 7, msg: rejected"},
		{name: "invalid JSON", status: http.StatusOK, body: "not JSON", err: "failed to unmarshal webhook response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var attempts int
				stubWebhookTransport(t, func(_ *http.Request) (*http.Response, error) {
					attempts++
					switch attempts {
					case 1:
						return &http.Response{
							StatusCode: http.StatusServiceUnavailable,
							Body:       io.NopCloser(strings.NewReader("try again")),
						}, nil
					case 2:
						return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
					default:
						t.Fatal("delivery retried a final response")
						return nil, nil
					}
				})

				err := Post(&Request{URL: "https://receiver.example/hook"})
				require.ErrorContains(t, err, tc.err)
				require.Equal(t, 2, attempts)
			})
		})
	}
}

func TestRetryDelay(t *testing.T) {
	for _, tc := range []struct {
		name       string
		attempt    int
		retryAfter string
		wantBase   time.Duration
	}{
		{name: "first retry", wantBase: 2 * time.Second},
		{name: "second retry doubles the backoff", attempt: 1, wantBase: 4 * time.Second},
		{name: "whole seconds override the backoff", attempt: 1, retryAfter: "1", wantBase: time.Second},
		{name: "HTTP date falls back to exponential backoff", attempt: 1, retryAfter: "Wed, 21 Oct 2026 07:28:00 GMT", wantBase: 4 * time.Second},
		{name: "negative seconds fall back to exponential backoff", attempt: 1, retryAfter: "-1", wantBase: 4 * time.Second},
		{name: "fractional seconds fall back to exponential backoff", attempt: 1, retryAfter: "0.5", wantBase: 4 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delay := retryDelay(tc.attempt, tc.retryAfter)
			require.GreaterOrEqual(t, delay, tc.wantBase)
			require.Less(t, delay, tc.wantBase+tc.wantBase/2)
		})
	}
}
