package rtorrent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/icholy/digest"
)

// digestRtorrent is a ruTorrent-style endpoint that only accepts HTTP Digest
// (realm="ruTorrent", qop="auth", algorithm=MD5) and rejects Basic with a 401
// carrying a Digest challenge.
type digestRtorrent struct {
	*httptest.Server
	mu         sync.Mutex
	basicTries int // requests that carried a Basic Authorization header
	unauthed   int // requests with no credentials at all
	digestOK   int // requests that passed Digest verification
	bodies     []string
}

func newDigestRtorrent(t *testing.T, user, pass string) *digestRtorrent {
	t.Helper()
	d := &digestRtorrent{}
	const nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("Authorization")

		d.mu.Lock()
		defer d.mu.Unlock()
		challenge := func() {
			w.Header().Add("WWW-Authenticate", `Digest realm="ruTorrent", qop="auth", algorithm=MD5, nonce="`+nonce+`", opaque="5ccc069c403ebaf9f0171e9517f40e41"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
		switch {
		case auth == "":
			d.unauthed++
			challenge()
			return
		case strings.HasPrefix(auth, "Basic "):
			d.basicTries++
			challenge()
			return
		}
		creds, err := digest.ParseCredentials(auth)
		if err != nil {
			challenge()
			return
		}
		want, err := digest.Digest(&digest.Challenge{
			Realm: "ruTorrent", Nonce: nonce, Algorithm: "MD5", QOP: []string{"auth"},
		}, digest.Options{
			Method: r.Method, URI: r.URL.RequestURI(), Count: creds.Nc, Cnonce: creds.Cnonce,
			Username: user, Password: pass,
		})
		if err != nil || creds.Response != want.Response || creds.Username != user || creds.URI != r.URL.RequestURI() {
			challenge()
			return
		}
		d.digestOK++
		d.bodies = append(d.bodies, string(body))
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, stringResponse("0.9.8"))
	}))
	t.Cleanup(d.Close)
	return d
}

func newDigestTestClient(t *testing.T, endpoint, user, pass string) *Client {
	t.Helper()
	c := newTestClient(t, endpoint)
	c.username, c.password = user, pass
	// newTestClient swaps the endpoint in after New, so the transport is the
	// guarded production one, which refuses loopback. Use a plain transport.
	c.http.Transport = http.DefaultTransport
	return c
}

func TestDigestAuth(t *testing.T) {
	for _, path := range []string{"/RPC2", "/rutorrent/plugins/httprpc/action.php"} {
		t.Run(path, func(t *testing.T) {
			srv := newDigestRtorrent(t, "seedbox", "s3cret")
			c := newDigestTestClient(t, srv.URL+path, "seedbox", "s3cret")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			v, err := c.Version(ctx)
			if err != nil {
				t.Fatalf("system.client_version over Digest: %v", err)
			}
			if v != "0.9.8" {
				t.Fatalf("version = %q, want 0.9.8", v)
			}
			// The body must survive the 401 round trip intact.
			if len(srv.bodies) != 1 || !strings.Contains(srv.bodies[0], "<methodName>system.client_version</methodName>") {
				t.Fatalf("server saw bodies %q, want one system.client_version call", srv.bodies)
			}
			if srv.basicTries != 1 {
				t.Fatalf("basic attempts = %d, want exactly 1 (Basic first, then Digest)", srv.basicTries)
			}
			if !c.digestMode.Load() {
				t.Fatal("digest scheme was not cached after a successful retry")
			}

			// Later calls skip the Basic attempt entirely.
			if _, err := c.Version(ctx); err != nil {
				t.Fatalf("second call: %v", err)
			}
			if srv.basicTries != 1 {
				t.Fatalf("basic attempts after cached call = %d, want still 1", srv.basicTries)
			}
			if srv.digestOK != 2 {
				t.Fatalf("digest-verified requests = %d, want 2", srv.digestOK)
			}
		})
	}
}

func TestDigestAuthWrongPassword(t *testing.T) {
	srv := newDigestRtorrent(t, "seedbox", "s3cret")
	c := newDigestTestClient(t, srv.URL+"/RPC2", "seedbox", "nope")
	_, err := c.Version(context.Background())
	if err == nil {
		t.Fatal("expected an error for a wrong password")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Digest") {
		t.Fatalf("error should mention 401 and Digest, got: %v", err)
	}
	if c.digestMode.Load() {
		t.Fatal("digest scheme must not be cached after a failed login")
	}
}

func TestBasicOnly401DoesNotMentionDigest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := newDigestTestClient(t, srv.URL+"/RPC2", "u", "p")
	_, err := c.Version(context.Background())
	if err == nil || strings.Contains(err.Error(), "Digest") {
		t.Fatalf("want a Digest-free 401 error, got %v", err)
	}
}

func TestOffersDigest(t *testing.T) {
	cases := []struct {
		vals []string
		want bool
	}{
		{nil, false},
		{[]string{`Basic realm="x"`}, false},
		{[]string{`Digest realm="x"`}, true},
		{[]string{`digest realm="x"`}, true},
		{[]string{`Basic realm="x"`, `Digest realm="x"`}, true},
	}
	for _, tc := range cases {
		h := http.Header{}
		for _, v := range tc.vals {
			h.Add("WWW-Authenticate", v)
		}
		if got := offersDigest(h); got != tc.want {
			t.Errorf("offersDigest(%q) = %v, want %v", tc.vals, got, tc.want)
		}
	}
}
