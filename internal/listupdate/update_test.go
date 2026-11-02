package listupdate

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateValidationAndReplacement(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		good       bool
	}{
		{"domains", "# header\nExample.COM\ntracker.example\n", 200, true},
		{"hosts", "0.0.0.0 tracker.example\n", 200, true},
		{"empty", "# empty", 200, false}, {"malformed", "tracker.example\n||ad.example^", 200, false},
		{"html", "<html>not a list</html>", 200, false}, {"http_error", "tracker.example", 500, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer s.Close()
			path := filepath.Join(t.TempDir(), "list")
			os.WriteFile(path, []byte("original.example\n"), 0644)
			result, err := update(context.Background(), s.Client(), s.URL, path)
			if (err == nil) != tc.good {
				t.Fatalf("%+v %v", result, err)
			}
			data, _ := os.ReadFile(path)
			want := "original.example\n"
			if tc.good {
				want = tc.body
				if result.Domains == 0 || len(result.SHA256) != 64 {
					t.Fatal(result)
				}
			}
			if string(data) != want {
				t.Fatalf("destination changed incorrectly: %q", data)
			}
			files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".personal-blocker-list-*"))
			if len(files) != 0 {
				t.Fatal("temp file leaked")
			}
		})
	}
}
func TestSizeLimit(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		chunk := strings.Repeat("a", 1<<20)
		for i := 0; i < 17; i++ {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	}))
	defer s.Close()
	path := filepath.Join(t.TempDir(), "list")
	if _, err := update(context.Background(), s.Client(), s.URL, path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("created invalid file")
	}
}
func TestCancellationAndHTTPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Update(ctx, DefaultURL, filepath.Join(t.TempDir(), "list"), time.Second); err == nil {
		t.Fatal("accepted cancellation")
	}
	if _, err := Update(context.Background(), "http://example.com/list", "unused", time.Second); err == nil {
		t.Fatal("accepted HTTP")
	}
	if _, err := Update(context.Background(), DefaultURL, "unused", 0); err == nil {
		t.Fatal("accepted zero timeout")
	}
}
func TestSymlink(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "tracker.example\n") }))
	defer s.Close()
	d := t.TempDir()
	target := filepath.Join(d, "target")
	os.WriteFile(target, []byte("original.example"), 0644)
	link := filepath.Join(d, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := update(context.Background(), s.Client(), s.URL, link); err == nil {
		t.Fatal("accepted symlink")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "original.example" {
		t.Fatal("target changed")
	}
}

func TestTimeoutAndRedirectPolicy(t *testing.T) {
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	client := slow.Client()
	client.Timeout = 30 * time.Millisecond
	if _, err := update(context.Background(), client, slow.URL, filepath.Join(t.TempDir(), "list")); err == nil {
		t.Fatal("expected timeout")
	}
	// Use the production Update client: plain HTTP is rejected before any request.
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1/untrusted", http.StatusFound)
	}))
	defer redirect.Close()
	client = redirect.Client()
	client.CheckRedirect = checkRedirect
	if _, err := update(context.Background(), client, redirect.URL, filepath.Join(t.TempDir(), "list")); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("downgrade accepted: %v", err)
	}
	loop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/again", http.StatusFound) }))
	defer loop.Close()
	client = loop.Client()
	client.CheckRedirect = checkRedirect
	if _, err := update(context.Background(), client, loop.URL, filepath.Join(t.TempDir(), "list")); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("redirect limit: %v", err)
	}
}
