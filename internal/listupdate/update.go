// Package listupdate downloads a single list and replaces it only after validation.
package listupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"personal-blocker/internal/rules"
)

const DefaultURL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt"
const MaxBytes int64 = 16 << 20

type Result struct {
	Domains int
	Bytes   int
	SHA256  string
}

// Update enforces HTTPS (including redirects), a total timeout and a decoded-body
// size limit. A failed download or validation leaves the destination unchanged.
func Update(ctx context.Context, source, destination string, timeout time.Duration) (Result, error) {
	if timeout <= 0 {
		return Result{}, fmt.Errorf("timeout must be positive")
	}
	client := &http.Client{Timeout: timeout}
	client.CheckRedirect = checkRedirect
	return update(ctx, client, source, destination)
}
func validateURL(u *url.URL) error {
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("list source must be an HTTPS URL without credentials")
	}
	return nil
}
func update(ctx context.Context, client *http.Client, source, destination string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return Result{}, err
	}
	if err = validateURL(req.URL); err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "personal-blocker/1")
	response, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("download returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > MaxBytes {
		return Result{}, fmt.Errorf("list exceeds %d bytes", MaxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
	if err != nil {
		return Result{}, err
	}
	if int64(len(data)) > MaxBytes {
		return Result{}, fmt.Errorf("list exceeds %d bytes", MaxBytes)
	}
	var warning string
	entries, err := rules.Parse(bytes.NewReader(data), source, func(s string) {
		if warning == "" {
			warning = s
		}
	})
	if err != nil {
		return Result{}, err
	}
	if warning != "" {
		return Result{}, fmt.Errorf("invalid list: %s", warning)
	}
	if len(entries) == 0 {
		return Result{}, fmt.Errorf("refusing an empty downloaded list")
	}
	// Never replace a symlink or special file. Rename would replace the link itself,
	// but rejecting it avoids surprising the user about where their list lives.
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() {
			return Result{}, fmt.Errorf("destination is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return Result{}, err
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".personal-blocker-list-*")
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err = temp.Write(data); err != nil {
		return Result{}, err
	}
	if err = temp.Chmod(0644); err != nil {
		return Result{}, err
	}
	if err = temp.Sync(); err != nil {
		return Result{}, err
	}
	if err = temp.Close(); err != nil {
		return Result{}, err
	}
	if err = ctx.Err(); err != nil {
		return Result{}, err
	}
	if err = os.Rename(temp.Name(), destination); err != nil {
		return Result{}, err
	}
	return Result{len(entries), len(data), fmt.Sprintf("%x", sha256.Sum256(data))}, nil
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("too many redirects")
	}
	return validateURL(req.URL)
}
