// Package rules loads domain lists and applies allow-first suffix matching.
package rules

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

type Source struct {
	File   string
	Line   int
	Domain string
}
type Engine struct{ allow, block map[string]Source }

func Normalize(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil {
		return "", fmt.Errorf("invalid domain %q", s)
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", s)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid domain %q", s)
			}
		}
	}
	return s, nil
}

func Parse(r io.Reader, filename string, warn func(string)) (map[string]Source, error) {
	result := map[string]Source{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for line := 1; scanner.Scan(); line++ {
		fields := strings.Fields(strings.SplitN(scanner.Text(), "#", 2)[0])
		if len(fields) == 0 {
			continue
		}
		if net.ParseIP(fields[0]) != nil {
			fields = fields[1:]
		} else if len(fields) != 1 {
			if warn != nil {
				warn(fmt.Sprintf("%s:%d: expected a domain or hosts-file entry", filename, line))
			}
			continue
		}
		if len(fields) == 0 && warn != nil {
			warn(fmt.Sprintf("%s:%d: missing hostname", filename, line))
		}
		for _, field := range fields {
			domain, err := Normalize(field)
			if err != nil {
				if warn != nil {
					warn(fmt.Sprintf("%s:%d: %v", filename, line, err))
				}
				continue
			}
			result[domain] = Source{filename, line, domain}
		}
	}
	return result, scanner.Err()
}

func Load(blockPaths, allowPaths []string, warn func(string)) (*Engine, error) {
	e := &Engine{map[string]Source{}, map[string]Source{}}
	for i, paths := range [][]string{allowPaths, blockPaths} {
		target := e.allow
		if i == 1 {
			target = e.block
		}
		for _, path := range paths {
			f, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("load rules: %w", err)
			}
			entries, err := Parse(f, path, warn)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			for domain, source := range entries {
				target[domain] = source
			}
		}
	}
	return e, nil
}
func match(host string, entries map[string]Source) (Source, bool) {
	for {
		if s, ok := entries[host]; ok {
			return s, true
		}
		i := strings.IndexByte(host, '.')
		if i < 0 {
			return Source{}, false
		}
		host = host[i+1:]
	}
}

// Decide returns whether the name is blocked and the most specific matching source.
func (e *Engine) Decide(host string) (bool, Source) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if source, ok := match(host, e.allow); ok {
		return false, source
	}
	source, ok := match(host, e.block)
	return ok, source
}

// LoadStrict is used for reload: malformed input must not silently remove rules.
// Deliberately empty local files remain valid.
func LoadStrict(blockPaths, allowPaths []string) (*Engine, error) {
	var first string
	e, err := Load(blockPaths, allowPaths, func(s string) {
		if first == "" {
			first = s
		}
	})
	if err != nil {
		return nil, err
	}
	if first != "" {
		return nil, fmt.Errorf("invalid rules: %s", first)
	}
	return e, nil
}
