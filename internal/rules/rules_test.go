package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	for _, s := range []string{" doubleclick.net ", "DoubleClick.NET.", "doubleclick.net"} {
		v, e := Normalize(s)
		if e != nil || v != "doubleclick.net" {
			t.Fatalf("%q: %q %v", s, v, e)
		}
	}
	for _, s := range []string{"", ".", "bad..com", "-bad.com", "bad_.com", "127.0.0.1", "https://foo.com"} {
		if _, e := Normalize(s); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
func TestDecide(t *testing.T) {
	e := &Engine{allow: map[string]Source{"safe.doubleclick.net": {Domain: "safe.doubleclick.net"}}, block: map[string]Source{"doubleclick.net": {Domain: "doubleclick.net"}}}
	for _, tc := range []struct {
		host  string
		block bool
	}{{"doubleclick.net", true}, {"ads.doubleclick.net", true}, {"stats.ads.doubleclick.net", true}, {"notdoubleclick.net", false}, {"doubleclick.net.evil.com", false}, {"DoubleClick.NET.", true}, {"safe.doubleclick.net", false}, {"a.safe.doubleclick.net", false}} {
		b, _ := e.Decide(tc.host)
		if b != tc.block {
			t.Errorf("%s: got %v", tc.host, b)
		}
	}
}
func TestParse(t *testing.T) {
	var warnings []string
	m, e := Parse(strings.NewReader("\n# comment\nDoubleClick.NET. # inline\n0.0.0.0 a.example b.example\n127.0.0.1 tracker.example\n:: ipv6.example\n||bad.example^\ninvalid extra\n"), "list", func(s string) { warnings = append(warnings, s) })
	if e != nil || len(m) != 5 || len(warnings) != 2 {
		t.Fatalf("%v %v %v", m, warnings, e)
	}
	if m["doubleclick.net"].Line != 3 {
		t.Fatal("lost source line")
	}
	empty, e := Parse(strings.NewReader(""), "empty", nil)
	if e != nil || len(empty) != 0 {
		t.Fatal("empty list failed")
	}
}
func TestLoad(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "rules")
	if err := os.WriteFile(path, []byte("example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := Load([]string{path}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := e.Decide("example.com"); b {
		t.Fatal("allow must win")
	}
	if _, err = Load([]string{filepath.Join(d, "missing")}, nil, nil); err == nil {
		t.Fatal("missing file accepted")
	}
}
