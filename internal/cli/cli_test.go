package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommands(t *testing.T) {
	p := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(p, []byte("doubleclick.net"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, logs bytes.Buffer
	args := []string{"test", "--blocklists", p, "--allowlists=", "Ads.DoubleClick.NET."}
	if err := Execute(context.Background(), args, &out, &logs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "BLOCK ads.doubleclick.net matched=doubleclick.net") {
		t.Fatal(out.String())
	}
	for _, args := range [][]string{nil, {"unknown"}, {"test"}, {"run", "--blocklists", p, "--allowlists=", "--timeout=0"}, {"run", "--blocklists", p, "--allowlists=", "--upstreams=bad"}} {
		if Execute(context.Background(), args, &out, &logs) == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
