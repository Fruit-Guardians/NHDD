//go:build contract

// Contract test: runs the Go repair pipelines (dexfix.go / sofix.go) over a
// fixture work dir and writes a classification JSON for tests/contract/compare.py.
//
// Run from gui/: go test -tags contract -run TestContractFixtures -count=1 ./
// Env: NHDD_CONTRACT_IN (dir with dex/ and so/), NHDD_CONTRACT_MANIFEST, NHDD_CONTRACT_OUT.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type cFixture struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	OrigSha256 string `json:"orig_sha256"`
}

type cManifest struct {
	Fixtures []cFixture `json:"fixtures"`
}

type cResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Sha256 string `json:"sha256"`
	Where  string `json:"where"`
}

func sha256Path(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestContractFixtures(t *testing.T) {
	in := os.Getenv("NHDD_CONTRACT_IN")
	manifestPath := os.Getenv("NHDD_CONTRACT_MANIFEST")
	out := os.Getenv("NHDD_CONTRACT_OUT")
	if in == "" || manifestPath == "" || out == "" {
		t.Fatal("NHDD_CONTRACT_IN / _MANIFEST / _OUT must be set")
	}

	if _, err := FixDexDirectory(filepath.Join(in, "dex")); err != nil {
		t.Fatalf("FixDexDirectory: %v", err)
	}
	if _, err := FixSoDirectory(filepath.Join(in, "so")); err != nil {
		t.Fatalf("FixSoDirectory: %v", err)
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var man cManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("manifest json: %v", err)
	}

	results := make([]cResult, 0, len(man.Fixtures))
	for _, fx := range man.Fixtures {
		sub := "so"
		if fx.Kind == "dex" {
			sub = "dex"
		}
		d := filepath.Join(in, sub)
		inplace := filepath.Join(d, fx.Name)
		quarantined := filepath.Join(d, "bad", fx.Name)
		var r cResult
		r.Name = fx.Name
		switch {
		case fileExists(inplace):
			r.Sha256 = sha256Path(inplace)
			r.Where = "inplace"
			if r.Sha256 == fx.OrigSha256 {
				r.Status = "OK"
			} else {
				r.Status = "FIXED"
			}
		case fileExists(quarantined):
			r.Status = "BAD"
			r.Sha256 = sha256Path(quarantined)
			r.Where = "bad/"
		default:
			r.Status = "MISSING"
		}
		results = append(results, r)
	}

	payload, err := json.MarshalIndent(map[string]any{
		"impl": "go", "results": results,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, payload, 0644); err != nil {
		t.Fatal(err)
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
