package main

// These are offline compatibility regressions for upgraded build/tool
// dependencies, not a substitute for advisory or binary vulnerability scans.
import (
	"bytes"
	"crypto/elliptic"
	"image"
	"image/color"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/ecc/p384"
	"github.com/go-git/go-billy/v5/osfs"
	git "github.com/go-git/go-git/v5"
	"github.com/sirupsen/logrus"
	"golang.org/x/image/tiff"
)

func TestDependencyGitWorktreeRoundTrip(t *testing.T) {
	repo, err := git.PlainInit(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	file, err := worktree.Filesystem.Create("fixture.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("NHDD offline dependency fixture\n")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = worktree.Add("fixture.txt"); err != nil {
		t.Fatal(err)
	}
	status, err := worktree.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.File("fixture.txt").Staging != git.Added {
		t.Fatal("Git worktree no longer reports the staged fixture")
	}
}

func TestDependencyBillyBoundFilesystem(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside.txt")
	const sentinel = "outside fixture must remain unchanged"
	if err := os.WriteFile(outside, []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	fs := osfs.New(filepath.Join(root, "bounded"), osfs.WithBoundOS())
	file, err := fs.Create("safe.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	// BoundOS may reject a traversal or normalize it inside the root. Either
	// behavior must leave the real file outside the bound filesystem untouched.
	if candidate, err := fs.Create("../outside.txt"); err == nil {
		if _, err := candidate.Write([]byte("bounded fixture")); err != nil {
			candidate.Close()
			t.Fatal(err)
		}
		if err := candidate.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != sentinel {
		t.Fatal("Bound filesystem modified a file outside its root")
	}
}

func TestDependencyTIFFRoundTrip(t *testing.T) {
	source := image.NewRGBA(image.Rect(0, 0, 2, 2))
	source.SetRGBA(1, 1, color.RGBA{R: 40, G: 120, B: 200, A: 255})
	var encoded bytes.Buffer
	if err := tiff.Encode(&encoded, source, &tiff.Options{Compression: tiff.Deflate}); err != nil {
		t.Fatal(err)
	}
	decoded, err := tiff.Decode(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Bounds() != source.Bounds() {
		t.Fatal("TIFF dimensions changed")
	}
	if color.RGBAModel.Convert(decoded.At(1, 1)) != source.RGBAAt(1, 1) {
		t.Fatal("TIFF pixel changed")
	}
}

func TestDependencyP384CombinedMultMatchesStandardLibrary(t *testing.T) {
	standard, optimized := elliptic.P384(), p384.P384()
	qx, qy := standard.ScalarBaseMult([]byte{13})
	nearOrder := new(big.Int).Sub(standard.Params().N, big.NewInt(1)).Bytes()
	for _, scalars := range [][2][]byte{
		{{1}, {1}}, {{13}, {7}}, {nearOrder, {1}},
		{bytes.Repeat([]byte{0x80}, 48), bytes.Repeat([]byte{0x55}, 48)},
	} {
		x1, y1 := standard.ScalarBaseMult(scalars[0])
		x2, y2 := standard.ScalarMult(qx, qy, scalars[1])
		wantX, wantY := standard.Add(x1, y1, x2, y2)
		gotX, gotY := optimized.CombinedMult(qx, qy, scalars[0], scalars[1])
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatal("P-384 combined multiplication differs from the standard library")
		}
	}
}

type dependencyLogSink struct{ lines chan string }

func (sink dependencyLogSink) Write(data []byte) (int, error) {
	sink.lines <- string(data)
	return len(data), nil
}

func TestDependencyLogrusEntryWriterCompletes(t *testing.T) {
	logger := logrus.New()
	sink := dependencyLogSink{lines: make(chan string, 1)}
	logger.SetOutput(sink)
	logger.SetFormatter(&logrus.JSONFormatter{DisableTimestamp: true})
	writer := logger.WithField("component", "offline-fixture").Writer()
	t.Cleanup(func() { writer.Close() })
	if _, err := writer.Write([]byte("NHDD fixture message\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-sink.lines:
		if !strings.Contains(line, "NHDD fixture message") || !strings.Contains(line, "offline-fixture") {
			t.Fatal("Structured log fields or message lost")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Logrus Entry.Writer did not complete")
	}
}
