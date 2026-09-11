package runtimemeasure

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// foldingNode gives the temp-file register the kernel's append-only semantics:
// the TSM node folds a write into the current value, while a plain file
// replaces it. Reusing one node and one journal path across two OpenJournal
// calls is a daemon restart inside a still-running guest.
type foldingNode struct {
	Register
	extends int
	fail    error
}

func (n *foldingNode) Extend(event []byte) error {
	if n.fail != nil {
		return n.fail
	}
	cur, err := n.Extension()
	if err != nil {
		return err
	}
	var reg, ev [Size]byte
	copy(reg[:], cur)
	copy(ev[:], event)
	next := Extend(reg, ev)
	if err := n.Register.Extend(next[:]); err != nil {
		return err
	}
	n.extends++
	return nil
}

// newNode fakes the TSM node at path, holding initial.
func newNode(t *testing.T, path string, initial [Size]byte) *foldingNode {
	t.Helper()
	if err := os.WriteFile(path, initial[:], 0o600); err != nil {
		t.Fatalf("seed register file: %v", err)
	}
	return &foldingNode{Register: TDXRegister(path)}
}

// journalPaths returns a register node path and a journal path under one temp
// dir, so a test can reopen the same pair.
func journalPaths(t *testing.T) (nodePath, journalPath string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "rtmr3:sha384"), filepath.Join(dir, "state", "measured")
}

func mustOpen(t *testing.T, path string, reg Register) *Journal {
	t.Helper()
	j, err := OpenJournal(path, reg)
	if err != nil {
		t.Fatalf("OpenJournal = _, %v", err)
	}
	return j
}

func mustMeasure(t *testing.T, j *Journal, ref string, want bool) {
	t.Helper()
	extended, err := j.MeasureOnce(ref)
	if err != nil {
		t.Fatalf("MeasureOnce(%q) = _, %v", ref, err)
	}
	if extended != want {
		t.Fatalf("MeasureOnce(%q) = %v, want %v", ref, extended, want)
	}
}

func registerValue(t *testing.T, node *foldingNode) [Size]byte {
	t.Helper()
	b, err := node.Extension()
	if err != nil {
		t.Fatalf("read register: %v", err)
	}
	var reg [Size]byte
	copy(reg[:], b)
	return reg
}

// A first boot has no journal file: the directory is created, nothing is
// extended, and the first measurement lands.
func TestOpenJournalFreshBoot(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, Zero)

	j := mustOpen(t, journalPath, node)
	if got := j.Digests(); len(got) != 0 {
		t.Fatalf("Digests() = %v, want none", got)
	}
	if node.extends != 0 {
		t.Fatalf("extends = %d, want 0", node.extends)
	}

	mustMeasure(t, j, digestA, true)
	if want := FromDigests([]string{digestA}); registerValue(t, node) != want {
		t.Error("register does not match the single-extend fold")
	}
	if got := j.Digests(); !slices.Equal(got, []string{digestA}) {
		t.Errorf("Digests() = %v, want [%s]", got, digestA)
	}
	b, err := os.ReadFile(journalPath)
	if err != nil || string(b) != digestA+"\n" {
		t.Errorf("journal file = %q, %v; want %q", b, err, digestA+"\n")
	}
}

// A restart whose register already matches the journal re-extends nothing and
// keeps every recorded digest deduped.
func TestJournalCleanRestart(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, Zero)

	first := mustOpen(t, journalPath, node)
	mustMeasure(t, first, digestA, true)
	mustMeasure(t, first, digestB, true)

	second := mustOpen(t, journalPath, node)
	if node.extends != 2 {
		t.Fatalf("extends = %d after restart, want 2 (a clean restart repairs nothing)", node.extends)
	}
	if got := second.Digests(); !slices.Equal(got, []string{digestA, digestB}) {
		t.Fatalf("Digests() = %v, want [%s %s]", got, digestA, digestB)
	}
	mustMeasure(t, second, digestA, false)
	mustMeasure(t, second, digestB, false)
	if node.extends != 2 {
		t.Fatalf("extends = %d, want 2 (journaled digests must never re-extend)", node.extends)
	}
}

// Crash after recording a digest but before the extend landed: the journal
// names a digest the register lacks, and opening finishes that one extend.
func TestJournalRepairsInterruptedExtend(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, Zero) // the extend never ran
	writeJournal(t, journalPath, digestA+"\n")

	j := mustOpen(t, journalPath, node)
	if node.extends != 1 {
		t.Fatalf("extends = %d, want 1 (startup repair)", node.extends)
	}
	if want := FromDigests([]string{digestA}); registerValue(t, node) != want {
		t.Error("register does not match the repaired fold")
	}
	mustMeasure(t, j, digestA, false)
	if node.extends != 1 {
		t.Fatalf("extends = %d, want 1 (the repaired digest must not extend again)", node.extends)
	}
}

// A repair that cannot be completed is fatal: running on with a register one
// extend behind the journal would measure every later workload onto a value no
// verifier can reproduce.
func TestJournalRepairFailureIsFatal(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, Zero)
	node.fail = errors.New("sysfs write failed")
	writeJournal(t, journalPath, digestA+"\n")

	j, err := OpenJournal(journalPath, node)
	if err == nil {
		t.Fatal("OpenJournal = _, nil; want an error when the repair extend fails")
	}
	if j != nil {
		t.Error("OpenJournal returned a journal alongside a failed repair")
	}
}

// A register matching neither fold carries a foreign extend. It is reported,
// never "repaired" by extending again, and it stops all further measurement.
func TestJournalDivergenceRefusesToExtend(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, FromDigests([]string{digestB}))
	writeJournal(t, journalPath, digestA+"\n")

	j, err := OpenJournal(journalPath, node)
	if !errors.Is(err, ErrRegisterDiverged) {
		t.Fatalf("OpenJournal = _, %v, want ErrRegisterDiverged", err)
	}
	if j == nil {
		t.Fatal("OpenJournal returned no journal; a caller must be able to log and keep polling")
	}
	if node.extends != 0 {
		t.Fatalf("extends = %d, want 0", node.extends)
	}
	for _, ref := range []string{digestA, digestB} {
		if _, err := j.MeasureOnce(ref); !errors.Is(err, ErrRegisterDiverged) {
			t.Errorf("MeasureOnce(%q) = _, %v, want ErrRegisterDiverged", ref, err)
		}
	}
	if node.extends != 0 {
		t.Fatalf("extends = %d, want 0 (a diverged register must never be extended)", node.extends)
	}
}

// Lines that are not canonical digests are skipped and reported: a partial
// last line is what a crash mid-append leaves, and refusing to open would stop
// the guest measuring anything for the rest of the boot.
func TestJournalSkipsMalformedLines(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, FromDigests([]string{digestA}))
	writeJournal(t, journalPath, strings.Join([]string{
		digestA,
		"not-a-digest",
		"sha256:tooshort",
		"",
		"sha256:" + strings.ToUpper(strings.TrimPrefix(digestB, "sha256:")),
		"ghcr.io/example/app@" + digestB, // the file holds canonical digests only
		digestA,                          // duplicate
	}, "\n")+"\n")

	j, err := OpenJournal(journalPath, node)
	if !errors.Is(err, ErrMalformedEntry) {
		t.Fatalf("OpenJournal = _, %v, want ErrMalformedEntry", err)
	}
	if errors.Is(err, ErrRegisterDiverged) {
		t.Fatalf("OpenJournal = _, %v; the surviving line folds to the register", err)
	}
	if got := j.Digests(); !slices.Equal(got, []string{digestA}) {
		t.Fatalf("Digests() = %v, want exactly [%s]", got, digestA)
	}
	if node.extends != 0 {
		t.Fatalf("extends = %d, want 0", node.extends)
	}
}

// The finding the journal exists for: a daemon restart inside a still-running
// guest must not re-extend what the previous process measured, whichever
// spelling of the image it is handed.
func TestMeasureOnceDedupsAcrossRestarts(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, Zero)

	first := mustOpen(t, journalPath, node)
	mustMeasure(t, first, digestA, true)

	second := mustOpen(t, journalPath, node)
	mustMeasure(t, second, digestA, false)
	mustMeasure(t, second, "ghcr.io/example/app@"+digestA, false)
	mustMeasure(t, second, digestB, true)

	if node.extends != 2 {
		t.Fatalf("extends = %d, want 2", node.extends)
	}
	if want := FromDigests([]string{digestA, digestB}); registerValue(t, node) != want {
		t.Error("register does not match the two-extend fold")
	}
}

// A failed extend rolls the record back, so the journal keeps matching the
// register and the image is retried instead of being lost.
func TestMeasureOnceExtendFailureRollsBack(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, Zero)
	node.fail = errors.New("sysfs write failed")

	j := mustOpen(t, journalPath, node)
	extended, err := j.MeasureOnce(digestA)
	if err == nil || extended {
		t.Fatalf("MeasureOnce = %v, %v; want false and the extend error", extended, err)
	}
	if got := j.Digests(); len(got) != 0 {
		t.Fatalf("Digests() = %v, want none after the rollback", got)
	}
	if b, err := os.ReadFile(journalPath); err != nil || len(b) != 0 {
		t.Fatalf("journal file = %q, %v; want empty after the rollback", b, err)
	}

	node.fail = nil
	mustMeasure(t, j, digestA, true)
	if want := FromDigests([]string{digestA}); registerValue(t, node) != want {
		t.Error("register does not match the fold after the retry")
	}
}

// A reference that names no digest is refused before anything is written: an
// unpinned image cannot be measured, and a tag is not an identity.
func TestMeasureOnceRejectsUnpinnedReference(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	node := newNode(t, nodePath, Zero)
	j := mustOpen(t, journalPath, node)

	if _, err := j.MeasureOnce("ghcr.io/example/app:latest"); err == nil {
		t.Fatal("MeasureOnce(tag) = _, nil; want an error")
	}
	if node.extends != 0 || len(j.Digests()) != 0 {
		t.Fatalf("extends = %d, Digests() = %v; want 0 and none", node.extends, j.Digests())
	}
}

// A guest launched with an anchor reads back Seed(anchor) before anything is
// measured, so the seed must be folded in or every restart reads as divergence.
func TestOpenJournalSeeded(t *testing.T) {
	nodePath, journalPath := journalPaths(t)
	seed := Seed([]byte("anchor-bytes-v1\n"))
	node := newNode(t, nodePath, seed)

	j, err := openJournalSeeded(journalPath, node, seed)
	if err != nil {
		t.Fatalf("openJournalSeeded = _, %v", err)
	}
	mustMeasure(t, j, digestA, true)
	if want := FromDigestsSeeded(seed, []string{digestA}); registerValue(t, node) != want {
		t.Error("register does not match the seeded fold")
	}

	if _, err := openJournalSeeded(journalPath, node, seed); err != nil {
		t.Fatalf("seeded restart = _, %v, want a clean restart", err)
	}
	// The same guest opened as if it booted from Zero: the seed is unaccounted
	// for, which is exactly the shape of a foreign extend.
	if _, err := OpenJournal(journalPath, node); !errors.Is(err, ErrRegisterDiverged) {
		t.Fatalf("unseeded open of a seeded register = _, %v, want ErrRegisterDiverged", err)
	}
}

// An unreadable register cannot arbitrate, so the journal stays the dedup
// truth and the problem is reported rather than treated as divergence.
func TestOpenJournalRegisterUnreadable(t *testing.T) {
	_, journalPath := journalPaths(t)
	writeJournal(t, journalPath, digestA+"\n")
	missing := TDXRegister(filepath.Join(t.TempDir(), "absent"))

	j, err := OpenJournal(journalPath, missing)
	if err == nil {
		t.Fatal("OpenJournal = _, nil; an unreadable register must be reported")
	}
	if errors.Is(err, ErrRegisterDiverged) {
		t.Fatalf("OpenJournal = _, %v; an unreadable register is not divergence", err)
	}
	if j == nil {
		t.Fatal("OpenJournal returned no journal")
	}
	if got := j.Digests(); !slices.Equal(got, []string{digestA}) {
		t.Fatalf("Digests() = %v, want [%s]", got, digestA)
	}
}

func TestOpenJournalRejectsNilRegister(t *testing.T) {
	_, journalPath := journalPaths(t)
	if _, err := OpenJournal(journalPath, nil); err == nil {
		t.Fatal("OpenJournal(nil register) = _, nil; want an error")
	}
}

func writeJournal(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
