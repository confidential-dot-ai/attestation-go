package runtimemeasure

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ErrRegisterDiverged reports that the register folds to neither the journal
// nor the journal without its last entry, so something outside the journal
// extended it. An extend cannot be undone, so no later extend repairs the
// register and the journal can no longer predict it. A diverged [Journal]
// refuses to extend rather than adding events to a value no verifier
// accepts.
var ErrRegisterDiverged = errors.New("runtime measurement register does not match the journal")

// ErrMalformedEntry reports that the journal file held a line that is not a
// canonical digest. Such a line is skipped, not fatal: a crash during the
// append can leave a partial last line, which was by construction never
// extended, and refusing to open would stop the guest measuring anything for
// the rest of the boot.
var ErrMalformedEntry = errors.New("journal line is not a canonical digest")

// Journal makes register extends exactly-once across process restarts.
//
// A runtime measurement register is append-only: extending the same image
// twice yields a register no verifier expecting one extend can match, and
// nothing undoes it. An in-guest measurer therefore cannot hold its
// already-extended set in memory, where a restart loses it. Journal keeps that
// set on disk as one canonical digest per line, in extend order.
//
// The write order is record-then-extend, so a crash between the two leaves the
// register at most one extend behind the journal, which [OpenJournal] repairs
// by replaying that extend. The opposite order would leave an extend no record
// explains, and nothing can repair that.
//
// A Journal is not safe for concurrent use, and two journals over one register
// break exactly-once: run one measurer per register.
type Journal struct {
	path     string
	reg      Register
	seed     [Size]byte
	measured map[string]struct{}
	order    []string
	diverged bool
}

// OpenJournal loads the journal at path and cross-checks it against reg, whose
// value at guest boot is [Zero].
//
// Use [openJournalSeeded] on a guest whose register was seeded before the
// measurer started — every guest launched with an anchor (see [Seed]) is one.
func OpenJournal(path string, reg Register) (*Journal, error) {
	return openJournalSeeded(path, reg, Zero)
}

// openJournalSeeded is [OpenJournal] for a register that already held seed
// before any journaled extend. On TDX a guest launched with an anchor reads
// back Seed(anchor) with nothing measured, so folding the journal from [Zero]
// there would report every restart as divergence.
//
// A missing file is a fresh boot, not an error. What the file does hold is
// then reconciled with the register:
//
//   - The fold matches: a clean restart, nothing to do.
//   - The fold without the last entry matches: a crash between recording a
//     digest and extending it. The interrupted extend finishes here, so the
//     digest is measured exactly once overall. A failure to finish it returns
//     a nil journal — the register stays one extend short of what the journal
//     claims, and only this repair closes that gap.
//   - Neither matches: the journal is marked diverged. The journal is still
//     returned, wrapping [ErrRegisterDiverged], so a caller can log it and keep
//     running, but [Journal.MeasureOnce] will refuse to extend.
//
// Any other non-nil error (a skipped malformed line, an unreadable register)
// also comes back alongside a usable journal. To fail closed, treat any
// non-nil error as fatal; to keep measuring, log everything except
// [ErrRegisterDiverged], which already blocks further extends.
func openJournalSeeded(path string, reg Register, seed [Size]byte) (*Journal, error) {
	if reg == nil {
		return nil, errors.New("open journal: no register to measure into")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create journal dir: %w", err)
	}
	j := &Journal{path: path, reg: reg, seed: seed, measured: map[string]struct{}{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		b = nil // first start this boot; the register is still cross-checked
	} else if err != nil {
		return nil, fmt.Errorf("read journal %s: %w", path, err)
	}

	var problems []error
	var skipped []string
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Canonicalize rather than pattern-match, so the journal admits
		// exactly the strings Event hashes.
		d, err := CanonicalDigest(line)
		if err != nil || d != line {
			skipped = append(skipped, line)
			continue
		}
		if _, dup := j.measured[d]; dup {
			continue
		}
		j.measured[d] = struct{}{}
		j.order = append(j.order, d)
	}
	if len(skipped) > 0 {
		problems = append(problems, fmt.Errorf("journal %s: %w: skipped %d line(s), first %q", path, ErrMalformedEntry, len(skipped), skipped[0]))
	}

	if err := j.reconcile(&problems); err != nil {
		return nil, err
	}
	return j, errors.Join(problems...)
}

// reconcile compares the register against the journal and repairs the one
// recoverable difference. Recoverable problems are appended to problems; only
// a failed repair extend is returned, and that is fatal.
func (j *Journal) reconcile(problems *[]error) error {
	cur, err := j.reg.Extension()
	if err != nil {
		// The journal remains the record of what was extended. Re-extending
		// its digests because the register is unreadable is the one mistake
		// nothing here can undo.
		*problems = append(*problems, fmt.Errorf("cannot read the register to cross-check the journal: %w", err))
		return nil
	}
	if want := FromDigestsSeeded(j.seed, j.order); bytes.Equal(cur, want[:]) {
		return nil
	}
	if n := len(j.order); n > 0 {
		if want := FromDigestsSeeded(j.seed, j.order[:n-1]); bytes.Equal(cur, want[:]) {
			last := j.order[n-1]
			event := Event(last)
			if err := j.reg.Extend(event[:]); err != nil {
				return fmt.Errorf("finish the interrupted extend of %s: %w", last, err)
			}
			return nil
		}
	}
	j.diverged = true
	*problems = append(*problems, fmt.Errorf("%w: %d journaled digest(s) do not fold to the register's current value %x", ErrRegisterDiverged, len(j.order), cur))
	return nil
}

// MeasureOnce extends the register with Event(ref) unless this journal already
// records it, and reports whether it extended. ref is a canonical digest or a
// digest-pinned reference, canonicalized ([CanonicalDigest]) first, so two
// spellings of one image measure once between them.
//
// The digest is recorded before the extend: a crash in between under-extends
// the register, which the next [OpenJournal] repairs. A failed extend rolls the
// record back, so a later call for the same image tries again.
//
// It refuses with [ErrRegisterDiverged] once the register is known to carry
// extends this journal cannot account for.
func (j *Journal) MeasureOnce(ref string) (bool, error) {
	d, err := CanonicalDigest(ref)
	if err != nil {
		return false, err
	}
	if j.diverged {
		return false, fmt.Errorf("refusing to extend %s: %w", d, ErrRegisterDiverged)
	}
	if _, done := j.measured[d]; done {
		return false, nil
	}
	if err := j.record(d); err != nil {
		return false, fmt.Errorf("record %s before extending: %w", d, err)
	}
	event := Event(d)
	if err := j.reg.Extend(event[:]); err != nil {
		return false, errors.Join(fmt.Errorf("extend %s: %w", d, err), j.unrecordLast(d))
	}
	j.measured[d] = struct{}{}
	return true, nil
}

// Digests returns the journaled digests in extend order.
func (j *Journal) Digests() []string { return slices.Clone(j.order) }

// record appends one digest to the file, then to the in-memory order, so the
// order never claims a digest the file does not hold. The append is synced
// before the caller extends: a record that only reached the page cache could
// vanish in a power loss after the extend landed, which is the one ordering
// [OpenJournal] cannot repair.
func (j *Journal) record(digest string) error {
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(digest + "\n")
	var serr error
	if werr == nil {
		serr = f.Sync()
	}
	if err := errors.Join(werr, serr, f.Close()); err != nil {
		return err
	}
	j.order = append(j.order, digest)
	return nil
}

// unrecordLast rewrites the journal without the digest whose extend failed.
// The rewrite is atomic, so a crash mid-rollback leaves the
// recorded-but-not-extended shape [OpenJournal] repairs.
func (j *Journal) unrecordLast(digest string) error {
	if n := len(j.order); n > 0 && j.order[n-1] == digest {
		j.order = j.order[:n-1]
	}
	var sb strings.Builder
	for _, d := range j.order {
		sb.WriteString(d)
		sb.WriteByte('\n')
	}
	if err := writeAtomic(j.path, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("roll back journal %s: %w", j.path, err)
	}
	return nil
}

// writeAtomic replaces path via a same-directory temp file and a rename, so a
// reader never sees a half-written journal. The temp file must share the
// directory: a rename across filesystems is not atomic. The data is synced
// before the rename and the directory after it, so the replacement survives a
// power loss rather than reverting to the file it replaced.
//
// Atomic here means a reader sees the old file or the new one, never a mix.
// It is not mutual exclusion between writers; a Journal has one writer.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir, base := filepath.Dir(path), filepath.Base(path)
	tmp, err := os.CreateTemp(dir, base+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if name != "" {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = "" // renamed away: nothing left to clean up
	return syncDir(dir)
}

// syncDir flushes a directory's entries, so a rename into it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
