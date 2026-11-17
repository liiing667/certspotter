// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package evidence

import (
	"fmt"
	"testing"

	"software.sslmate.com/src/certspotter/merkletree"
)

// makeLeaves returns the Merkle leaf hashes of n certificates whose names
// are derived from fork, so different forks of a log produce different leaves.
func makeLeaves(fork string, n uint64) []merkletree.Hash {
	leaves := make([]merkletree.Hash, n)
	for i := range leaves {
		leaves[i] = merkletree.HashLeaf([]byte(fmt.Sprintf("cert-%s-%d", fork, i)))
	}
	return leaves
}

func leafRecords(leaves []merkletree.Hash, from, to uint64) []LeafRecord {
	records := make([]LeafRecord, 0, to-from)
	for i := from; i < to; i++ {
		records = append(records, LeafRecord{Index: i, Hash: leaves[i]})
	}
	return records
}

func makeCheckpoint(leaves []merkletree.Hash, size uint64) Checkpoint {
	return Checkpoint{TreeSize: size, RootHash: reconstructRoot(leaves, size)}
}

// rollbackFixture simulates a log that grows to tree size 8 and then rolls
// back to a fork that diverges after entry 3.
type rollbackFixture struct {
	oldLeaves []merkletree.Hash // original tree, entries 0..7
	newLeaves []merkletree.Hash // rolled-back tree: entries 0..3 shared, 4..7 differ
	oldCP4    Checkpoint
	oldCP8    Checkpoint
	newCP4    Checkpoint
	newCP6    Checkpoint
	newCP8    Checkpoint
}

func newRollbackFixture(t *testing.T) *rollbackFixture {
	t.Helper()
	f := &rollbackFixture{
		oldLeaves: makeLeaves("old", 8),
		newLeaves: makeLeaves("new", 8),
	}
	copy(f.newLeaves, f.oldLeaves[:4]) // shared prefix [0,4)
	f.oldCP4 = makeCheckpoint(f.oldLeaves, 4)
	f.oldCP8 = makeCheckpoint(f.oldLeaves, 8)
	f.newCP4 = makeCheckpoint(f.newLeaves, 4)
	f.newCP6 = makeCheckpoint(f.newLeaves, 6)
	f.newCP8 = makeCheckpoint(f.newLeaves, 8)
	if f.oldCP4 != f.newCP4 {
		t.Fatal("fixture broken: shared prefix must yield identical checkpoint at size 4")
	}
	if f.oldCP8.RootHash == f.newCP8.RootHash {
		t.Fatal("fixture broken: rolled-back tree must have a different root hash at size 8")
	}
	return f
}

func TestProvenBaseline(t *testing.T) {
	f := newRollbackFixture(t)
	set := &Set{
		Checkpoints: []Checkpoint{f.oldCP4, f.oldCP8},
		Leaves:      leafRecords(f.oldLeaves, 0, 8),
	}
	verdict := Evaluate(set)
	if verdict.Status != Proven {
		t.Fatalf("expected proven, got %s", verdict)
	}
	if verdict.Cursor.TreeSize != 8 || verdict.Cursor.RootHash != f.oldCP8.RootHash {
		t.Fatalf("expected cursor (8, %x), got (%d, %x)", f.oldCP8.RootHash, verdict.Cursor.TreeSize, verdict.Cursor.RootHash)
	}

	sct := SCTClaim{LeafHash: f.oldLeaves[5], Timestamp: 1234}
	if sv := EvaluateSCT(set, sct); sv.Status != SCTProven || sv.Index != 5 {
		t.Fatalf("expected SCT proven at index 5, got %s (index %d)", sv.Status, sv.Index)
	}
}

// After the log rolls back, the old checkpoint at size 8 and the new one
// claim different root hashes for the same tree size.  The verdict must
// surface both hashes and rewind the cursor to the last consistent prefix.
func TestRollbackConflictingRootHashes(t *testing.T) {
	f := newRollbackFixture(t)
	set := &Set{
		Checkpoints: []Checkpoint{f.oldCP4, f.oldCP8, f.newCP8},
		Leaves:      leafRecords(f.newLeaves, 0, 8),
	}
	verdict := Evaluate(set)
	if verdict.Status != Conflict {
		t.Fatalf("expected conflict, got %s", verdict)
	}
	if verdict.ConflictAt != 8 {
		t.Fatalf("expected conflict at tree size 8, got %d", verdict.ConflictAt)
	}
	if verdict.ClaimedRoot != f.oldCP8.RootHash || verdict.ExpectedRoot != f.newCP8.RootHash {
		t.Fatalf("expected claimed %x vs reconstructed %x, got claimed %x vs reconstructed %x",
			f.oldCP8.RootHash, f.newCP8.RootHash, verdict.ClaimedRoot, verdict.ExpectedRoot)
	}
	if verdict.Cursor.TreeSize != 4 || verdict.Cursor.RootHash != f.oldCP4.RootHash {
		t.Fatalf("expected cursor rewound to (4, %x), got (%d, %x)", f.oldCP4.RootHash, verdict.Cursor.TreeSize, verdict.Cursor.RootHash)
	}
}

// An SCT that was proven under the abandoned tree must stop being valid
// evidence as soon as the rollback is detected.
func TestRollbackInvalidatesStaleSCT(t *testing.T) {
	f := newRollbackFixture(t)
	staleSCT := SCTClaim{LeafHash: f.oldLeaves[5], Timestamp: 1234}

	before := &Set{
		Checkpoints: []Checkpoint{f.oldCP4, f.oldCP8},
		Leaves:      leafRecords(f.oldLeaves, 0, 8),
	}
	if sv := EvaluateSCT(before, staleSCT); sv.Status != SCTProven {
		t.Fatalf("precondition failed: SCT should be proven before rollback, got %s", sv.Status)
	}

	// The conflicting checkpoint arrives; the evidence set is now in
	// conflict and the stale SCT must be rejected, not trusted.
	conflicted := &Set{
		Checkpoints: []Checkpoint{f.oldCP4, f.oldCP8, f.newCP8},
		Leaves:      leafRecords(f.oldLeaves, 0, 8),
	}
	if sv := EvaluateSCT(conflicted, staleSCT); sv.Status != SCTConflict {
		t.Fatalf("expected stale SCT to be conflict after rollback, got %s", sv.Status)
	}

	// After the stale checkpoint and stale certificates are discarded but
	// before the new tree is proven, the SCT is merely missing - still not
	// valid evidence.
	reproving := &Set{
		Checkpoints: []Checkpoint{f.newCP4, f.newCP8},
		Leaves:      leafRecords(f.newLeaves, 0, 6),
	}
	if sv := EvaluateSCT(reproving, staleSCT); sv.Status == SCTProven {
		t.Fatalf("stale SCT must not be proven while the new tree is unverified")
	}
}

// A checkpoint beyond a gap in the certificates cannot be verified, and the
// cursor must not skip the gap - even if further checkpoints exist beyond it.
func TestMissingProofGapNotSkipped(t *testing.T) {
	f := newRollbackFixture(t)
	set := &Set{
		Checkpoints: []Checkpoint{f.newCP4, f.newCP8},
		Leaves:      leafRecords(f.newLeaves, 0, 6), // gap: entries 6 and 7 missing
	}
	verdict := Evaluate(set)
	if verdict.Status != Missing {
		t.Fatalf("expected missing, got %s", verdict)
	}
	if verdict.GapStart != 6 || verdict.GapEnd != 8 {
		t.Fatalf("expected gap [6,8), got [%d,%d)", verdict.GapStart, verdict.GapEnd)
	}
	if verdict.Cursor.TreeSize != 4 {
		t.Fatalf("cursor must not skip the gap: expected 4, got %d", verdict.Cursor.TreeSize)
	}

	// An SCT whose certificate sits past the gap is not usable yet.
	sct := SCTClaim{LeafHash: f.newLeaves[5], Timestamp: 1234}
	if sv := EvaluateSCT(set, sct); sv.Status != SCTMissing {
		t.Fatalf("expected SCT missing past the gap, got %s", sv.Status)
	}
}

// Once the missing certificates are supplied, the evidence proves exactly one
// advanceable cursor, deterministically.
func TestReprovingYieldsUniqueCursor(t *testing.T) {
	f := newRollbackFixture(t)
	set := &Set{
		Checkpoints: []Checkpoint{f.newCP4, f.newCP6, f.newCP8},
		Leaves:      leafRecords(f.newLeaves, 0, 8),
	}
	first := Evaluate(set)
	second := Evaluate(set)
	if first != second {
		t.Fatalf("evaluation must be deterministic: %s vs %s", first, second)
	}
	if first.Status != Proven || first.Cursor.TreeSize != 8 || first.Cursor.RootHash != f.newCP8.RootHash {
		t.Fatalf("expected unique cursor (8, %x), got %s", f.newCP8.RootHash, first)
	}

	sct := SCTClaim{LeafHash: f.newLeaves[6], Timestamp: 1234}
	if sv := EvaluateSCT(set, sct); sv.Status != SCTProven {
		t.Fatalf("expected re-proven SCT to be valid, got %s", sv.Status)
	}
}

// A legitimate new checkpoint on the same tree advances the cursor.
func TestLegitimateCheckpointAdvancesCursor(t *testing.T) {
	f := newRollbackFixture(t)
	leaves := makeLeaves("new", 10)
	copy(leaves, f.newLeaves)
	cp10 := makeCheckpoint(leaves, 10)
	set := &Set{
		Checkpoints: []Checkpoint{f.newCP8, cp10},
		Leaves:      leafRecords(leaves, 0, 10),
	}
	verdict := Evaluate(set)
	if verdict.Status != Proven || verdict.Cursor.TreeSize != 10 || verdict.Cursor.RootHash != cp10.RootHash {
		t.Fatalf("expected cursor to advance to 10, got %s", verdict)
	}
}

// Two certificates recorded at the same log position with different hashes
// are a leaf-level rollback signal and must be reported as a conflict.
func TestConflictingLeavesAtSameIndex(t *testing.T) {
	f := newRollbackFixture(t)
	set := &Set{
		Checkpoints: []Checkpoint{f.oldCP4},
		Leaves: []LeafRecord{
			{Index: 2, Hash: f.oldLeaves[2]},
			{Index: 2, Hash: f.newLeaves[5]}, // stale record disagrees
		},
	}
	verdict := Evaluate(set)
	if verdict.Status != Conflict || verdict.ConflictAt != 2 {
		t.Fatalf("expected conflict at index 2, got %s", verdict)
	}
}

// Crash recovery must reproduce the same determination and must never skip a
// gap, no matter where the crash lands between writes.
func TestCrashRecoveryDoesNotSkipGaps(t *testing.T) {
	f := newRollbackFixture(t)
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Evidence with a gap is stored, then the cursor justified by it.
	gapped := &Set{
		Checkpoints: []Checkpoint{f.newCP4, f.newCP8},
		Leaves:      leafRecords(f.newLeaves, 0, 6),
	}
	if err := store.StoreSet(gapped); err != nil {
		t.Fatal(err)
	}
	if err := store.StoreCursor(Cursor{TreeSize: 4, RootHash: f.newCP4.RootHash}); err != nil {
		t.Fatal(err)
	}

	// Crash and recover: the gap is still there and the cursor stays behind it.
	_, verdict, err := store.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Missing || verdict.Cursor.TreeSize != 4 || verdict.GapStart != 6 {
		t.Fatalf("expected missing with cursor 4 after recovery, got %s", verdict)
	}

	// The missing certificates arrive; the crash lands between storing the
	// evidence and storing the new cursor.
	completed := &Set{
		Checkpoints: []Checkpoint{f.newCP4, f.newCP8},
		Leaves:      leafRecords(f.newLeaves, 0, 8),
	}
	if err := store.StoreSet(completed); err != nil {
		t.Fatal(err)
	}
	_, verdict, err = store.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Proven || verdict.Cursor.TreeSize != 8 {
		t.Fatalf("expected recovered cursor 8 after re-proving, got %s", verdict)
	}
	if err := store.StoreCursor(verdict.Cursor); err != nil {
		t.Fatal(err)
	}

	// A stored cursor that is ahead of the recovered evidence means evidence
	// was lost; recovery must refuse to honor it rather than skip the gap.
	if err := store.StoreSet(gapped); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Recover(); err == nil {
		t.Fatalf("expected recovery to reject a cursor ahead of the evidence")
	}
}
