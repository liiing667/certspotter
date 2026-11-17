// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

// Package evidence determines the recoverable consistency of Certificate
// Transparency evidence: log checkpoints, SCTs, and the actual certificates
// they purport to cover.
//
// All three kinds of evidence share a single tree-size and root-hash check:
// a checkpoint is only meaningful if its root hash can be reconstructed from
// the actual certificates, and an SCT is only valid evidence if it is covered
// by a checkpoint that has been proven in this way.  Consequently, if a log
// rolls back (or forks), SCTs that were "proven" only under the abandoned
// tree stop being valid evidence instead of lingering forever.
//
// Every determination is one of three states:
//
//   - Missing:  part of the evidence is still absent (a gap in the
//     certificates, or a checkpoint that cannot be reconstructed yet).
//     Recovery retries the same position; gaps are never skipped.
//   - Conflict:   the evidence contains irreconcilable root hashes.  The log
//     has rolled back or presented a forked view.
//   - Proven:   every checkpoint is verified against the actual
//     certificates, yielding a unique cursor to which monitoring may advance.
package evidence

import (
	"fmt"
	"slices"

	"software.sslmate.com/src/certspotter/merkletree"
)

// Status is the three-way consistency determination of an evidence set.
type Status int

const (
	// Missing means part of the evidence is still absent.  The cursor does
	// not advance past the gap, and recovery retries the same position.
	Missing Status = iota
	// Conflict means the evidence contains irreconcilable root hashes: the
	// log has rolled back or presented a forked view of the tree.
	Conflict
	// Proven means every checkpoint has been verified against the actual
	// certificates.
	Proven
)

func (s Status) String() string {
	switch s {
	case Missing:
		return "missing"
	case Conflict:
		return "conflict"
	case Proven:
		return "proven"
	default:
		return fmt.Sprintf("Status(%d)", int(s))
	}
}

// Checkpoint is a log's claim that the tree of the given size has the given
// root hash (e.g. a signed tree head or a checkpoint from a static-CT log).
type Checkpoint struct {
	TreeSize uint64          `json:"tree_size"`
	RootHash merkletree.Hash `json:"root_hash"`
}

// LeafRecord binds an actual certificate, identified by its Merkle leaf hash,
// to its position in the log.
type LeafRecord struct {
	Index uint64          `json:"index"`
	Hash  merkletree.Hash `json:"hash"`
}

// SCTClaim is the evidence carried by a signed certificate timestamp: the
// Merkle leaf hash of the certificate it vouches for.  An SCT is only as
// good as the checkpoint under which its inclusion is proven.
type SCTClaim struct {
	LeafHash  merkletree.Hash `json:"leaf_hash"`
	Timestamp uint64          `json:"timestamp"`
}

// Set is the recovered evidence for a single log.
type Set struct {
	Checkpoints []Checkpoint `json:"checkpoints"`
	Leaves      []LeafRecord `json:"leaves"`
	SCTs        []SCTClaim   `json:"scts"`
}

// Cursor identifies a proven tree position: the largest tree size whose root
// hash has been reconstructed from the actual certificates and matched
// against a checkpoint.  The zero Cursor is the empty tree.
type Cursor struct {
	TreeSize uint64          `json:"tree_size"`
	RootHash merkletree.Hash `json:"root_hash"`
}

func zeroCursor() Cursor {
	return Cursor{TreeSize: 0, RootHash: merkletree.HashNothing()}
}

// Verdict is the result of evaluating an evidence set.
type Verdict struct {
	Status Status `json:"status"`

	// Cursor is the unique position to which monitoring may advance: the
	// largest checkpoint that was proven against the actual certificates
	// before any gap or conflict.  It never skips a gap.
	Cursor Cursor `json:"cursor"`

	// Conflict details, valid when Status == Conflict:
	ConflictAt   uint64          `json:"conflict_at,omitzero"`   // tree size (or leaf index) of the conflict
	ClaimedRoot  merkletree.Hash `json:"claimed_root,omitzero"`  // root hash claimed by a checkpoint or stale record
	ExpectedRoot merkletree.Hash `json:"expected_root,omitzero"` // root hash reconstructed from the actual certificates

	// Gap details, valid when Status == Missing:
	GapStart uint64 `json:"gap_start,omitzero"` // first missing leaf index
	GapEnd   uint64 `json:"gap_end,omitzero"`   // tree size of the smallest checkpoint that cannot be verified yet
}

func (v Verdict) String() string {
	switch v.Status {
	case Conflict:
		return fmt.Sprintf("conflict at tree size %d: checkpoint claims root hash %x but the actual certificates reconstruct to %x (proven cursor: %d)",
			v.ConflictAt, v.ClaimedRoot, v.ExpectedRoot, v.Cursor.TreeSize)
	case Missing:
		return fmt.Sprintf("missing certificates in [%d,%d) to verify checkpoint (proven cursor: %d)",
			v.GapStart, v.GapEnd, v.Cursor.TreeSize)
	case Proven:
		return fmt.Sprintf("proven up to tree size %d (root hash %x)", v.Cursor.TreeSize, v.Cursor.RootHash)
	default:
		return v.Status.String()
	}
}

// leafPrefix returns the leaf hashes of the contiguous prefix [0, L), where L
// is the index of the first gap.  If two records disagree about the hash at
// the same index, it returns a conflict instead: the log rolled back and the
// stale record was not discarded.  A conflict is irreconcilable no matter
// where it occurs, so it is reported even if it lies beyond a gap.
func leafPrefix(leaves []LeafRecord) ([]merkletree.Hash, *Verdict) {
	sorted := slices.Clone(leaves)
	slices.SortFunc(sorted, func(a, b LeafRecord) int { return cmpUint64(a.Index, b.Index) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].Index == sorted[i].Index && sorted[i-1].Hash != sorted[i].Hash {
			return nil, &Verdict{
				Status:       Conflict,
				ConflictAt:   sorted[i].Index,
				ClaimedRoot:  sorted[i].Hash,
				ExpectedRoot: sorted[i-1].Hash,
			}
		}
	}
	prefix := make([]merkletree.Hash, 0, len(sorted))
	for _, leaf := range sorted {
		if leaf.Index > uint64(len(prefix)) {
			break // gap: everything past the first missing index is unusable
		}
		if leaf.Index < uint64(len(prefix)) {
			continue // duplicate record with identical hash
		}
		prefix = append(prefix, leaf.Hash)
	}
	return prefix, nil
}

func cmpUint64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func reconstructRoot(leaves []merkletree.Hash, size uint64) merkletree.Hash {
	tree := merkletree.EmptyCollapsedTree()
	for _, hash := range leaves[:size] {
		tree.Add(hash) // cannot fail: offset is 0
	}
	return tree.CalculateRoot()
}

// Evaluate determines the consistency of an evidence set by checking every
// checkpoint against the root hash reconstructed from the actual
// certificates.  It is deterministic: for a given set there is exactly one
// advanceable cursor, and it never lies beyond an unverified gap.
func Evaluate(set *Set) Verdict {
	leaves, leafConflict := leafPrefix(set.Leaves)
	if leafConflict != nil {
		leafConflict.Cursor = zeroCursor()
		return *leafConflict
	}

	// Group checkpoints by tree size; disagreeing checkpoints at the same
	// tree size are the canonical signal of a log rollback.
	sizes := make([]uint64, 0, len(set.Checkpoints))
	roots := make(map[uint64][]merkletree.Hash)
	for _, cp := range set.Checkpoints {
		if _, ok := roots[cp.TreeSize]; !ok {
			sizes = append(sizes, cp.TreeSize)
		}
		if !slices.Contains(roots[cp.TreeSize], cp.RootHash) {
			roots[cp.TreeSize] = append(roots[cp.TreeSize], cp.RootHash)
		}
	}
	slices.Sort(sizes)

	cursor := zeroCursor()
	for _, size := range sizes {
		sizeRoots := roots[size]
		if size > uint64(len(leaves)) {
			if len(sizeRoots) > 1 {
				// Unverifiable due to the gap, but already irreconcilable.
				return Verdict{Status: Conflict, Cursor: cursor, ConflictAt: size, ClaimedRoot: sizeRoots[1], ExpectedRoot: sizeRoots[0]}
			}
			// The gap must be filled before this checkpoint - and anything
			// beyond it - can be considered.  Never skip the gap.
			return Verdict{Status: Missing, Cursor: cursor, GapStart: uint64(len(leaves)), GapEnd: size}
		}
		reconstructed := reconstructRoot(leaves, size)
		for _, root := range sizeRoots {
			if root != reconstructed {
				return Verdict{Status: Conflict, Cursor: cursor, ConflictAt: size, ClaimedRoot: root, ExpectedRoot: reconstructed}
			}
		}
		cursor = Cursor{TreeSize: size, RootHash: reconstructed}
	}
	return Verdict{Status: Proven, Cursor: cursor}
}

// SCTStatus is the disposition of a single SCT under the current evidence.
type SCTStatus int

const (
	// SCTMissing means the certificate or a covering checkpoint is still
	// absent; the SCT is not (yet) usable evidence.
	SCTMissing SCTStatus = iota
	// SCTConflict means the SCT was only ever covered by a checkpoint that
	// conflicts with the actual certificates - stale evidence from a
	// rolled-back tree that must not be treated as valid.
	SCTConflict
	// SCTProven means the SCT's certificate is covered by the proven cursor.
	SCTProven
)

func (s SCTStatus) String() string {
	switch s {
	case SCTMissing:
		return "missing"
	case SCTConflict:
		return "conflict"
	case SCTProven:
		return "proven"
	default:
		return fmt.Sprintf("SCTStatus(%d)", int(s))
	}
}

// SCTVerdict is the disposition of an SCT along with the set verdict it was
// derived from.
type SCTVerdict struct {
	Status SCTStatus `json:"status"`
	Index  uint64    `json:"index,omitzero"` // log position of the certificate, if retrieved
	Found  bool      `json:"found"`          // whether the certificate has been retrieved
	Set    Verdict   `json:"set"`
}

// EvaluateSCT determines whether an SCT is currently valid evidence.  The
// answer is always derived from the current proven cursor, never cached, so
// a log rollback immediately invalidates SCTs from the abandoned tree.
func EvaluateSCT(set *Set, sct SCTClaim) SCTVerdict {
	verdict := Evaluate(set)
	leaves, _ := leafPrefix(set.Leaves)
	for index, hash := range leaves {
		if hash != sct.LeafHash {
			continue
		}
		if uint64(index) < verdict.Cursor.TreeSize {
			return SCTVerdict{Status: SCTProven, Index: uint64(index), Found: true, Set: verdict}
		}
		if verdict.Status == Conflict {
			return SCTVerdict{Status: SCTConflict, Index: uint64(index), Found: true, Set: verdict}
		}
		return SCTVerdict{Status: SCTMissing, Index: uint64(index), Found: true, Set: verdict}
	}
	return SCTVerdict{Status: SCTMissing, Found: false, Set: verdict}
}
