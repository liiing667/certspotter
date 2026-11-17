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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Store durably persists the evidence set and the proven cursor for one log,
// so that a crash or restart yields the same consistency determination.
//
// Evidence is always written before the cursor that depends on it, and both
// files are written atomically (temp file, fsync, rename).  Recovery
// re-derives the cursor from the evidence instead of trusting the stored
// cursor, so a crash can never skip an unverified gap.
type Store struct {
	dir string
}

// OpenStore opens (creating if necessary) the evidence store in dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0777); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) evidencePath() string { return filepath.Join(s.dir, "evidence.json") }
func (s *Store) cursorPath() string   { return filepath.Join(s.dir, "cursor.json") }

// LoadSet returns the stored evidence set, or an empty set if none has been
// stored yet.
func (s *Store) LoadSet() (*Set, error) {
	set := new(Set)
	fileBytes, err := os.ReadFile(s.evidencePath())
	if errors.Is(err, fs.ErrNotExist) {
		return set, nil
	} else if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(fileBytes, set); err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", s.evidencePath(), err)
	}
	return set, nil
}

// StoreSet atomically stores the evidence set.
func (s *Store) StoreSet(set *Set) error {
	return writeJSONFile(s.evidencePath(), set, 0666)
}

// StoreCursor atomically stores the proven cursor.  Callers must store the
// evidence that justifies the cursor first.
func (s *Store) StoreCursor(cursor Cursor) error {
	return writeJSONFile(s.cursorPath(), cursor, 0666)
}

// LoadCursor returns the stored cursor, or the zero cursor if none has been
// stored yet.
func (s *Store) LoadCursor() (Cursor, error) {
	cursor := zeroCursor()
	fileBytes, err := os.ReadFile(s.cursorPath())
	if errors.Is(err, fs.ErrNotExist) {
		return cursor, nil
	} else if err != nil {
		return cursor, err
	}
	if err := json.Unmarshal(fileBytes, &cursor); err != nil {
		return cursor, fmt.Errorf("error parsing %s: %w", s.cursorPath(), err)
	}
	return cursor, nil
}

// Recover loads the evidence set and re-derives the consistency verdict from
// scratch.  The returned cursor is the one computed from the evidence, which
// is the only cursor recovery may advance to.  A stored cursor that is ahead
// of what the evidence proves indicates lost evidence and is reported as an
// error rather than honored: gaps are never skipped.
func (s *Store) Recover() (*Set, Verdict, error) {
	set, err := s.LoadSet()
	if err != nil {
		return nil, Verdict{}, err
	}
	verdict := Evaluate(set)
	stored, err := s.LoadCursor()
	if err != nil {
		return nil, Verdict{}, err
	}
	if stored.TreeSize > verdict.Cursor.TreeSize {
		return nil, Verdict{}, fmt.Errorf("stored cursor (tree size %d) is ahead of what the recovered evidence proves (tree size %d): evidence was lost",
			stored.TreeSize, verdict.Cursor.TreeSize)
	}
	return set, verdict, nil
}

func randomFileSuffix() string {
	var randomBytes [12]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(randomBytes[:])
}

func writeSyncFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err2 := f.Sync(); err2 != nil && err == nil {
		err = err2
	}
	if err2 := f.Close(); err2 != nil && err == nil {
		err = err2
	}
	return err
}

func writeFile(filename string, data []byte, perm os.FileMode) error {
	tempname := filename + ".tmp." + randomFileSuffix()
	if err := writeSyncFile(tempname, data, perm); err != nil {
		return fmt.Errorf("error writing %s: %w", filename, err)
	}
	if err := os.Rename(tempname, filename); err != nil {
		os.Remove(tempname)
		return fmt.Errorf("error writing %s: %w", filename, err)
	}
	return nil
}

func writeJSONFile(filename string, data any, perm os.FileMode) error {
	fileBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	fileBytes = append(fileBytes, '\n')
	return writeFile(filename, fileBytes, perm)
}
