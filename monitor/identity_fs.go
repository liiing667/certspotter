// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const identityConflictSchemaVersion = 1

type storedIdentityConflict struct {
	SchemaVersion     int       `json:"schema_version"`
	Verdict           string    `json:"verdict"`
	TBSSHA256         string    `json:"tbs_sha256"`
	CertificateSHA256 string    `json:"certificate_sha256"`
	Error             string    `json:"error"`
	LogID             string    `json:"log_id,omitempty"`
	EntryIndex        uint64    `json:"entry_index,omitempty"`
	FirstObserved     time.Time `json:"first_observed"`
}

func (s *FilesystemState) identityConflictPath(ref IdentityRef) string {
	tbsFingerprint := hexIdentityHash(ref.TBSSHA256)
	certFingerprint := hexIdentityHash(ref.CertificateSHA256)
	return filepath.Join(
		s.StateDir,
		"identity_conflicts",
		tbsFingerprint[0:2],
		tbsFingerprint+"-"+certFingerprint+".json",
	)
}

// RecordIdentityConflict persists the first rejection conclusion for an exact
// TBS/certificate identity pair.  An existing record is never overwritten.
func (s *FilesystemState) RecordIdentityConflict(_ context.Context, conflict *IdentityConflict) error {
	if conflict == nil {
		return errors.New("identity conflict record is nil")
	}
	if conflict.FirstObserved.IsZero() {
		conflict.FirstObserved = time.Now().UTC()
	}

	path := s.identityConflictPath(conflict.Ref)
	if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		return err
	}
	if fileExists(path) {
		// Preserve the original rejection conclusion.
		return nil
	}

	record := storedIdentityConflict{
		SchemaVersion:     identityConflictSchemaVersion,
		Verdict:           "rejected",
		TBSSHA256:         hexIdentityHash(conflict.Ref.TBSSHA256),
		CertificateSHA256: hexIdentityHash(conflict.Ref.CertificateSHA256),
		LogID:             conflict.LogID.Base64String(),
		EntryIndex:        conflict.EntryIndex,
		FirstObserved:     conflict.FirstObserved,
	}
	if conflict.Reason != nil {
		record.Error = conflict.Reason.Error()
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	if _, writeErr := file.Write(data); writeErr != nil {
		file.Close()
		return writeErr
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// LoadIdentityConflict loads a persisted identity rejection for an exact
// TBS/certificate pair.  It returns nil, nil when no rejection exists.
func (s *FilesystemState) LoadIdentityConflict(_ context.Context, ref IdentityRef) (*IdentityConflict, error) {
	path := s.identityConflictPath(ref)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var record storedIdentityConflict
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("error parsing identity conflict record %s: %w", path, err)
	}

	conflict := &IdentityConflict{
		Ref:           ref,
		EntryIndex:    record.EntryIndex,
		FirstObserved: record.FirstObserved,
	}
	if record.Error != "" {
		conflict.Reason = &IdentityMismatchError{
			TBSSHA256:            ref.TBSSHA256,
			PrecertificateSHA256: ref.CertificateSHA256,
			Reason:               errors.New(record.Error),
		}
	}
	if record.LogID != "" {
		logIDBytes, err := base64.StdEncoding.DecodeString(record.LogID)
		if err != nil {
			return nil, fmt.Errorf("error parsing log ID in %s: %w", path, err)
		}
		if len(logIDBytes) != len(conflict.LogID) {
			return nil, fmt.Errorf("log ID in %s has length %d, want %d", path, len(logIDBytes), len(conflict.LogID))
		}
		copy(conflict.LogID[:], logIDBytes)
	}

	// Prefer the hashes in the record if they decode; the path/ref remains the
	// stable lookup key.
	if tbs, err := hex.DecodeString(record.TBSSHA256); err == nil && len(tbs) == len(ref.TBSSHA256) {
		copy(conflict.Ref.TBSSHA256[:], tbs)
	}
	if cert, err := hex.DecodeString(record.CertificateSHA256); err == nil && len(cert) == len(ref.CertificateSHA256) {
		copy(conflict.Ref.CertificateSHA256[:], cert)
	}
	return conflict, nil
}

func (s *FilesystemState) checkCertIdentityAllowed(ctx context.Context, cert *DiscoveredCert) error {
	if identityErr := cert.ValidateIdentity(); identityErr != nil {
		mismatch, ok := AsIdentityMismatch(identityErr)
		if !ok {
			mismatch = &IdentityMismatchError{
				TBSSHA256:            cert.TBSSHA256,
				PrecertificateSHA256: cert.SHA256,
				Reason:               identityErr,
			}
		}
		conflict := &IdentityConflict{Ref: identityRefForCert(cert), Reason: mismatch}
		if cert.LogEntry != nil {
			if cert.LogEntry.Log != nil {
				conflict.LogID = cert.LogEntry.Log.LogID
			}
			conflict.EntryIndex = cert.LogEntry.Index
		}
		if err := s.RecordIdentityConflict(ctx, conflict); err != nil {
			return fmt.Errorf("error persisting identity rejection: %w", err)
		}
		return fmt.Errorf("%w for TBS %x and certificate %x: %w",
			ErrUntrustedIdentity, cert.TBSSHA256, cert.SHA256, mismatch)
	}

	conflict, err := s.LoadIdentityConflict(ctx, identityRefForCert(cert))
	if err != nil {
		return err
	}
	if conflict != nil {
		if conflict.Reason != nil {
			return fmt.Errorf("%w: identity pair TBS %x/certificate %x was previously rejected: %w",
				ErrUntrustedIdentity, cert.TBSSHA256, cert.SHA256, conflict.Reason)
		}
		return fmt.Errorf("%w: identity pair TBS %x/certificate %x was previously rejected",
			ErrUntrustedIdentity, cert.TBSSHA256, cert.SHA256)
	}
	return nil
}
