// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// notificationRecord is a persistent record that a notification about a
// certificate matching a watch item was successfully delivered.  Records are
// stored in the notification ledger ($CERTSPOTTER_STATE_DIR/notified) so that
// a certificate is only notified about once, even if it is discovered
// multiple times (e.g. in different logs, or as both a precertificate and a
// final certificate) or certspotter is restarted.
type notificationRecord struct {
	WatchItem  string    `json:"watch_item"`
	TBSSHA256  string    `json:"tbs_sha256"`
	CertSHA256 string    `json:"cert_sha256"`
	NotifiedAt time.Time `json:"notified_at"`
}

func (s *FilesystemState) notifiedDir() string {
	return filepath.Join(s.StateDir, "notified")
}

// notificationRecordPath returns the path of the ledger record for the given
// (watch item, certificate) pair.  The TBS fingerprint identifies the
// certificate, so a precertificate and its corresponding final certificate
// share the same record.  Distinct certificates always have distinct records.
func (s *FilesystemState) notificationRecordPath(watchItem WatchItem, tbsSHA256 [32]byte) string {
	key := sha256.Sum256([]byte(watchItem.String() + "\x00" + hex.EncodeToString(tbsSHA256[:])))
	return filepath.Join(s.notifiedDir(), hex.EncodeToString(key[:])+".json")
}

// alreadyNotified returns true if the ledger contains a record for the given
// (watch item, certificate) pair.
func (s *FilesystemState) alreadyNotified(watchItem WatchItem, tbsSHA256 [32]byte) (bool, error) {
	recordPath := s.notificationRecordPath(watchItem, tbsSHA256)
	if _, err := os.Lstat(recordPath); err == nil {
		return true, nil
	} else if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else {
		return false, fmt.Errorf("error checking notification ledger: %w", err)
	}
}

// recordNotification atomically records in the ledger that a notification
// about cert was successfully delivered.  Must only be called after
// successful delivery; on failure no record is written so the notification
// can be retried.
func (s *FilesystemState) recordNotification(cert *DiscoveredCert) error {
	if err := os.Mkdir(s.notifiedDir(), 0777); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("error creating notification ledger directory: %w", err)
	}
	record := &notificationRecord{
		WatchItem:  cert.WatchItem.String(),
		TBSSHA256:  hex.EncodeToString(cert.TBSSHA256[:]),
		CertSHA256: hex.EncodeToString(cert.SHA256[:]),
		NotifiedAt: time.Now(),
	}
	recordPath := s.notificationRecordPath(cert.WatchItem, cert.TBSSHA256)
	if err := writeJSONFile(recordPath, record, 0666); err != nil {
		return fmt.Errorf("error writing notification ledger record: %w", err)
	}
	return nil
}
