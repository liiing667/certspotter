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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// pendingNotificationRecord is a write-ahead record for a certificate
// notification.  The record is persisted before invoking any notification
// sink and removed only after the sink reports success and the historical
// notified marker (when certificates are saved) has been persisted.
//
// If certspotter exits or is killed between those two events, restart recovery
// replays the record.  This makes notification delivery at-least-once and,
// crucially, prevents a committed log scan position from stranding a
// certificate that was discovered but not successfully reported.
type pendingNotificationRecord struct {
	ID         string                    `json:"id"`
	TBSSHA256  string                    `json:"tbs_sha256"`
	CertSHA256 string                    `json:"cert_sha256"`
	SaveCerts  bool                      `json:"save_certs"`
	CreatedAt  time.Time                 `json:"created_at"`
	Summary    string                    `json:"summary"`
	Text       string                    `json:"text"`
	Environ    []string                  `json:"environ"`
	Files      []pendingNotificationFile `json:"files,omitempty"`
}

type pendingNotificationFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
}

func (s *FilesystemState) pendingNotificationsDir() string {
	return filepath.Join(s.StateDir, "pending_notifications")
}

func (s *FilesystemState) pendingNotificationPath(id string) string {
	return filepath.Join(s.pendingNotificationsDir(), id+".json")
}

func (s *FilesystemState) lockCertNotification(tbsSHA256 [32]byte) func() {
	mu := &s.notifyLocks[tbsSHA256[0]]
	mu.Lock()
	return mu.Unlock
}

func (s *FilesystemState) lockPendingNotification(record *pendingNotificationRecord) func() {
	var tbsSHA256 [32]byte
	if decoded, err := hex.DecodeString(record.TBSSHA256); err == nil && len(decoded) == len(tbsSHA256) {
		copy(tbsSHA256[:], decoded)
	}
	return s.lockCertNotification(tbsSHA256)
}

func newPendingNotificationRecord(cert *DiscoveredCert, notif *notification, saveCerts bool, files []pendingNotificationFile) *pendingNotificationRecord {
	tbsFingerprint := hex.EncodeToString(cert.TBSSHA256[:])
	return &pendingNotificationRecord{
		ID:         tbsFingerprint,
		TBSSHA256:  tbsFingerprint,
		CertSHA256: hex.EncodeToString(cert.SHA256[:]),
		SaveCerts:  saveCerts,
		CreatedAt:  time.Now().UTC(),
		Summary:    notif.summary,
		Text:       notif.text,
		Environ:    notif.environ,
		Files:      files,
	}
}

func readPendingNotificationFile(path string) (pendingNotificationFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pendingNotificationFile{}, err
	}
	return pendingNotificationFile{Path: path, Data: data}, nil
}

func materializePendingNotificationFiles(record *pendingNotificationRecord) error {
	for _, file := range record.Files {
		if dir := filepath.Dir(file.Path); dir != "" {
			if err := os.MkdirAll(dir, 0777); err != nil {
				return err
			}
		}
		if err := writeFile(file.Path, file.Data, 0666); err != nil {
			return err
		}
	}
	return nil
}

func (s *FilesystemState) savePendingNotification(record *pendingNotificationRecord) error {
	if err := os.MkdirAll(s.pendingNotificationsDir(), 0777); err != nil {
		return err
	}
	return writeJSONFile(s.pendingNotificationPath(record.ID), record, 0666)
}

func loadPendingNotificationFile(path string) (*pendingNotificationRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	record := new(pendingNotificationRecord)
	if err := json.Unmarshal(data, record); err != nil {
		return nil, err
	}
	if record.ID == "" {
		return nil, errors.New("pending notification record has no ID")
	}
	return record, nil
}

// RecoverPendingNotifications replays certificate notifications that were
// persisted before certspotter exited and not completed.  It is safe to call
// on an initialized state directory and is idempotent after successful
// delivery.
func (s *FilesystemState) RecoverPendingNotifications(ctx context.Context) error {
	dirPath := s.pendingNotificationsDir()
	entries, err := os.ReadDir(dirPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("error reading pending notifications directory: %w", err)
	}

	var recoveryErrs []error
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if strings.HasSuffix(name, ".v1.json") {
			// This is the certificate metadata artifact exposed to scripts,
			// not a pending-notification record.
			continue
		}

		recordPath := filepath.Join(dirPath, name)
		record, err := loadPendingNotificationFile(recordPath)
		if errors.Is(err, fs.ErrNotExist) {
			// A concurrently completed recovery/notification removed it.
			continue
		}
		if err != nil {
			// Preserve the unreadable record for forensics rather than
			// deleting a discovered certificate, but do not let one corrupt
			// file prevent all other pending notifications from recovering.
			quarantinePath := recordPath + ".corrupt." + randomFileSuffix()
			if renameErr := os.Rename(recordPath, quarantinePath); renameErr != nil {
				recoveryErrs = append(recoveryErrs, fmt.Errorf("error parsing %s: %w (and unable to quarantine it: %v)", recordPath, err, renameErr))
			} else {
				log.Printf("quarantined unreadable pending notification at %s as %s: %s", recordPath, quarantinePath, err)
			}
			continue
		}

		unlock := s.lockPendingNotification(record)
		err = s.recoverPendingNotification(ctx, record)
		unlock()
		if err != nil {
			recoveryErrs = append(recoveryErrs, err)
		}
	}
	return errors.Join(recoveryErrs...)
}

func (s *FilesystemState) recoverPendingNotification(ctx context.Context, record *pendingNotificationRecord) error {
	if s.pendingNotificationSuppressed(record) {
		// A marker/legacy record says this certificate was delivered or
		// explicitly authorized.  Clean up the write-ahead record instead
		// of sending a duplicate alert.
		if err := s.completePendingNotification(record); err != nil {
			return fmt.Errorf("error cleaning suppressed notification %s: %w", record.ID, err)
		}
		return nil
	}
	if err := materializePendingNotificationFiles(record); err != nil {
		return fmt.Errorf("error restoring files for pending notification %s: %w", record.ID, err)
	}
	notif := &notification{
		summary: record.Summary,
		text:    record.Text,
		environ: record.Environ,
	}
	if err := s.notify(ctx, notif); err != nil {
		return fmt.Errorf("error replaying pending notification %s: %w", record.ID, err)
	}
	if err := s.completePendingNotification(record); err != nil {
		return fmt.Errorf("error completing pending notification %s: %w", record.ID, err)
	}
	return nil
}

func (s *FilesystemState) pendingNotificationSuppressed(record *pendingNotificationRecord) bool {
	if record.TBSSHA256 != "" && len(record.TBSSHA256) >= 2 {
		tbsMarker := filepath.Join(s.StateDir, "certs", record.TBSSHA256[0:2], "."+record.TBSSHA256+".notified")
		if fileExists(tbsMarker) {
			return true
		}
	}
	if record.CertSHA256 == "" || len(record.CertSHA256) < 2 {
		return false
	}
	certDir := filepath.Join(s.StateDir, "certs", record.CertSHA256[0:2])
	for _, filename := range []string{
		"." + record.CertSHA256 + ".notified",
		record.CertSHA256 + ".cert.pem",
		record.CertSHA256 + ".precert.pem",
	} {
		if fileExists(filepath.Join(certDir, filename)) {
			return true
		}
	}
	return false
}

// RecoverPendingCerts is an alias for callers that name this operation after
// the domain object rather than the notification record.
func (s *FilesystemState) RecoverPendingCerts(ctx context.Context) error {
	return s.RecoverPendingNotifications(ctx)
}

// RecoverDiscoveredCertificates is a descriptive alias for startup recovery.
func (s *FilesystemState) RecoverDiscoveredCertificates(ctx context.Context) error {
	return s.RecoverPendingNotifications(ctx)
}

// Recover is a short alias for startup recovery.
func (s *FilesystemState) Recover(ctx context.Context) error {
	return s.RecoverPendingNotifications(ctx)
}

// ReplayPendingNotifications is an alias that emphasizes delivery retry.
func (s *FilesystemState) ReplayPendingNotifications(ctx context.Context) error {
	return s.RecoverPendingNotifications(ctx)
}

func (s *FilesystemState) completePendingNotification(record *pendingNotificationRecord) error {
	if record.SaveCerts && record.TBSSHA256 != "" {
		tbsDir := filepath.Join(s.StateDir, "certs", record.TBSSHA256[0:2])
		notifiedPath := filepath.Join(tbsDir, "."+record.TBSSHA256+".notified")
		if err := os.MkdirAll(tbsDir, 0777); err != nil {
			return err
		}
		if err := writeFile(notifiedPath, nil, 0666); err != nil {
			return err
		}
	}

	for _, file := range record.Files {
		if err := os.Remove(file.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	if err := os.Remove(s.pendingNotificationPath(record.ID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
