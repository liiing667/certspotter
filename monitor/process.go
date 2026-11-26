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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ctclient"
	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
)

type LogEntry struct {
	ctclient.Entry
	Index uint64
	Log   *loglist.Log
}

// ProcessLogEntry verifies and processes one downloaded CT log entry.  It is
// the exported form of the monitor's internal processing boundary.
func ProcessLogEntry(ctx context.Context, config *Config, issuerGetter ctclient.IssuerGetter, entry *LogEntry) error {
	return processLogEntry(ctx, config, issuerGetter, entry)
}

// ProcessEntry is a concise alias for ProcessLogEntry.
func ProcessEntry(ctx context.Context, config *Config, issuerGetter ctclient.IssuerGetter, entry *LogEntry) error {
	return ProcessLogEntry(ctx, config, issuerGetter, entry)
}

func processLogEntry(ctx context.Context, config *Config, issuerGetter ctclient.IssuerGetter, entry *LogEntry) error {
	leaf, err := cttypes.ParseLeafInput(entry.LeafInput())
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error parsing Merkle Tree Leaf: %w", err))
	}
	switch leaf.TimestampedEntry.EntryType {
	case cttypes.X509EntryType:
		return processX509LogEntry(ctx, config, issuerGetter, entry, leaf.TimestampedEntry.SignedEntryASN1Cert)
	case cttypes.PrecertEntryType:
		return processPrecertLogEntry(ctx, config, issuerGetter, entry, leaf.TimestampedEntry.SignedEntryPreCert)
	default:
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("unknown log entry type %d", leaf.TimestampedEntry.EntryType))
	}
}

func processX509LogEntry(ctx context.Context, config *Config, issuerGetter ctclient.IssuerGetter, entry *LogEntry, cert *cttypes.ASN1Cert) error {
	certInfo, err := certspotter.MakeCertInfoFromRawCert(*cert)
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error parsing X.509 certificate: %w", err))
	}
	if precertTBS, err := certspotter.ReconstructPrecertTBS(certInfo.TBS); err == nil {
		certInfo.TBS = precertTBS
	} else {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error reconstructing precertificate TBSCertificate: %w", err))
	}

	getChain := func(ctx context.Context) ([]cttypes.ASN1Cert, error) {
		var (
			chain = []cttypes.ASN1Cert{*cert}
			errs  = []error{}
		)
		if issuers, err := entry.GetChain(ctx, issuerGetter); err == nil {
			chain = append(chain, issuers...)
		} else {
			errs = append(errs, err)
		}
		return chain, errors.Join(errs...)
	}
	return processCertificate(ctx, config, entry, certInfo, getChain)
}

func processPrecertLogEntry(ctx context.Context, config *Config, issuerGetter ctclient.IssuerGetter, entry *LogEntry, precert *cttypes.PreCert) error {
	certInfo, err := certspotter.MakeCertInfoFromRawTBS(precert.TBSCertificate)
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error parsing precert TBSCertificate: %w", err))
	}
	precertBytes, err := entry.Precertificate()
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error getting precert entry's precertificate: %w", err))
	}
	if validationErr := VerifyPrecertIdentity(precertBytes, precert.TBSCertificate); validationErr != nil {
		mismatch := newIdentityMismatchError(precertBytes, precert.TBSCertificate, validationErr)
		return processIdentityMismatch(ctx, config, entry, mismatch)
	}

	getChain := func(ctx context.Context) ([]cttypes.ASN1Cert, error) {
		var (
			chain = []cttypes.ASN1Cert{precertBytes}
			errs  = []error{}
		)
		if issuers, err := entry.GetChain(ctx, issuerGetter); err == nil {
			chain = append(chain, issuers...)
		} else {
			errs = append(errs, err)
		}
		if _, err := certspotter.ValidatePrecert(precertBytes, precert.TBSCertificate); err != nil {
			mismatch := newIdentityMismatchError(precertBytes, precert.TBSCertificate, err)
			errs = append(errs, fmt.Errorf("precertificate in extra_data does not match TBSCertificate in leaf_input: %w", mismatch))
		}
		return chain, errors.Join(errs...)
	}
	return processCertificate(ctx, config, entry, certInfo, getChain)
}

func processCertificate(ctx context.Context, config *Config, entry *LogEntry, certInfo *certspotter.CertInfo, getChain func(context.Context) ([]cttypes.ASN1Cert, error)) error {
	identifiers, err := certInfo.ParseIdentifiers()
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, err)
	}
	matched, watchItem := config.WatchList.Matches(identifiers)
	if !matched {
		return nil
	}

	chain, chainErr := getChain(ctx)
	if chainErr != nil {
		if ctx.Err() != nil {
			// Getting chain failed, but it was probably because our context
			// has been canceled, so just act like we never called getChain.
			return ctx.Err()
		}
		// Although getting the chain failed, we still want to notify
		// the user about the matching certificate. We'll include chainErr in the
		// notification so the user knows why the chain is missing or incorrect.
	}

	cert := &DiscoveredCert{
		WatchItem:    watchItem,
		LogEntry:     entry,
		Info:         certInfo,
		Chain:        chain,
		ChainError:   chainErr,
		TBSSHA256:    sha256.Sum256(certInfo.TBS.Raw),
		SHA256:       sha256.Sum256(chain[0]),
		PubkeySHA256: sha256.Sum256(certInfo.TBS.PublicKey.FullBytes),
		Identifiers:  identifiers,
		// Precert entries have passed ValidatePrecert above.  X.509 entries
		// are parsed from the exact DER certificate and ReconstructPrecertTBS
		// only removes SCT extension data from that same parsed TBS.
		IdentityVerified: true,
	}

	if identityErr := cert.ValidateIdentity(); identityErr != nil {
		mismatch, _ := AsIdentityMismatch(identityErr)
		if mismatch == nil {
			mismatch = &IdentityMismatchError{
				TBSSHA256:            cert.TBSSHA256,
				PrecertificateSHA256: cert.SHA256,
				Reason:               identityErr,
			}
		}
		return processIdentityMismatch(ctx, config, entry, mismatch)
	}

	// A state implementation that persists identity verdicts gets a chance to
	// suppress an exact certificate/TBS pair already rejected.  Keying by both
	// hashes means a later, genuinely different certificate is not blocked by
	// a rejection for another concrete certificate under the same TBS hash.
	if conflicts, ok := config.State.(IdentityConflictLoader); ok {
		prior, err := conflicts.LoadIdentityConflict(ctx, identityRefForCert(cert))
		if err != nil {
			return fmt.Errorf("error checking identity state for certificate %x: %w", cert.SHA256, err)
		}
		if prior != nil {
			return nil
		}
	}

	if err := config.State.NotifyCert(ctx, cert); err != nil {
		return fmt.Errorf("error notifying about certificate %x: %w", cert.SHA256, err)
	}

	return nil
}

func processIdentityMismatch(ctx context.Context, config *Config, entry *LogEntry, mismatch *IdentityMismatchError) error {
	if config.State != nil {
		if recorder, ok := config.State.(IdentityConflictRecorder); ok {
			conflict := &IdentityConflict{
				Ref: IdentityRef{
					TBSSHA256:         mismatch.TBSSHA256,
					CertificateSHA256: mismatch.PrecertificateSHA256,
				},
				Reason:     mismatch,
				LogID:      entry.Log.LogID,
				EntryIndex: entry.Index,
			}
			if err := recorder.RecordIdentityConflict(ctx, conflict); err != nil {
				return fmt.Errorf("error persisting identity rejection for leaf TBS %x: %w", mismatch.TBSSHA256, err)
			}
		}
	}
	return processMalformedLogEntry(ctx, config, entry, mismatch)
}

func processMalformedLogEntry(ctx context.Context, config *Config, entry *LogEntry, parseError error) error {
	if err := config.State.NotifyMalformedEntry(ctx, entry, parseError); err != nil {
		return fmt.Errorf("error notifying about malformed log entry %d in %s (%q): %w", entry.Index, entry.Log.GetMonitoringURL(), parseError, err)
	}
	return nil
}
