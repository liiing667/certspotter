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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/cttypes"
)

// ErrIdentityMismatch indicates that two objects which CT's precertificate
// pairing rules require to describe the same issuance instead have different
// signed identities.
var ErrIdentityMismatch = errors.New("precertificate identity does not match Merkle leaf input")

// ErrUntrustedIdentity is returned by sinks that refuse to publish a
// certificate whose identity binding has failed.
var ErrUntrustedIdentity = errors.New("certificate identity is not trusted")

// IdentityMismatchError records the two stable identities involved in an
// inconsistent CT precertificate entry.  The hashes make malformed-entry
// evidence and persistent rejection records comparable without relying on
// notification text.
type IdentityMismatchError struct {
	// TBSSHA256 is the hash of the TBSCertificate from leaf_input.
	TBSSHA256 [32]byte

	// PrecertificateSHA256 is the hash of the DER precertificate from
	// extra_data.
	PrecertificateSHA256 [32]byte

	// Reason is the lower-level precertificate validation failure.
	Reason error
}

func (e *IdentityMismatchError) Error() string {
	return fmt.Sprintf("%s: leaf TBS %x, extra_data precertificate %x: %v",
		ErrIdentityMismatch, e.TBSSHA256, e.PrecertificateSHA256, e.Reason)
}

func (e *IdentityMismatchError) Unwrap() error {
	return e.Reason
}

// Is allows errors.Is(err, ErrIdentityMismatch) to match both this structured
// error and wrapped validation failures used by older code paths.
func (e *IdentityMismatchError) Is(target error) bool {
	return target == ErrIdentityMismatch
}

// AsIdentityMismatch finds a structured identity mismatch in err.
func AsIdentityMismatch(err error) (*IdentityMismatchError, bool) {
	var mismatch *IdentityMismatchError
	if errors.As(err, &mismatch) {
		return mismatch, true
	}
	return nil, false
}

// IsIdentityMismatch reports whether err is a definitive identity-binding
// failure rather than a transient chain-fetch or parsing error.
func IsIdentityMismatch(err error) bool {
	return errors.Is(err, ErrIdentityMismatch) || isLegacyIdentityMismatch(err)
}

// isLegacyIdentityMismatch recognizes errors produced before identity failures
// had a structured type.  The phrase is specific to certspotter's precert/TBS
// validation wrapper, so ordinary chain retrieval errors do not match.
func isLegacyIdentityMismatch(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "precertificate in extra_data does not match TBSCertificate in leaf_input")
}

// VerifyPrecertIdentity checks that the precertificate from extra_data is the
// precertificate corresponding to the TBSCertificate in the Merkle leaf input.
func VerifyPrecertIdentity(precertificate cttypes.ASN1Cert, leafTBS cttypes.TBSCertificate) error {
	_, err := certspotter.ValidatePrecert(precertificate, leafTBS)
	return err
}

func newIdentityMismatchError(precertificate cttypes.ASN1Cert, leafTBS cttypes.TBSCertificate, reason error) *IdentityMismatchError {
	return &IdentityMismatchError{
		TBSSHA256:            sha256.Sum256(leafTBS),
		PrecertificateSHA256: sha256.Sum256(precertificate),
		Reason:               reason,
	}
}

// IdentityRef identifies one claimed TBS identity and the concrete certificate
// bytes that were supposed to realize it.  Identity decisions are keyed by the
// pair, not by TBS alone, so distinct certificates can never overwrite each
// other's rejection evidence.
type IdentityRef struct {
	TBSSHA256         [32]byte
	CertificateSHA256 [32]byte
}

// IdentityConflict is a durable rejection conclusion for an IdentityRef.
type IdentityConflict struct {
	Ref           IdentityRef
	Reason        error
	LogID         LogID
	EntryIndex    uint64
	FirstObserved time.Time
}

// IdentityConflictRecorder is an optional StateProvider capability for
// persisting definitive identity rejections.  It is intentionally not part of
// StateProvider so existing third-party implementations remain source
// compatible.
type IdentityConflictRecorder interface {
	RecordIdentityConflict(context.Context, *IdentityConflict) error
}

// IdentityConflictLoader loads a previously persisted identity rejection.
type IdentityConflictLoader interface {
	LoadIdentityConflict(context.Context, IdentityRef) (*IdentityConflict, error)
}

// IdentityConflictStore combines recording and loading identity conflicts.
type IdentityConflictStore interface {
	IdentityConflictRecorder
	IdentityConflictLoader
}

// Compatibility aliases for callers and tests that use security-domain wording.
type (
	IdentityRejection      = IdentityConflict
	RejectedIdentity       = IdentityConflict
	IdentityRejectionStore = IdentityConflictStore
	RejectedIdentityStore  = IdentityConflictStore
)

// ValidateIdentity returns the definitive identity error attached to a
// discovered certificate, including one joined into ChainError by chain
// construction.  Transient chain-building errors do not match.
func (cert *DiscoveredCert) ValidateIdentity() error {
	if cert == nil {
		return nil
	}
	if mismatch, ok := AsIdentityMismatch(cert.IdentityError); ok {
		return mismatch
	}
	if mismatch, ok := AsIdentityMismatch(cert.ChainError); ok {
		return mismatch
	}
	if isLegacyIdentityMismatch(cert.ChainError) {
		return &IdentityMismatchError{
			TBSSHA256:            cert.TBSSHA256,
			PrecertificateSHA256: cert.SHA256,
			Reason:               cert.ChainError,
		}
	}
	if IsIdentityMismatch(cert.IdentityError) {
		return cert.IdentityError
	}
	return nil
}

// IdentityConsistent reports whether the certificate's TBS and concrete
// certificate/precertificate identities are known to be consistent.
func (cert *DiscoveredCert) IdentityConsistent() bool {
	return cert.ValidateIdentity() == nil
}

// TrustedIdentity reports whether the certificate may continue through the
// trusted discovered-certificate stream.  Chain availability is deliberately
// not part of this predicate: certspotter has always reported matching
// certificates with a ChainError when issuer retrieval fails.
func (cert *DiscoveredCert) TrustedIdentity() bool {
	return cert.IdentityConsistent()
}

// IsTrustedCertificate is a domain-readable alias for TrustedIdentity.
func (cert *DiscoveredCert) IsTrustedCertificate() bool {
	return cert.TrustedIdentity()
}

// IsTrustedCertificate reports whether cert may enter the trusted discovered
// certificate stream.
func IsTrustedCertificate(cert *DiscoveredCert) bool {
	return cert != nil && cert.TrustedIdentity()
}

// CanEnterTrustedCertificateStream is an explicit domain-name alias for
// IsTrustedCertificate.
func CanEnterTrustedCertificateStream(cert *DiscoveredCert) bool {
	return IsTrustedCertificate(cert)
}

func identityRefForCert(cert *DiscoveredCert) IdentityRef {
	if cert == nil {
		return IdentityRef{}
	}
	return IdentityRef{TBSSHA256: cert.TBSSHA256, CertificateSHA256: cert.SHA256}
}

func hexIdentityHash(hash [32]byte) string {
	return hex.EncodeToString(hash[:])
}
