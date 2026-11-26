// Copyright (C) 2020 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package loglist

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"software.sslmate.com/src/certspotter/cttypes"
)

// maxSignedListAge is the maximum age of a signed log list, as determined
// by its log_list_timestamp.
const maxSignedListAge = 48 * time.Hour

// maxSignedListFutureSkew is how far in the future a signed log list's
// log_list_timestamp may be, to allow for clock skew between the signer
// and the verifier.
const maxSignedListFutureSkew = 24 * time.Hour

func (list *List) Validate() error {
	seenLogIDs := make(map[cttypes.LogID]string)
	for i := range list.Operators {
		operator := &list.Operators[i]
		if err := operator.Validate(); err != nil {
			return fmt.Errorf("problem with %dth operator (%s): %w", i, operator.Name, err)
		}
		for j := range operator.Logs {
			log := &operator.Logs[j]
			if otherOperator, duplicated := seenLogIDs[log.LogID]; duplicated {
				return fmt.Errorf("log ID %s is assigned to more than one operator (%q and %q)", log.LogIDString(), otherOperator, operator.Name)
			}
			seenLogIDs[log.LogID] = operator.Name
		}
		for j := range operator.TiledLogs {
			log := &operator.TiledLogs[j]
			if otherOperator, duplicated := seenLogIDs[log.LogID]; duplicated {
				return fmt.Errorf("log ID %s is assigned to more than one operator (%q and %q)", log.LogIDString(), otherOperator, operator.Name)
			}
			seenLogIDs[log.LogID] = operator.Name
		}
	}
	return nil
}

func (list *List) validateSigned(name string, now time.Time) error {
	// log_list_name is optional (not all publishers include it), but when
	// present it must equal the base name of the signed archive, so that a
	// signed list intended for a different environment/name cannot be
	// substituted for the expected list.
	if list.LogListName != "" && list.LogListName != name {
		return fmt.Errorf("log_list_name is %q, want %q", list.LogListName, name)
	}
	if list.LogListTimestamp.IsZero() {
		return errors.New("log_list_timestamp is missing")
	}
	if age := now.Sub(list.LogListTimestamp); age > maxSignedListAge {
		return fmt.Errorf("log_list_timestamp (%s) is more than %v in the past", list.LogListTimestamp.Format(time.RFC3339), maxSignedListAge)
	}
	if skew := list.LogListTimestamp.Sub(now); skew > maxSignedListFutureSkew {
		return fmt.Errorf("log_list_timestamp (%s) is more than %v in the future", list.LogListTimestamp.Format(time.RFC3339), maxSignedListFutureSkew)
	}
	return nil
}

func (operator *Operator) Validate() error {
	for i := range operator.Logs {
		if err := operator.Logs[i].Validate(); err != nil {
			return fmt.Errorf("problem with %dth non-tiled log (%s): %w", i, operator.Logs[i].LogIDString(), err)
		}
	}
	for i := range operator.TiledLogs {
		if err := operator.TiledLogs[i].Validate(); err != nil {
			return fmt.Errorf("problem with %dth tiled log (%s): %w", i, operator.TiledLogs[i].LogIDString(), err)
		}
	}
	return nil
}

func (log *Log) Validate() error {
	realLogID := sha256.Sum256(log.Key)
	if log.LogID != realLogID {
		return fmt.Errorf("log ID does not match log key")
	}

	if !log.IsRFC6962() && !log.IsStaticCTAPI() {
		return fmt.Errorf("URL(s) not provided")
	} else if log.IsRFC6962() && log.IsStaticCTAPI() {
		return fmt.Errorf("inconsistent URLs provided")
	}

	if log.MMD < 0 {
		return fmt.Errorf("log has a negative MMD")
	}

	return nil
}
