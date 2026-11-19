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
	"net/url"
	"time"

	"software.sslmate.com/src/certspotter/cttypes"
)

// maxSignedListAge is the maximum age of a signed log list, as determined
// by its log_list_timestamp.
const maxSignedListAge = 48 * time.Hour

func (list *List) Validate() error {
	seenLogIDs := make(map[cttypes.LogID]string)
	for i := range list.Operators {
		if err := list.Operators[i].Validate(); err != nil {
			return fmt.Errorf("problem with %dth operator (%s): %w", i, list.Operators[i].Name, err)
		}
		if err := list.Operators[i].checkUniqueLogIDs(seenLogIDs); err != nil {
			return fmt.Errorf("problem with %dth operator (%s): %w", i, list.Operators[i].Name, err)
		}
	}
	return nil
}

// checkUniqueLogIDs rejects a log ID that appears more than once in the list,
// whether under the same operator or a different one.  seenLogIDs maps each
// log ID to the name of the first operator that contains it.
func (operator *Operator) checkUniqueLogIDs(seenLogIDs map[cttypes.LogID]string) error {
	check := func(log *Log) error {
		if firstOperator, exists := seenLogIDs[log.LogID]; exists {
			return fmt.Errorf("duplicate log ID %s (also listed by operator %q)", log.LogIDString(), firstOperator)
		}
		seenLogIDs[log.LogID] = operator.Name
		return nil
	}
	for i := range operator.Logs {
		if err := check(&operator.Logs[i]); err != nil {
			return fmt.Errorf("problem with %dth non-tiled log (%s): %w", i, operator.Logs[i].LogIDString(), err)
		}
	}
	for i := range operator.TiledLogs {
		if err := check(&operator.TiledLogs[i]); err != nil {
			return fmt.Errorf("problem with %dth tiled log (%s): %w", i, operator.TiledLogs[i].LogIDString(), err)
		}
	}
	return nil
}

func (list *List) validateSigned(name string, now time.Time) error {
	if list.LogListName != "" && list.LogListName != name {
		return fmt.Errorf("log_list_name is %q, want %q", list.LogListName, name)
	}
	if list.LogListTimestamp.IsZero() {
		return errors.New("log_list_timestamp is missing")
	}
	if list.LogListTimestamp.After(now) {
		return fmt.Errorf("log_list_timestamp (%s) is in the future", list.LogListTimestamp.Format(time.RFC3339))
	}
	if age := now.Sub(list.LogListTimestamp); age > maxSignedListAge {
		return fmt.Errorf("log_list_timestamp (%s) is more than %v in the past", list.LogListTimestamp.Format(time.RFC3339), maxSignedListAge)
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

	switch {
	case log.URL != "" && (log.SubmissionURL != "" || log.MonitoringURL != ""):
		return fmt.Errorf("inconsistent URLs provided: url must not be combined with submission_url or monitoring_url")
	case log.URL != "":
		// RFC 6962 log
		if err := validateLogURL("url", log.URL); err != nil {
			return err
		}
	case log.SubmissionURL != "" || log.MonitoringURL != "":
		if log.SubmissionURL == "" || log.MonitoringURL == "" {
			return fmt.Errorf("static-ct-api log requires both submission_url and monitoring_url")
		}
		if err := validateLogURL("submission_url", log.SubmissionURL); err != nil {
			return err
		}
		if err := validateLogURL("monitoring_url", log.MonitoringURL); err != nil {
			return err
		}
	default:
		return fmt.Errorf("URL(s) not provided")
	}

	if log.MMD < 0 {
		return fmt.Errorf("log has a negative MMD")
	}

	return nil
}

// validateLogURL rejects URLs that are not absolute https:// URLs with a host,
// so a malformed or wrong-scheme URL cannot point monitoring at an unexpected
// destination.
func validateLogURL(field, rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if parsedURL.Scheme != "https" || parsedURL.Host == "" {
		return fmt.Errorf("%s must be an absolute https:// URL with a host, got %q", field, rawURL)
	}
	return nil
}
