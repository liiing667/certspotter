// Copyright (C) 2026 Opsmate, Inc.
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
	"strings"
	"testing"
	"time"
)

func validLog() Log {
	key := []byte("not a real log key")
	return Log{
		Key:         key,
		LogID:       sha256.Sum256(key),
		MMD:         86400,
		URL:         "https://ct.example.com/",
		Description: testLogDescription,
	}
}

func validStaticLog() Log {
	log := validLog()
	log.URL = ""
	log.SubmissionURL = "https://ct.example.com/submit/"
	log.MonitoringURL = "https://ct.example.com/monitor/"
	return log
}

func checkValidateError(t *testing.T, list *List, want string) {
	t.Helper()
	err := list.Validate()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got error %v, want error containing %q", err, want)
	}
}

func TestValidateValidLists(t *testing.T) {
	rfc6962List := &List{Operators: []Operator{{
		Name: "Operator A",
		Logs: []Log{validLog()},
	}}}
	if err := rfc6962List.Validate(); err != nil {
		t.Fatalf("RFC 6962 list: %v", err)
	}

	staticList := &List{Operators: []Operator{{
		Name:      "Operator A",
		TiledLogs: []Log{validStaticLog()},
	}}}
	if err := staticList.Validate(); err != nil {
		t.Fatalf("static-ct-api list: %v", err)
	}
}

func TestValidateDuplicateLogID(t *testing.T) {
	first := validLog()

	t.Run("SameOperator", func(t *testing.T) {
		second := validLog()
		second.URL = "https://ct2.example.com/"
		list := &List{Operators: []Operator{{
			Name: "Operator A",
			Logs: []Log{first, second},
		}}}
		checkValidateError(t, list, "duplicate log ID")
	})

	t.Run("DifferentOperators", func(t *testing.T) {
		list := &List{Operators: []Operator{
			{Name: "Operator A", Logs: []Log{first}},
			{Name: "Operator B", TiledLogs: []Log{validStaticLog()}},
		}}
		err := list.Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicate log ID") {
			t.Fatalf("got error %v, want duplicate log ID error", err)
		}
		if !strings.Contains(err.Error(), "Operator A") {
			t.Fatalf("error %v should name the first operator", err)
		}
	})

	t.Run("DistinctIDsAccepted", func(t *testing.T) {
		second := validLog()
		second.Key = []byte("a different log key")
		second.LogID = sha256.Sum256(second.Key)
		second.URL = "https://ct2.example.com/"
		list := &List{Operators: []Operator{
			{Name: "Operator A", Logs: []Log{first}},
			{Name: "Operator B", Logs: []Log{second}},
		}}
		if err := list.Validate(); err != nil {
			t.Fatalf("list with distinct log IDs should be valid: %v", err)
		}
	})
}

func TestValidateLogURLs(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*Log)
		wantError string
	}{
		{"NoURLs", func(log *Log) { log.URL = "" }, "URL(s) not provided"},
		{"HTTPURL", func(log *Log) { log.URL = "http://ct.example.com/" }, "must be an absolute https:// URL"},
		{"NoHost", func(log *Log) { log.URL = "https:///path/" }, "must be an absolute https:// URL"},
		{"RelativeURL", func(log *Log) { log.URL = "/ct/v1/" }, "must be an absolute https:// URL"},
		{"MalformedURL", func(log *Log) { log.URL = "https:// ct.example.com/" }, "not a valid URL"},
		{"MixedURLs", func(log *Log) { log.SubmissionURL = "https://ct.example.com/submit/" }, "inconsistent URLs"},
		{"StaticMissingMonitoring", func(log *Log) {
			log.URL = ""
			log.SubmissionURL = "https://ct.example.com/submit/"
		}, "requires both submission_url and monitoring_url"},
		{"StaticMissingSubmission", func(log *Log) {
			log.URL = ""
			log.MonitoringURL = "https://ct.example.com/monitor/"
		}, "requires both submission_url and monitoring_url"},
		{"StaticHTTPSubmission", func(log *Log) {
			log.URL = ""
			log.SubmissionURL = "http://ct.example.com/submit/"
			log.MonitoringURL = "https://ct.example.com/monitor/"
		}, "must be an absolute https:// URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := validLog()
			tc.mutate(&log)
			err := log.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("got error %v, want error containing %q", err, tc.wantError)
			}
		})
	}
}

func TestValidateLogIDMismatch(t *testing.T) {
	log := validLog()
	log.LogID = sha256.Sum256([]byte("some other key"))
	list := &List{Operators: []Operator{{Name: "Operator A", Logs: []Log{log}}}}
	checkValidateError(t, list, "log ID does not match log key")
}

func TestValidateNegativeMMD(t *testing.T) {
	log := validLog()
	log.MMD = -1
	list := &List{Operators: []Operator{{Name: "Operator A", Logs: []Log{log}}}}
	checkValidateError(t, list, "negative MMD")
}

func TestUnmarshalRejectsInvalidListEntirely(t *testing.T) {
	// A list containing both a valid and a duplicated entry must not yield
	// any loadable fragment: Unmarshal fails for the whole document.
	good := validLog()
	evil := validLog()
	evil.SubmissionURL = "http://evil.example.com/"
	evil.MonitoringURL = "http://evil.example.com/monitor/"
	list := &List{Operators: []Operator{
		{Name: "Operator A", Logs: []Log{good}},
		{Name: "Operator B", TiledLogs: []Log{evil}},
	}}
	if _, err := Unmarshal(marshalList(t, list)); err == nil {
		t.Fatal("expected corrupt list to be rejected, not partially loaded")
	}

	// Sanity check: the same entries with distinct IDs and proper URLs load.
	evil = validStaticLog()
	evil.Key = []byte("a different log key")
	evil.LogID = sha256.Sum256(evil.Key)
	list.Operators[1].TiledLogs = []Log{evil}
	if _, err := Unmarshal(marshalList(t, list)); err != nil {
		t.Fatalf("valid list should load: %v", err)
	}
}

func TestUnmarshalSignedRejectsFutureTimestamp(t *testing.T) {
	privkey := generateECDSAKey(t)
	pubkey := marshalPubkey(t, privkey)

	now := time.Date(2026, time.October, 29, 12, 0, 0, 0, time.UTC)
	list := testList()
	list.LogListTimestamp = now.Add(time.Second)
	zipBytes := makeSignedZipJSON(t, privkey, "log_list", marshalList(t, list))

	_, err := unmarshalSigned(zipBytes, "log_list.zip", pubkey, now)
	if err == nil || !strings.Contains(err.Error(), "in the future") {
		t.Fatalf("got error %v, want future timestamp error", err)
	}

	// Exactly now is acceptable; the past within the max age is acceptable.
	list.LogListTimestamp = now
	zipBytes = makeSignedZipJSON(t, privkey, "log_list", marshalList(t, list))
	if _, err := unmarshalSigned(zipBytes, "log_list.zip", pubkey, now); err != nil {
		t.Fatalf("timestamp equal to now should be accepted: %v", err)
	}
}

func TestUnmarshalSignedRejectsDuplicateAndBadURL(t *testing.T) {
	privkey := generateECDSAKey(t)
	pubkey := marshalPubkey(t, privkey)

	t.Run("DuplicateLogID", func(t *testing.T) {
		list := testList()
		dup := validLog()
		list.Operators = append(list.Operators, Operator{
			Name: "Rogue Operator",
			Logs: []Log{dup},
		})
		zipBytes := makeSignedZipJSON(t, privkey, "log_list", marshalList(t, list))
		_, err := UnmarshalSigned(zipBytes, "log_list.zip", pubkey)
		if err == nil || !strings.Contains(err.Error(), "duplicate log ID") {
			t.Fatalf("got error %v, want duplicate log ID error", err)
		}
	})

	t.Run("BadURL", func(t *testing.T) {
		list := testList()
		list.Operators[0].Logs[0].URL = "http://monitoring.example.com/"
		zipBytes := makeSignedZipJSON(t, privkey, "log_list", marshalList(t, list))
		_, err := UnmarshalSigned(zipBytes, "log_list.zip", pubkey)
		if err == nil || !strings.Contains(err.Error(), "https:// URL") {
			t.Fatalf("got error %v, want invalid URL error", err)
		}
	})
}
