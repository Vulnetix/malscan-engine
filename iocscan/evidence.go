package iocscan

import (
	"os"
	"runtime"
	"time"

	"github.com/vulnetix/malscan-engine/detect"
)

// HostInfo captures the host the scan ran on, so evidence is self-describing
// when collected from many machines (CI runners, processor workers).
type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`   // runtime.GOOS
	Arch     string `json:"arch"` // runtime.GOARCH
	PID      int    `json:"pid"`
	ScanTime string `json:"scanTime"` // RFC3339, when the scan started
}

// hostInfo collects the current host's details. A failed os.Hostname is
// non-fatal — the field is left blank.
func hostInfo(now time.Time) HostInfo {
	name, _ := os.Hostname()
	return HostInfo{
		Hostname: name,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		PID:      os.Getpid(),
		ScanTime: now.UTC().Format(time.RFC3339),
	}
}

// Evidence is one IOC hit: which indicator matched, where (file + line/offset),
// and the surrounding file content for human review.
type Evidence struct {
	IndicatorType  IndicatorType `json:"indicatorType"`
	IndicatorValue string        `json:"indicatorValue"`
	// Indicator carries the full STIX provenance (name, description, severity,
	// labels, external references) of the matched indicator.
	Indicator *Indicator `json:"indicator,omitempty"`

	FilePath string `json:"filePath"`          // absolute path on the host
	RelPath  string `json:"relPath,omitempty"` // path relative to the scan root
	IsBinary bool   `json:"isBinary,omitempty"`

	// Text-file location. LineNumber is 1-indexed; ColStart/ColEnd are 0-indexed
	// byte offsets into MatchedLine. Zero for binary matches.
	LineNumber  int    `json:"lineNumber,omitempty"`
	ColStart    int    `json:"colStart,omitempty"`
	ColEnd      int    `json:"colEnd,omitempty"`
	MatchedLine string `json:"matchedLine,omitempty"`

	// ContextBefore / ContextAfter hold up to ContextLines lines above and below
	// MatchedLine (text files only).
	ContextBefore []string `json:"contextBefore,omitempty"`
	ContextAfter  []string `json:"contextAfter,omitempty"`

	// ByteOffset is the offset of the matched string within a binary file.
	ByteOffset int64 `json:"byteOffset,omitempty"`
}

// ToFinding adapts an Evidence into a detect.Finding (ClassEvidence) so callers
// can fold IOC hits into the existing finding / combination-verdict pipeline. A
// known-bad-infrastructure indicator is factual malicious evidence (CWE-506).
func (e Evidence) ToFinding() detect.Finding {
	loc := e.FilePath
	if e.RelPath != "" {
		loc = e.RelPath
	}
	desc := "file references known-bad " + string(e.IndicatorType) + " IOC " + e.IndicatorValue
	if e.Indicator != nil && e.Indicator.Name != "" {
		desc = e.Indicator.Name + " — referenced in " + loc
	}
	matched := e.MatchedLine
	if matched == "" {
		matched = e.IndicatorValue
	}
	return detect.Finding{
		ID:          "IOC-STIX-MATCH",
		Category:    "ioc",
		Class:       detect.ClassEvidence,
		CWE:         detect.DefaultMalwareCWE,
		Description: desc,
		MatchedLine: matched,
	}
}

// Warning is a non-fatal notice returned alongside results (e.g. a stale or
// checksum-mismatched feed cache was used). The engine returns these rather than
// logging, so callers decide how to surface them.
type Warning struct {
	Code       string `json:"code"`           // "stale-cache" | "checksum-mismatch" | "feed-error" | "parse-error"
	Feed       string `json:"feed,omitempty"` // cache slug the warning concerns
	Message    string `json:"message"`
	AgeSeconds int    `json:"ageSeconds,omitempty"` // age of the stale cache used
}

// Report is the complete result of a Scan.
type Report struct {
	Host           HostInfo   `json:"host"`
	Root           string     `json:"root"`
	Ecosystem      string     `json:"ecosystem,omitempty"`
	IndicatorCount int        `json:"indicatorCount"`
	FilesScanned   int        `json:"filesScanned"`
	Evidence       []Evidence `json:"evidence"`
	Warnings       []Warning  `json:"warnings,omitempty"`
	Errors         []string   `json:"errors,omitempty"`
}

// Malicious reports whether the scan produced any IOC evidence.
func (r *Report) Malicious() bool { return len(r.Evidence) > 0 }

// Findings adapts every Evidence into a detect.Finding for downstream
// integration.
func (r *Report) Findings() []detect.Finding {
	out := make([]detect.Finding, 0, len(r.Evidence))
	for _, e := range r.Evidence {
		out = append(out, e.ToFinding())
	}
	return out
}
