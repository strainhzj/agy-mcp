// Session handle records: the protected session index a managed-only
// instance issues and resolves conversation continuation handles against
// (the Phase 3 machinery). The on-disk contract mirrors the job files: one
// JSON record per handle under <stateDir>/sessions/, written atomically, so
// handles survive a server restart (same instance, same snapshot) and die on
// anything else (new instance, new snapshot, expiry).
//
// A record is control-plane state and never worker-visible: the worker's
// sandbox mounts no part of the state directory, and the handle, not the
// native agy conversation id it wraps, is the only form a caller ever sees.
package jobstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// SessionsDirName is the state-directory subdirectory holding one session
// record per handle. It lives beside jobs/ (see New) and is deliberately not
// part of the job store root: every job scan (List, GC, startup recovery)
// iterates jobs/ only, so session records never read as jobs and job GC never
// reaps them. Their lifetime is SessionTTL, independent of JobTTL.
const SessionsDirName = "sessions"

// SessionRecordFile is the per-handle record file name suffix.
const SessionRecordFile = ".json"

// SessionRecordContract is the version of the session record shape this build
// writes and accepts. A record with another contract is inert: it never
// resolves, and GC does not reap what it cannot parse (the operator sees it
// in the directory and decides).
const SessionRecordContract = 1

// SessionsDir returns the state directory subdirectory session records live in.
func SessionsDir(stateDir string) string { return filepath.Join(stateDir, SessionsDirName) }

// sessionHandlePattern is the only shape this package writes or resolves:
// the "ah" prefix plus 32 lowercase hex characters. A caller-supplied
// conversation_id must match it before it ever becomes a file name, so a
// crafted id ("../..", "ah/../../x") can never escape the sessions directory.
var sessionHandlePattern = regexp.MustCompile(`^ah[0-9a-f]{32}$`)

// ValidSessionHandle reports whether raw is the exact shape this server
// issues. It is the guard between caller input and the filesystem path the
// record is read from.
func ValidSessionHandle(raw string) bool { return sessionHandlePattern.MatchString(raw) }

// SessionRecord is one issued conversation continuation handle: the opaque
// string a caller passes as conversation_id, bound to the deployment that
// issued it and the native agy conversation id it stands for.
type SessionRecord struct {
	// Contract is SessionRecordContract in every record this build accepts.
	Contract int `json:"contract"`
	// Handle is the opaque identifier the caller sees and passes back.
	Handle string `json:"handle"`
	// ProjectID and InstanceID name the deployment that issued the handle; a
	// record only resolves on the instance that wrote it.
	ProjectID  string `json:"project_id"`
	InstanceID string `json:"instance_id"`
	// SnapshotFingerprint is the snapshot version the first turn ran against.
	// A redeployed snapshot is a new deployment: its instance refuses handles
	// from the old one instead of continuing sessions across a content change.
	SnapshotFingerprint string `json:"snapshot_fingerprint"`
	// NativeID is the agy conversation id the handle stands for. It is never
	// returned to a caller; resolution hands it to agy internally.
	NativeID string `json:"native_id"`
	// FirstJobID is the completed first-turn job whose result named NativeID,
	// the provenance the handle's authority rests on.
	FirstJobID string `json:"first_job_id"`
	// CreatedAt and ExpiresAt bound the handle's life. The expiry is
	// independent of JobTTL: the first-turn job dir may be collected long
	// before the handle it produced expires.
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionRecordPath returns the record file path for one handle.
func SessionRecordPath(stateDir, handle string) (string, error) {
	if !ValidSessionHandle(handle) {
		return "", fmt.Errorf("invalid session handle %q", handle)
	}
	return filepath.Join(SessionsDir(stateDir), handle+SessionRecordFile), nil
}

// WriteSessionRecord atomically and durably writes one session record,
// creating the sessions directory when needed. The handle must already have
// the exact issued shape (see ValidSessionHandle).
func WriteSessionRecord(stateDir string, r SessionRecord) error {
	path, err := SessionRecordPath(stateDir, r.Handle)
	if err != nil {
		return err
	}
	if err := MkdirAllDurable(SessionsDir(stateDir), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFileAtomicDurable(filepath.Dir(path), filepath.Base(path), b)
}

// ReadSessionRecord reads one session record. Every failure (absent,
// unreadable, malformed, wrong handle shape) is surfaced: resolution treats
// them all as "not a handle of this server", never as an empty default.
func ReadSessionRecord(stateDir, handle string) (SessionRecord, error) {
	path, err := SessionRecordPath(stateDir, handle)
	if err != nil {
		return SessionRecord{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return SessionRecord{}, err
	}
	var r SessionRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return SessionRecord{}, err
	}
	return r, nil
}

// RemoveSessionRecord deletes one session record. A missing record removes
// nothing and reports no error (removal is best effort in GC).
func RemoveSessionRecord(stateDir, handle string) error {
	path, err := SessionRecordPath(stateDir, handle)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ListSessionHandles returns every handle-shaped record name in the sessions
// directory. Entries that are not handle files (temp files from an interrupted
// write, operator notes) are skipped: they can never resolve anyway, and GC
// must not delete what it cannot attribute.
func ListSessionHandles(stateDir string) ([]string, error) {
	entries, err := os.ReadDir(SessionsDir(stateDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		handle, ok := cutSuffix(name, SessionRecordFile)
		if !ok || !ValidSessionHandle(handle) {
			continue
		}
		out = append(out, handle)
	}
	return out, nil
}

// cutSuffix reports whether s ends with suffix and returns the part before it.
func cutSuffix(s, suffix string) (string, bool) {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)], true
	}
	return "", false
}
