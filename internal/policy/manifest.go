// Package policy: the project manifest a protected (pi profile) deployment
// loads at startup, and the strict decoding it demands.
//
// The manifest is the deployment-side statement of what this instance serves:
// which project, which snapshot version, and where that snapshot lives on the
// host. It is produced by the controlled pipeline (deploy/launch-pi.sh writes
// it next to the instance's control-plane state) and read by the control plane
// only; the worker never sees it, and no tool parameter can supply any of its
// values. internal/config owns the environment mapping and the checks that
// need the state directory; this file owns the file format and the field
// rules, so the two cannot drift on what a manifest means.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ManifestSchemaVersion is the only project-manifest contract version this
// build understands. A manifest carrying any other value is refused rather
// than guessed at, because a newer manifest may carry rules this build does
// not implement.
const ManifestSchemaVersion = 1

// WorkerMountPath is the neutral, worker-view mount point a protected
// instance serves its project snapshot at. It is fixed by the profile, not
// configurable: the control plane runs in the host view (where no such mount
// exists) and maps between the two, so a caller-visible path never names a
// host path.
const WorkerMountPath = "/workspace"

// FingerprintPrefix is the only accepted snapshot-fingerprint encoding: a
// lowercase SHA-256 digest with an explicit algorithm tag, so a future
// algorithm change is a contract change rather than an ambiguous longer hex
// string.
const FingerprintPrefix = "sha256:"

// ManifestFields are the required top-level fields, in the order the manifest
// writer emits them. It exists so the unknown-field check and the
// required-field check read from one list.
var manifestFields = []string{
	"schema_version", "project_id", "snapshot_root",
	"snapshot_fingerprint", "worker_mount", "read_only",
}

// projectIDPattern bounds a project id to characters the launcher can bake
// into generated scripts and JSON without quoting surprises. It is the same
// shape the launcher enforces on PI_PROJECT_ID.
var projectIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// fingerprintPattern is the snapshot fingerprint shape: "sha256:" plus 64
// lowercase hex characters.
var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ProjectManifest is the decoded, validated project manifest. Every field is
// deployment-assigned: nothing here comes from a tool call, and a protected
// instance refuses to start without a manifest that satisfies all of these
// rules.
type ProjectManifest struct {
	// SchemaVersion must be ManifestSchemaVersion.
	SchemaVersion int `json:"schema_version"`
	// ProjectID is the deployment-assigned project identity.
	ProjectID string `json:"project_id"`
	// SnapshotRoot is the host-side absolute path of the read-only snapshot
	// this instance serves. It is the host side of the WorkerMount mapping.
	SnapshotRoot string `json:"snapshot_root"`
	// SnapshotFingerprint binds the instance to one snapshot version
	// ("sha256:<64 hex>").
	SnapshotFingerprint string `json:"snapshot_fingerprint"`
	// WorkerMount must be WorkerMountPath.
	WorkerMount string `json:"worker_mount"`
	// ReadOnly must be true: a protected instance serves a read-only snapshot.
	ReadOnly bool `json:"read_only"`
}

// LoadProjectManifest reads and validates the manifest at path. Every failure
// is fail-closed: the caller must treat an error as a startup failure, never
// as a reason to continue with a partially understood manifest.
//
// The checks are the file-format half of the startup gate. The checks that
// need the state directory (the manifest must not live inside it, and the
// snapshot root must not overlap it) live in internal/config, which owns the
// state directory.
func LoadProjectManifest(path string) (ProjectManifest, error) {
	if path == "" {
		return ProjectManifest{}, fmt.Errorf("project manifest path is empty")
	}
	if !filepath.IsAbs(path) {
		return ProjectManifest{}, fmt.Errorf("project manifest path %q is not absolute", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return ProjectManifest{}, fmt.Errorf("read project manifest %s: %w", path, err)
	}
	if info.IsDir() {
		return ProjectManifest{}, fmt.Errorf("project manifest %s is a directory", path)
	}
	// The manifest is deployment-owned configuration. A group- or world-writable
	// one could be rewritten by anything the worker can reach, so refuse it
	// rather than trusting a file another process may edit.
	if info.Mode().Perm()&0o022 != 0 {
		return ProjectManifest{}, fmt.Errorf("project manifest %s is group- or world-writable (%s); the deployment must write it 0440 or tighter", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ProjectManifest{}, fmt.Errorf("read project manifest %s: %w", path, err)
	}
	fields, err := decodeStrictObject(data)
	if err != nil {
		return ProjectManifest{}, fmt.Errorf("project manifest %s is not a strict JSON object: %w", path, err)
	}
	for _, name := range manifestFields {
		if _, ok := fields[name]; !ok {
			return ProjectManifest{}, fmt.Errorf("project manifest %s is missing the required field %q", path, name)
		}
	}
	var m ProjectManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return ProjectManifest{}, fmt.Errorf("project manifest %s: %w", path, err)
	}
	if m.SchemaVersion != ManifestSchemaVersion {
		return ProjectManifest{}, fmt.Errorf("project manifest %s has schema_version %d; this build understands version %d", path, m.SchemaVersion, ManifestSchemaVersion)
	}
	if !projectIDPattern.MatchString(m.ProjectID) {
		return ProjectManifest{}, fmt.Errorf("project manifest %s has project_id %q; want 1-64 characters of lowercase letters, digits, dot, dash or underscore, starting with a letter or digit", path, m.ProjectID)
	}
	if !filepath.IsAbs(m.SnapshotRoot) {
		return ProjectManifest{}, fmt.Errorf("project manifest %s has snapshot_root %q; want an absolute host path", path, m.SnapshotRoot)
	}
	if !fingerprintPattern.MatchString(m.SnapshotFingerprint) {
		return ProjectManifest{}, fmt.Errorf("project manifest %s has snapshot_fingerprint %q; want %s followed by 64 lowercase hex characters", path, m.SnapshotFingerprint, FingerprintPrefix)
	}
	if m.WorkerMount != WorkerMountPath {
		return ProjectManifest{}, fmt.Errorf("project manifest %s has worker_mount %q; the protected profile fixes it at %s", path, m.WorkerMount, WorkerMountPath)
	}
	if !m.ReadOnly {
		return ProjectManifest{}, fmt.Errorf("project manifest %s has read_only %v; a protected instance serves a read-only snapshot, so it must be true", path, m.ReadOnly)
	}
	return m, nil
}

// decodeStrictObject decodes a JSON object into its raw fields, rejecting
// unknown fields and duplicate keys. encoding/json alone cannot do either: it
// silently drops unknown fields and keeps the last of a duplicated key, so a
// manifest with a typo'd field name or a redefined field would load as if it
// were the intended one.
func decodeStrictObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("want a JSON object")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("object keys must be strings")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		if _, dup := fields[key]; dup {
			return nil, fmt.Errorf("duplicate field %q", key)
		}
		fields[key] = raw
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected data after the JSON object")
	}
	return fields, nil
}

// SnapshotRootCanonical canonicalizes the manifest's snapshot root for the
// policy: EvalSymlinks first (see resolveExistingDir), then Abs, and it must
// exist and be a directory. It is separate from LoadProjectManifest so the
// caller controls when the filesystem is consulted, and so the error names
// the manifest field rather than the file.
func (m ProjectManifest) SnapshotRootCanonical() (string, error) {
	if !filepath.IsAbs(m.SnapshotRoot) {
		return "", fmt.Errorf("snapshot_root %q is not absolute", m.SnapshotRoot)
	}
	return resolveExistingDir(m.SnapshotRoot)
}
