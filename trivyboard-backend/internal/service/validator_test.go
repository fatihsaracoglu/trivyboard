package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeTempDir creates a fresh temp dir and returns its absolute path.
func makeTempDir(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", name+"-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestValidateScanPathRejectsEmptyRoots verifies that fs scans are rejected
// when SCANNABLE_ROOTS is empty (the production default).
func TestValidateScanPathRejectsEmptyRoots(t *testing.T) {
	err := ValidateScanPath("/tmp", nil)
	if err == nil {
		t.Fatal("expected error when scannable roots is empty")
	}
	if !strings.Contains(err.Error(), "No scannable roots") {
		t.Errorf("expected 'No scannable roots' error, got: %v", err)
	}
}

// TestValidateScanPathRejectsDangerousPaths verifies that dangerous system
// directories are rejected even when they're under a configured root.
func TestValidateScanPathRejectsDangerousPaths(t *testing.T) {
	// Configure "/" as the only root — this should still reject /, /etc, etc.
	roots := []string{"/"}
	dangerous := []string{"/etc", "/var", "/proc", "/sys", "/dev", "/boot", "/root"}
	for _, p := range dangerous {
		// Skip /etc etc. — they exist on Linux. ValidateScanPath should
		// reject them as dangerous even though they're under "/".
		if _, err := os.Stat(p); err != nil {
			continue // path doesn't exist on this platform; skip
		}
		err := ValidateScanPath(p, roots)
		if err == nil {
			t.Errorf("expected dangerous path %s to be rejected", p)
		}
	}
}

// TestValidateScanPathAcceptsRootItself verifies that the configured root is
// itself scannable.
func TestValidateScanPathAcceptsRootItself(t *testing.T) {
	dir := makeTempDir(t, "scanroot")
	if err := ValidateScanPath(dir, []string{dir}); err != nil {
		t.Errorf("expected root itself to be allowed, got: %v", err)
	}
}

// TestValidateScanPathAcceptsChildPath verifies a subdirectory of a root is
// allowed.
func TestValidateScanPathAcceptsChildPath(t *testing.T) {
	dir := makeTempDir(t, "scanroot")
	child := filepath.Join(dir, "subdir")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := ValidateScanPath(child, []string{dir}); err != nil {
		t.Errorf("expected child path to be allowed, got: %v", err)
	}
}

// TestValidateScanPathRejectsSiblingThatLooksLikePrefix verifies the
// separator-based prefix check: /tmp/foo-evil must NOT be allowed under
// /tmp/foo even though HasPrefix("/tmp/foo-evil", "/tmp/foo") is true.
func TestValidateScanPathRejectsSiblingThatLooksLikePrefix(t *testing.T) {
	dir := makeTempDir(t, "scanroot")
	sibling := dir + "-evil"
	if err := os.Mkdir(sibling, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sibling) })
	err := ValidateScanPath(sibling, []string{dir})
	if err == nil {
		t.Errorf("expected sibling path %s to be rejected under root %s", sibling, dir)
	}
}

// TestValidateScanPathRejectsNonexistent verifies a missing path is rejected
// with a "does not exist" message.
func TestValidateScanPathRejectsNonexistent(t *testing.T) {
	dir := makeTempDir(t, "scanroot")
	missing := filepath.Join(dir, "does-not-exist")
	err := ValidateScanPath(missing, []string{dir})
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected 'does not exist' error, got: %v", err)
	}
}

// TestValidateScanPathFollowsSymlinks verifies that a symlink that resolves
// outside the configured roots is rejected.
func TestValidateScanPathFollowsSymlinks(t *testing.T) {
	root := makeTempDir(t, "scanroot")
	outside := makeTempDir(t, "outside")
	// Create a symlink inside root pointing outside.
	link := filepath.Join(root, "link-out")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation failed (running as root? %v)", err)
	}
	err := ValidateScanPath(link, []string{root})
	if err == nil {
		t.Errorf("expected symlink pointing outside root to be rejected")
	}
}

// TestValidateRepoTargetRemoteHTTPS verifies a remote https URL is accepted
// when the host is in the allowed list.
func TestValidateRepoTargetRemoteHTTPS(t *testing.T) {
	kind, err := ValidateRepoTarget("https://github.com/foo/bar.git", nil, []string{"github.com"})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if kind != "git-remote" {
		t.Errorf("expected kind 'git-remote', got %q", kind)
	}
}

// TestValidateRepoTargetRemoteHTTPSSRejectsUnknownHost verifies a remote URL
// with an unknown host is rejected.
func TestValidateRepoTargetRemoteHTTPSRejectsUnknownHost(t *testing.T) {
	_, err := ValidateRepoTarget("https://evil.example.com/x.git", nil, []string{"github.com"})
	if err == nil {
		t.Fatal("expected error for unknown git host")
	}
}

// TestValidateRepoTargetRejectsHTTP verifies that plain HTTP is rejected.
func TestValidateRepoTargetRejectsHTTP(t *testing.T) {
	_, err := ValidateRepoTarget("http://github.com/foo.git", nil, []string{"github.com"})
	if err == nil {
		t.Fatal("expected error for http:// URL")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected 'HTTPS' error, got: %v", err)
	}
}

// TestValidateRepoTargetRejectsSSH verifies that git+ssh URLs are rejected.
func TestValidateRepoTargetRejectsSSH(t *testing.T) {
	_, err := ValidateRepoTarget("ssh://git@github.com/foo.git", nil, []string{"github.com"})
	if err == nil {
		t.Fatal("expected error for ssh:// URL")
	}
}

// TestValidateRepoTargetLocalPath verifies that a local path is accepted
// when it's within the configured scannable roots.
func TestValidateRepoTargetLocalPath(t *testing.T) {
	dir := makeTempDir(t, "scanroot")
	kind, err := ValidateRepoTarget(dir, []string{dir}, nil)
	if err != nil {
		t.Fatalf("expected success for local path, got: %v", err)
	}
	if kind != "git-local" {
		t.Errorf("expected kind 'git-local', got %q", kind)
	}
}

// TestValidateRepoTargetRejectsLocalOutsideRoot verifies that a local path
// outside the configured roots is rejected.
func TestValidateRepoTargetRejectsLocalOutsideRoot(t *testing.T) {
	dir1 := makeTempDir(t, "root1")
	dir2 := makeTempDir(t, "root2")
	_, err := ValidateRepoTarget(dir2, []string{dir1}, nil)
	if err == nil {
		t.Fatal("expected error for local path outside root")
	}
}

// TestValidateScannersAcceptsAllowList verifies the scanner allow-list.
func TestValidateScannersAcceptsAllowList(t *testing.T) {
	if err := ValidateScanners(nil); err != nil {
		t.Errorf("nil scanners should pass, got: %v", err)
	}
	if err := ValidateScanners([]string{"vuln", "misconfig", "secret", "license"}); err != nil {
		t.Errorf("standard scanner set should pass, got: %v", err)
	}
	if err := ValidateScanners([]string{"VULN", "Misconfig"}); err != nil {
		t.Errorf("mixed-case scanners should pass (normalized), got: %v", err)
	}
}

// TestValidateScannersRejectsUnknown verifies unknown scanner IDs are
// rejected with the typed error.
func TestValidateScannersRejectsUnknown(t *testing.T) {
	err := ValidateScanners([]string{"vuln", "evil"})
	if err == nil {
		t.Fatal("expected error for unknown scanner")
	}
	ise, ok := err.(*InvalidScannerError)
	if !ok {
		t.Fatalf("expected *InvalidScannerError, got %T: %v", err, err)
	}
	if ise.Scanner != "evil" {
		t.Errorf("expected scanner 'evil', got %q", ise.Scanner)
	}
}

// TestNormalizeScannersDedupes verifies normalization de-dupes + lowercases.
func TestNormalizeScannersDedupes(t *testing.T) {
	got := NormalizeScanners([]string{"VULN", "vuln", "Misconfig", ""})
	want := []string{"vuln", "misconfig"}
	if len(got) != len(want) {
		t.Fatalf("expected %d scanners, got %d: %v", len(want), len(got), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("at index %d: expected %q, got %q", i, v, got[i])
		}
	}
}

// TestNormalizeScannersDefaultsToAll verifies the default scanner set.
func TestNormalizeScannersDefaultsToAll(t *testing.T) {
	got := NormalizeScanners(nil)
	if len(got) != 4 {
		t.Fatalf("expected 4 default scanners, got %d", len(got))
	}
}
