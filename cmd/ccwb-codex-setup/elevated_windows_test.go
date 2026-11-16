package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPowerShellCommandEnvironment(t *testing.T) {
	for _, name := range []string{"PSModulePath", "psmodulepath", "PSMODULEPATH"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "inherited modules")
			t.Setenv("CCWB_POWERSHELL_TEST", "preserved")

			cmd := powershellCommand("exit 0")

			preserved := false
			for _, entry := range cmd.Environ() {
				key, value, _ := strings.Cut(entry, "=")
				if strings.EqualFold(key, "PSModulePath") {
					t.Error("Windows PowerShell inherited PSModulePath")
				}

				if key == "CCWB_POWERSHELL_TEST" && value == "preserved" {
					preserved = true
				}
			}

			if !preserved {
				t.Error("unrelated environment variable was not preserved")
			}

			if os.Getenv(name) != "inherited modules" {
				t.Error("the parent process environment was changed")
			}
		})
	}
}

func TestReadACLIgnoresInheritedModulePath(t *testing.T) {
	// Without the default module paths, Windows PowerShell cannot load Get-Acl.
	t.Setenv("PSModulePath", t.TempDir())
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.toml")
	writeTestFile(t, path, []byte("settings\n"))

	for _, target := range []string{dir, path} {
		if _, err := readACL(target); err != nil {
			t.Errorf("readACL(%q): %v", target, err)
		}
	}
}

func TestInstallRequirements(t *testing.T) {
	requireElevatedWindows(t)
	t.Setenv("ProgramData", t.TempDir())

	setup := setupFixture(t)
	if code, installErr := installRequirements(setup); code != 0 || installErr != nil {
		t.Fatalf("initial install returned %d: %v", code, installErr)
	}

	path, err := requirementsPath()
	if err != nil {
		t.Fatal(err)
	}

	original := readTestFile(t, path)
	if !bytes.Equal(original, setup.Requirements()) {
		t.Fatalf("requirements = %q, want %q", original, setup.Requirements())
	}

	assertRequirementsLocked(t, filepath.Dir(path))

	setup.Codex.ReasoningEffort = "low"
	if code, installErr := installRequirements(setup); code != 0 || installErr != nil {
		t.Fatalf("replacement returned %d: %v", code, installErr)
	}

	if got := readTestFile(t, path); !bytes.Equal(got, setup.Requirements()) {
		t.Errorf("updated requirements = %q, want %q", got, setup.Requirements())
	}

	backups, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatal(err)
	}

	if len(backups) != 1 {
		t.Fatalf("backups = %v, want one", backups)
	}

	if got := readTestFile(t, backups[0]); !bytes.Equal(got, original) {
		t.Errorf("backup = %q, want original %q", got, original)
	}

	assertRequirementsLocked(t, filepath.Dir(path))
}

func TestLockRequirementsFolderWithInheritedPermissions(t *testing.T) {
	requireElevatedWindows(t)
	parent := t.TempDir()

	if err := runICACLS(parent, "/grant:r", "*"+systemSID+":(OI)(CI)F", "*"+administratorSID+":(OI)(CI)F", "*"+usersSID+":(OI)(CI)RX"); err != nil {
		t.Fatal(err)
	}

	if err := runICACLS(parent, "/inheritance:r"); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(parent, "Codex")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	acl, err := readACL(dir)
	if err != nil {
		t.Fatal(err)
	}

	if acl.protected || len(acl.rules) == 0 {
		t.Fatalf("expected inherited permissions before locking: %+v", acl)
	}

	for _, rule := range acl.rules {
		if !rule.inherited {
			t.Fatalf("expected only inherited rules before locking: %+v", acl)
		}
	}

	if lockErr := lockRequirementsFolder(dir); lockErr != nil {
		t.Fatal(lockErr)
	}

	acl, err = readACL(dir)
	if err != nil || !acl.directoryLocked() {
		t.Fatalf("folder was not locked: %+v, %v", acl, err)
	}
}

func TestRequirementsRepairsExtraGrant(t *testing.T) {
	requireElevatedWindows(t)
	t.Setenv("ProgramData", t.TempDir())

	path, err := requirementsPath()
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Dir(path)
	if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}

	if grantErr := runICACLS(dir, "/grant", "*S-1-1-0:(OI)(CI)W"); grantErr != nil {
		t.Fatal(grantErr)
	}

	acl, err := readACL(dir)
	if err != nil {
		t.Fatal(err)
	}

	if acl.directoryLocked() {
		t.Fatal("folder with an extra Everyone grant was reported as locked")
	}

	if code, installErr := installRequirements(setupFixture(t)); code != 0 || installErr != nil {
		t.Fatalf("repair returned %d: %v", code, installErr)
	}

	assertRequirementsLocked(t, dir)
}

func TestRequirementsRejectsJunctions(t *testing.T) {
	for _, linked := range []string{"OpenAI", "Codex"} {
		t.Run(linked, func(t *testing.T) {
			programData, target := t.TempDir(), t.TempDir()
			t.Setenv("ProgramData", programData)

			link := filepath.Join(programData, "OpenAI")
			if linked == "Codex" {
				if err := os.Mkdir(link, 0o700); err != nil {
					t.Fatal(err)
				}

				link = filepath.Join(link, "Codex")
			}

			createJunction(t, link, target)

			code, err := installRequirements(setupFixture(t))
			if code != exitPermissions || err == nil || !strings.Contains(err.Error(), "link or junction") {
				t.Fatalf("installRequirements = %d, %v; want %d and a junction error", code, err, exitPermissions)
			}

			entries, err := os.ReadDir(target)
			if err != nil {
				t.Fatal(err)
			}

			if len(entries) != 0 {
				t.Errorf("wrote through the junction: %v", entries)
			}
		})
	}
}

func TestHoldFoldersBlocksRename(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "Codex")

	held, err := holdFolders(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(dir, filepath.Join(parent, "moved")); err == nil {
		releaseFolders(held)
		t.Fatal("renamed a held folder")
	}

	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600); err != nil {
		t.Errorf("could not create a file in a held folder: %v", err)
	}

	releaseFolders(held)

	if err := os.Rename(dir, filepath.Join(parent, "moved")); err != nil {
		t.Errorf("released folder could not be renamed: %v", err)
	}
}

func TestWindowsDirectory(t *testing.T) {
	dir, err := windowsDirectory()
	if err != nil {
		t.Fatal(err)
	}

	if want := os.Getenv("SystemRoot"); !strings.EqualFold(dir, want) {
		t.Errorf("windowsDirectory = %q, want %q", dir, want)
	}
}

func TestCreateAdminOnlyDir(t *testing.T) {
	requireElevatedWindows(t)

	parent := t.TempDir()

	// The parent grants Users full control to subfolders, as CREATOR OWNER
	// does for the signed-in user in the Windows Temp folder.
	if err := runICACLS(parent, "/grant", "*"+usersSID+":(OI)(CI)F"); err != nil {
		t.Fatal(err)
	}

	first, err := createAdminOnlyDir(parent, "ccwb-awscli-")
	if err != nil {
		t.Fatal(err)
	}

	second, err := createAdminOnlyDir(parent, "ccwb-awscli-")
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{first, second} {
		if !strings.HasPrefix(filepath.Base(dir), "ccwb-awscli-") || filepath.Dir(dir) != parent {
			t.Errorf("unexpected download folder %q", dir)
		}

		acl, err := readACL(dir)
		if err != nil || !acl.adminOnly() {
			t.Fatalf("download folder not admin-only: %+v, %v", acl, err)
		}
	}

	if first == second {
		t.Errorf("both download folders are %q", first)
	}
}

func TestCheckAdminOnlyRejectsInheritedFolder(t *testing.T) {
	requireElevatedWindows(t)

	if err := checkAdminOnly(t.TempDir()); err == nil {
		t.Error("accepted a download folder with inherited permissions")
	}
}

func TestRequirementsPathRejectsInvalidBase(t *testing.T) {
	for _, base := range []string{"", "relative"} {
		t.Run(base, func(t *testing.T) {
			t.Setenv("ProgramData", base)

			if _, err := requirementsPath(); err == nil {
				t.Fatal("accepted a missing or relative ProgramData path")
			}
		})
	}
}

func TestElevatedRejectsInvalidInput(t *testing.T) {
	for _, args := range [][]string{nil, {"-elevated"}, {"-elevated", "unknown"}, {"-elevated", "requirements", "extra"}} {
		if code := runElevated(args, readFixture(t, "config.json")); code != exitElevatedConfig {
			t.Errorf("runElevated(%v) = %d, want %d", args, code, exitElevatedConfig)
		}
	}

	for _, cfg := range [][]byte{nil, readFixture(t, "invalid-config.json")} {
		if code := runElevated([]string{"-elevated", "requirements"}, cfg); code != exitElevatedConfig {
			t.Errorf("invalid config returned %d, want %d", code, exitElevatedConfig)
		}
	}
}

func TestRequirementsBackupDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml.bak-existing")
	original := []byte("the existing backup\n")
	writeTestFile(t, path, original)

	if err := backupRequirements(path, []byte("new backup\n")); err == nil {
		t.Fatal("overwrote an existing backup")
	}

	if got := readTestFile(t, path); !bytes.Equal(got, original) {
		t.Errorf("backup changed: %q", got)
	}
}

func TestRequirementsWriteCleansUpFailedRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.toml")

	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := writeRequirements(path, []byte("new settings\n")); err == nil {
		t.Fatal("replaced a directory with a settings file")
	}

	leftovers, err := filepath.Glob(filepath.Join(dir, ".ccwb-requirements-*"))
	if err != nil {
		t.Fatal(err)
	}

	if len(leftovers) != 0 {
		t.Errorf("temporary files remain after failure: %v", leftovers)
	}
}

func createJunction(t *testing.T, link, target string) {
	t.Helper()

	if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, output)
	}

	// Remove the junction itself before t.TempDir cleans up its target.
	t.Cleanup(func() { _ = os.Remove(link) })
}

func requireElevatedWindows(t *testing.T) {
	t.Helper()

	groups, err := exec.Command("whoami", "/groups").Output()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(groups), "S-1-16-12288") {
		if os.Getenv("CCWB_REQUIRE_ELEVATED_TESTS") == "1" {
			t.Fatal("Windows CI must run the requirements permissions tests in an elevated process")
		}

		t.Skip("the requirements permissions test needs an elevated Windows process")
	}
}

func assertRequirementsLocked(t *testing.T, dir string) {
	t.Helper()

	acl, err := readACL(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !acl.directoryLocked() {
		t.Fatalf("unexpected folder permissions: %+v", acl)
	}

	acl, err = readACL(filepath.Join(dir, "requirements.toml"))
	if err != nil {
		t.Fatal(err)
	}

	if !acl.fileLocked() {
		t.Fatalf("unexpected file permissions: %+v", acl)
	}
}
