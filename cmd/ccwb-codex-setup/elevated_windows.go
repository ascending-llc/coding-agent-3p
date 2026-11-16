package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ascending-llc/claude-3p-config/policy"
)

type heldFolder struct {
	path   string
	handle syscall.Handle
}

const (
	awsCLIInstallerURL    = "https://awscli.amazonaws.com/AWSCLIV2.msi"
	awsCLIDownloadTimeout = 5 * time.Minute
	msiRestartRequired    = 3010

	// fileListDirectory makes a held folder handle count for sharing checks;
	// a handle with only fileReadAttributes would not block a rename.
	fileListDirectory  = 0x1
	fileReadAttributes = 0x80

	// windowsDirectoryBytes holds a MAX_PATH UTF-16 registry value.
	windowsDirectoryBytes uint32 = 2 * syscall.MAX_PATH

	// adminOnlySDDL is owned by Administrators and grants full control only to
	// SYSTEM and Administrators, without inheriting from the parent folder.
	adminOnlySDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	sddlRevision1 = 1

	// downloadDirAttempts bounds retries when a random name is already taken.
	downloadDirAttempts = 10
)

var procConvertSDDL = syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")

func runElevated(args []string, cfg []byte) int {
	if len(args) != 2 || args[0] != "-elevated" {
		return exitElevatedConfig
	}

	steps, err := parseInstallSteps(args[1])
	if err != nil {
		return exitElevatedConfig
	}

	s, err := policy.ParseCodexSetup(bytes.NewReader(cfg))
	if err != nil {
		return exitElevatedConfig
	}

	code := 0
	if steps.awsCLI {
		code = installAWSCLI()
	}

	if steps.requirements {
		fileCode, fileErr := installRequirements(s)
		if fileErr != nil {
			_, _ = fmt.Fprintln(os.Stderr, fileErr)
		}

		if code == 0 {
			code = fileCode
		}
	}

	return code
}

func requirementsPath() (string, error) {
	base := os.Getenv("ProgramData")
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("ProgramData must be an absolute path")
	}

	return filepath.Join(base, "OpenAI", "Codex", "requirements.toml"), nil
}

func powershellCommand(script string) *exec.Cmd {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)

	// PowerShell 7 can pass its module paths through Go to Windows PowerShell
	// 5.1, whose built-in cmdlets then fail to load. Let it rebuild its defaults.
	cmd.Env = make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(name, "PSModulePath") {
			cmd.Env = append(cmd.Env, entry)
		}
	}

	return cmd
}

func readACL(path string) (pathACL, error) {
	script := `$ErrorActionPreference = 'Stop'; $acl = Get-Acl -LiteralPath ` + powershellQuote(path) + `;
'owner=' + $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
'protected=' + $acl.AreAccessRulesProtected;
foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
  'rule={0} {1} {2} inh={3} inherited={4}' -f $r.IdentityReference.Value, $r.AccessControlType, [int]$r.FileSystemRights, $r.InheritanceFlags, $r.IsInherited
}`

	cmd := powershellCommand(script)

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		return pathACL{}, fmt.Errorf("reading permissions for %s: %s: %s", path, err.Error(), strings.TrimSpace(stderr.String()))
	}

	acl, err := parseACL(output)
	if err != nil {
		return pathACL{}, fmt.Errorf("parsing permissions for %s: %s: %s", path, err.Error(), strings.TrimSpace(string(output)))
	}

	return acl, nil
}

func installAWSCLI() int {
	dir, err := awsCLIDownloadDir()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)

		return exitDownload
	}

	defer func() { _ = os.RemoveAll(dir) }()

	msi := filepath.Join(dir, "AWSCLIV2.msi")
	if downloadErr := downloadAWSCLI(msi); downloadErr != nil {
		return exitDownload
	}

	script := `$ErrorActionPreference = 'Stop'; $s = Get-AuthenticodeSignature -LiteralPath ` + powershellQuote(msi) + `;
$s.Status;
if ($null -ne $s.SignerCertificate) { $s.SignerCertificate.SubjectName.Format($true) }`

	output, err := powershellCommand(script).Output()
	if err != nil || !validAWSSignature(output) {
		return exitSignature
	}

	err = exec.Command("msiexec.exe", "/i", msi, "/qn", "/norestart", "/l*v", filepath.Join(dir, "awscli-install.log")).Run()
	if err == nil {
		return 0
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == msiRestartRequired {
		return 0
	}

	return exitInstall
}

// awsCLIDownloadDir creates an empty folder that only SYSTEM and Administrators
// can change. With same-account UAC this process shares the user's TEMP, where
// an unelevated process could replace the MSI after its signature check.
func awsCLIDownloadDir() (string, error) {
	windows, err := windowsDirectory()
	if err != nil {
		return "", err
	}

	return createAdminOnlyDir(filepath.Join(windows, "Temp"), "ccwb-awscli-")
}

// createAdminOnlyDir creates a new folder with a random name under parent that
// is locked from the moment it exists. A folder created with the parent's
// inherited permissions and locked afterwards can be opened in between: in
// the Windows Temp folder, CREATOR OWNER gives the signed-in user full control
// of a folder an elevated process creates.
func createAdminOnlyDir(parent, prefix string) (string, error) {
	sd, err := adminOnlySecurityDescriptor()
	if err != nil {
		return "", err
	}

	defer func() { _, _ = syscall.LocalFree(syscall.Handle(sd)) }()

	attributes := syscall.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))

	for range downloadDirAttempts {
		suffix := make([]byte, 8)
		if _, err = rand.Read(suffix); err != nil {
			return "", fmt.Errorf("creating the AWS CLI download folder: %s", err.Error())
		}

		dir := filepath.Join(parent, prefix+hex.EncodeToString(suffix))

		path, pathErr := syscall.UTF16PtrFromString(dir)
		if pathErr != nil {
			return "", pathErr
		}

		err = syscall.CreateDirectory(path, &attributes)
		if errors.Is(err, syscall.ERROR_ALREADY_EXISTS) {
			continue
		}

		if err != nil {
			return "", fmt.Errorf("creating the AWS CLI download folder: %s", err.Error())
		}

		if checkErr := checkAdminOnly(dir); checkErr != nil {
			_ = os.RemoveAll(dir)

			return "", checkErr
		}

		return dir, nil
	}

	return "", fmt.Errorf("creating the AWS CLI download folder: %s", err.Error())
}

func adminOnlySecurityDescriptor() (uintptr, error) {
	sddl, err := syscall.UTF16PtrFromString(adminOnlySDDL)
	if err != nil {
		return 0, err
	}

	var sd uintptr

	ok, _, callErr := procConvertSDDL.Call(uintptr(unsafe.Pointer(sddl)), sddlRevision1, uintptr(unsafe.Pointer(&sd)), 0)
	if ok == 0 {
		return 0, fmt.Errorf("building the download folder permissions: %s", callErr.Error())
	}

	return sd, nil
}

// windowsDirectory reads the Windows folder from HKLM, which only
// administrators can change. A user's environment can override %SystemRoot%.
func windowsDirectory() (string, error) {
	subkey, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return "", err
	}

	var key syscall.Handle
	if err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subkey, 0, syscall.KEY_QUERY_VALUE, &key); err != nil {
		return "", fmt.Errorf("finding the Windows folder: %s", err.Error())
	}

	defer func() { _ = syscall.RegCloseKey(key) }()

	name, err := syscall.UTF16PtrFromString("SystemRoot")
	if err != nil {
		return "", err
	}

	var valueType uint32

	size := windowsDirectoryBytes
	buf := make([]byte, size)

	if err = syscall.RegQueryValueEx(key, name, nil, &valueType, &buf[0], &size); err != nil {
		return "", fmt.Errorf("finding the Windows folder: %s", err.Error())
	}

	if valueType != syscall.REG_SZ || size%2 != 0 {
		return "", fmt.Errorf("finding the Windows folder: unexpected registry value")
	}

	value := make([]uint16, size/2)
	for i := range value {
		value[i] = uint16(buf[2*i]) | uint16(buf[2*i+1])<<8
	}

	dir := syscall.UTF16ToString(value)
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("finding the Windows folder: %q is not an absolute path", dir)
	}

	return dir, nil
}

// checkAdminOnly confirms that Windows applied the requested permissions,
// since the MSI's signature check relies on nobody else changing the folder.
func checkAdminOnly(dir string) error {
	acl, err := readACL(dir)
	if err != nil {
		return err
	}

	if !acl.adminOnly() {
		return fmt.Errorf("the download folder permissions do not match the required lock: %+v", acl)
	}

	return nil
}

func downloadAWSCLI(path string) error {
	client := &http.Client{Timeout: awsCLIDownloadTimeout}

	response, err := client.Get(awsCLIInstallerURL)
	if err != nil {
		return err
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading the AWS CLI: HTTP %d", response.StatusCode)
	}

	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	if _, err := io.Copy(file, response.Body); err != nil {
		_ = file.Close()

		return err
	}

	return file.Close()
}

func installRequirements(s policy.CodexSetup) (int, error) {
	path, err := requirementsPath()
	if err != nil {
		return exitPermissions, err
	}

	dir := filepath.Dir(path)

	held, err := holdFolders(filepath.Dir(dir), dir)
	if err != nil {
		return exitPermissions, err
	}

	defer releaseFolders(held)

	if lockErr := lockRequirementsFolder(dir); lockErr != nil {
		return exitPermissions, lockErr
	}

	// The folders can't be renamed while held, but check that neither was
	// turned into a link before the lock took effect.
	for _, folder := range held {
		if checkErr := checkPlainFolder(folder); checkErr != nil {
			return exitPermissions, checkErr
		}
	}

	existing, err := os.ReadFile(filepath.Clean(path))
	if err != nil && !os.IsNotExist(err) {
		return exitWrite, err
	}

	if err == nil {
		backup := path + ".bak-" + time.Now().Format("20060102-150405")
		if backupErr := backupRequirements(backup, existing); backupErr != nil {
			return exitWrite, backupErr
		}
	}

	if writeErr := writeRequirements(path, s.Requirements()); writeErr != nil {
		return exitWrite, writeErr
	}

	// Ownership also grants permission to change the file's ACL. The replacement
	// inherits the locked directory's rules, but must have a trusted owner too.
	if ownerErr := runICACLS(path, "/setowner", "*"+administratorSID); ownerErr != nil {
		return exitPermissions, ownerErr
	}

	acl, err := readACL(path)
	if err != nil {
		return exitPermissions, err
	}

	if !acl.fileLocked() {
		return exitPermissions, fmt.Errorf("the Codex settings file permissions do not match the required lock: %+v", acl)
	}

	return 0, nil
}

// holdFolders creates each folder if it's missing, then keeps it open without
// delete sharing so it can't be renamed or replaced until releaseFolders.
// A user who can create a junction or link at OpenAI or Codex could otherwise
// redirect this elevated write and lock to another folder, so those are refused.
func holdFolders(paths ...string) ([]heldFolder, error) {
	held := make([]heldFolder, 0, len(paths))

	for _, path := range paths {
		if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
			releaseFolders(held)

			return nil, err
		}

		name, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			releaseFolders(held)

			return nil, err
		}

		handle, err := syscall.CreateFile(name, fileListDirectory|fileReadAttributes,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING,
			syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			releaseFolders(held)

			return nil, fmt.Errorf("opening %s: %s", path, err.Error())
		}

		held = append(held, heldFolder{path: path, handle: handle})

		if err := checkPlainFolder(held[len(held)-1]); err != nil {
			releaseFolders(held)

			return nil, err
		}
	}

	return held, nil
}

func checkPlainFolder(folder heldFolder) error {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(folder.handle, &info); err != nil {
		return fmt.Errorf("checking %s: %s", folder.path, err.Error())
	}

	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a link or junction; the Codex settings are not written through it", folder.path)
	}

	if info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s is not a folder", folder.path)
	}

	return nil
}

func releaseFolders(held []heldFolder) {
	for _, folder := range held {
		_ = syscall.CloseHandle(folder.handle)
	}
}

func lockRequirementsFolder(dir string) error {
	if err := runICACLS(dir, "/setowner", "*"+administratorSID); err != nil {
		return err
	}

	// Establish explicit access before removing any existing or inherited
	// grants. Fresh directories may have only inherited permissions.
	if err := runICACLS(dir, "/grant:r", "*"+systemSID+":(OI)(CI)F", "*"+administratorSID+":(OI)(CI)F", "*"+usersSID+":(OI)(CI)RX"); err != nil {
		return err
	}

	if err := removeOtherRules(dir, systemSID, administratorSID, usersSID); err != nil {
		return err
	}

	if err := runICACLS(dir, "/inheritance:r"); err != nil {
		return err
	}

	acl, err := readACL(dir)
	if err != nil {
		return err
	}

	if !acl.directoryLocked() {
		return fmt.Errorf("the Codex folder permissions do not match the required lock: %+v", acl)
	}

	return nil
}

// removeOtherRules removes every explicit rule on dir except allow rules for
// the kept SIDs. /grant:r replaces only each named SID's grants, so this also
// repairs an existing custom ACL. Inherited rules are left to /inheritance:r.
func removeOtherRules(dir string, keep ...string) error {
	acl, err := readACL(dir)
	if err != nil {
		return err
	}

	removed := make(map[string]bool)
	for _, rule := range acl.rules {
		if rule.inherited || (rule.allow && slices.Contains(keep, rule.sid)) {
			continue
		}

		option := "/remove:d"
		if rule.allow {
			option = "/remove:g"
		}

		key := option + rule.sid
		if removed[key] {
			continue
		}

		if err := runICACLS(dir, option, "*"+rule.sid); err != nil {
			return err
		}

		removed[key] = true
	}

	return nil
}

func runICACLS(path string, args ...string) error {
	output, err := exec.Command("icacls", append([]string{path}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %q %v: %s: %s", path, args, err.Error(), strings.TrimSpace(string(output)))
	}

	return nil
}

func backupRequirements(path string, data []byte) error {
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)

		return err
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(path)

		return err
	}

	return nil
}

func writeRequirements(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ccwb-requirements-*")
	if err != nil {
		return err
	}

	defer func() { _ = os.Remove(file.Name()) }()

	if _, err := file.Write(data); err != nil {
		_ = file.Close()

		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	return os.Rename(file.Name(), path)
}
