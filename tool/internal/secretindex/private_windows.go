package secretindex

import (
	"errors"
	"golang.org/x/sys/windows"
	"io/fs"
	"os"
	"unsafe"
)

// Windows privacy follows the caller's directory ACL; Unix permission bits are
// not an ACL representation. The key and database still require regular files.
func privatePermissions(fs.FileMode) bool { return true }
func singleLink(fs.FileInfo) bool         { return true }

// Only a directory created by this invocation receives a protected DACL.
// Existing directories are validated, never silently chmodded/re-ACL'd.
func secureNewDirectory(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func checkPlatformPrivacy(path string, info fs.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil {
		return errors.New("index requires a private Windows DACL")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, n, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("index cannot validate this Windows ACL entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		trusted := sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 && sid.IsWellKnown(windows.WinCreatorOwnerSid) {
			trusted = true
		}
		if !trusted {
			return errors.New("index Windows ACL grants access beyond the current user, SYSTEM, or Administrators")
		}
	}
	if !info.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		var stat windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &stat); err != nil {
			return err
		}
		if stat.NumberOfLinks != 1 {
			return errors.New("index requires a single-link file")
		}
	}
	return nil
}
