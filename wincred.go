package wincred

import (
	"syscall"
	"unsafe"
	"C"
	"encoding/binary"
	"reflect"
	"time"
	"unicode/utf16"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCredRead   = modadvapi32.NewProc("CredReadW")
	procCredWrite  = modadvapi32.NewProc("CredWriteW")
	procCredDelete = modadvapi32.NewProc("CredDeleteW")
	procCredFree   = modadvapi32.NewProc("CredFree")
)

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
type nativeCREDENTIAL struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     uintptr
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374790(v=vs.85).aspx
type nativeCREDENTIAL_ATTRIBUTE struct {
	Keyword   *uint16
	Flags     uint32
	ValueSize uint32
	Value     uintptr
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
type nativeCRED_TYPE uint32

const (
	naCRED_TYPE_GENERIC                 nativeCRED_TYPE = 0x1
	naCRED_TYPE_DOMAIN_PASSWORD         nativeCRED_TYPE = 0x2
	naCRED_TYPE_DOMAIN_CERTIFICATE      nativeCRED_TYPE = 0x3
	naCRED_TYPE_DOMAIN_VISIBLE_PASSWORD nativeCRED_TYPE = 0x4
	naCRED_TYPE_GENERIC_CERTIFICATE     nativeCRED_TYPE = 0x5
	naCRED_TYPE_DOMAIN_EXTENDED         nativeCRED_TYPE = 0x6
)

// Create a Go string using a pointer to a zero-terminated UTF 16 encoded string.
// See github.com/AllenDang/w32
func utf16PtrToString(wstr *uint16) string {
	if wstr != nil {
		buf := make([]uint16, 0, 256)
		for ptr := uintptr(unsafe.Pointer(wstr)); ; ptr += 2 {
			rune := *(*uint16)(unsafe.Pointer(ptr))
			if rune == 0 {
				return string(utf16.Decode(buf))
			}
			buf = append(buf, rune)
		}
	}

	return ""
}

// Create a byte array from a given UTF 16 char array
func utf16ToByte(wstr []uint16) (result []byte) {
	result = make([]byte, len(wstr)*2)
	for i, _ := range wstr {
		binary.LittleEndian.PutUint16(result[(i*2):(i*2)+2], wstr[i])
	}
	return
}

// Convert the given CREDENTIAL struct to a more usable structure
func nativeToCredential(cred *nativeCREDENTIAL) (result *Credential) {
	result = new(Credential)
	result.Comment = utf16PtrToString(cred.Comment)
	result.TargetName = utf16PtrToString(cred.TargetName)
	result.TargetAlias = utf16PtrToString(cred.TargetAlias)
	result.UserName = utf16PtrToString(cred.UserName)
	result.LastWritten = time.Unix(0, cred.LastWritten.Nanoseconds())
	result.Persist = CredentialPersistence(cred.Persist)
	result.CredentialBlob = C.GoBytes(unsafe.Pointer(cred.CredentialBlob), C.int(cred.CredentialBlobSize))
	result.Attributes = make([]CredentialAttribute, cred.AttributeCount)
	attrSliceHeader := reflect.SliceHeader{
		Data: cred.Attributes,
		Len:  int(cred.AttributeCount),
		Cap:  int(cred.AttributeCount),
	}
	attrSlice := *(*[]nativeCREDENTIAL_ATTRIBUTE)(unsafe.Pointer(&attrSliceHeader))
	for i, attr := range attrSlice {
		resultAttr := &result.Attributes[i]
		resultAttr.Keyword = utf16PtrToString(attr.Keyword)
		resultAttr.Value = C.GoBytes(unsafe.Pointer(attr.Value), C.int(attr.ValueSize))
	}

	return result
}

// Convert the given Credential object back to a CREDENTIAL struct, which can be used for calling the
// Windows APIs
func nativeFromCredential(cred *Credential) (result *nativeCREDENTIAL) {
	result = new(nativeCREDENTIAL)
	result.Flags = 0
	result.Type = 0
	result.TargetName, _ = syscall.UTF16PtrFromString(cred.TargetName)
	result.Comment, _ = syscall.UTF16PtrFromString(cred.Comment)
	result.LastWritten = syscall.NsecToFiletime(cred.LastWritten.UnixNano())
	result.CredentialBlobSize = uint32(len(cred.CredentialBlob))
	if len(cred.CredentialBlob) > 0 {
		result.CredentialBlob = uintptr(unsafe.Pointer(&cred.CredentialBlob[0]))
	} else {
		result.CredentialBlob = 0
	}
	result.Persist = uint32(cred.Persist)
	result.AttributeCount = uint32(len(cred.Attributes))
	attributes := make([]nativeCREDENTIAL_ATTRIBUTE, len(cred.Attributes))
	if len(attributes) > 0 {
		result.Attributes = uintptr(unsafe.Pointer(&attributes[0]))
	} else {
		result.Attributes = 0
	}
	for i, _ := range cred.Attributes {
		inAttr := &cred.Attributes[i]
		outAttr := &attributes[i]
		outAttr.Keyword, _ = syscall.UTF16PtrFromString(inAttr.Keyword)
		outAttr.Flags = 0
		outAttr.ValueSize = uint32(len(inAttr.Value))
		if len(inAttr.Value) > 0 {
			outAttr.Value = uintptr(unsafe.Pointer(&inAttr.Value[0]))
		} else {
			outAttr.Value = 0
		}
	}
	result.TargetAlias, _ = syscall.UTF16PtrFromString(cred.TargetAlias)
	result.UserName, _ = syscall.UTF16PtrFromString(cred.UserName)

	return
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374804(v=vs.85).aspx
func nativeCredRead(targetName string, typ nativeCRED_TYPE) (*Credential, error) {
	var pcred uintptr
	targetNamePtr, _ := syscall.UTF16PtrFromString(targetName)
	ret, _, err := procCredRead.Call(
		uintptr(unsafe.Pointer(targetNamePtr)),
		uintptr(typ),
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	if ret == 0 {
		return nil, err
	}
	defer procCredFree.Call(pcred)

	return nativeToCredential((*nativeCREDENTIAL)(unsafe.Pointer(pcred))), nil
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa375187(v=vs.85).aspx
func nativeCredWrite(cred *Credential, typ nativeCRED_TYPE) error {
	ncred := nativeFromCredential(cred)
	ncred.Type = uint32(typ)
	ret, _, err := procCredWrite.Call(
		uintptr(unsafe.Pointer(ncred)),
		0,
	)
	if ret == 0 {
		return err
	}

	return nil
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa374787(v=vs.85).aspx
func nativeCredDelete(cred *Credential, typ nativeCRED_TYPE) error {
	targetNamePtr, _ := syscall.UTF16PtrFromString(cred.TargetName)
	ret, _, err := procCredDelete.Call(
		uintptr(unsafe.Pointer(targetNamePtr)),
		uintptr(typ),
		0,
	)
	if ret == 0 {
		return err
	}

	return nil
}

// Get the generic credential with the given name from Windows credential manager
func GetGenericCredential(targetName string) (*GenericCredential, error) {
	cred, err := nativeCredRead(targetName, naCRED_TYPE_GENERIC)
	if cred != nil {
		return &GenericCredential{*cred}, err
	}
	return nil, err
}

// Create a new generic credential with the given name
func NewGenericCredential(targetName string) (result *GenericCredential) {
	result = new(GenericCredential)
	result.TargetName = targetName
	result.Persist = PersistLocalMachine
	return
}

// Persist the credential to Windows credential manager
func (t *GenericCredential) Write() (err error) {
	err = nativeCredWrite(&t.Credential, naCRED_TYPE_GENERIC)
	return
}

// Delete the credential from Windows credential manager
func (t *GenericCredential) Delete() (err error) {
	err = nativeCredDelete(&t.Credential, naCRED_TYPE_GENERIC)
	return
}

// Get the domain password credential with the given target host name
func GetDomainPassword(targetName string) (*DomainPassword, error) {
	cred, err := nativeCredRead(targetName, naCRED_TYPE_DOMAIN_PASSWORD)
	if cred != nil {
		return &DomainPassword{*cred}, err
	}
	return nil, err
}

// Create a new domain password credential used for login to the given target host name
func NewDomainPassword(targetName string) (result *DomainPassword) {
	result = new(DomainPassword)
	result.TargetName = targetName
	result.Persist = PersistLocalMachine
	return
}

// Persist the domain password credential to Windows credential manager
func (t *DomainPassword) Write() (err error) {
	err = nativeCredWrite(&t.Credential, naCRED_TYPE_DOMAIN_PASSWORD)
	return
}

// Delete the domain password credential from Windows credential manager
func (t *DomainPassword) Delete() (err error) {
	err = nativeCredDelete(&t.Credential, naCRED_TYPE_DOMAIN_PASSWORD)
	return
}

// Set the CredentialBlob field of a domain password credential
// using an UTF16 encoded password string
func (t *DomainPassword) SetPassword(pw string) {
	t.CredentialBlob = utf16ToByte(syscall.StringToUTF16(pw))
}
