//go:build windows

package evasion

// getPEBAddress is implemented in peb_amd64.s — reads gs:[0x60] to get the PEB pointer.
func getPEBAddress() uintptr

// doSyscall executes a raw SYSCALL with the given syscall service number (SSN).
// Implemented in peb_amd64.s — bypasses user-mode hooks in ntdll.dll entirely.
// Arguments: ssn=syscall number, nargs=number of args, a1-a6=arguments.
// Returns: r1=status, r2=unused, err=0 (errors reflected in r1 NTSTATUS).
func doSyscall(ssn, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr)
