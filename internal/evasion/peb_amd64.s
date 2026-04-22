// Plan 9 assembly stubs for AMD64 Windows.
// getPEBAddress: reads gs:[0x60] to get the Process Environment Block pointer.
// doSyscall: performs a direct SYSCALL with a dynamic syscall service number (SSN).
//
// Windows x64 syscall calling convention:
//   arg1 → R10 (not RCX — SYSCALL clobbers RCX, so Windows uses R10 for arg1)
//   arg2 → RDX
//   arg3 → R8
//   arg4 → R9
//   arg5 → [RSP+0x28]  ← must be on the stack, kernel reads from here
//   arg6 → [RSP+0x30]  ← must be on the stack, kernel reads from here
//   Shadow space [RSP+0x00..0x1F] is reserved per Windows ABI
//
// Frame size is $64 (16-byte aligned):
//   [SP+0x00..0x1F] = 32-byte shadow space (Windows ABI requirement)
//   [SP+0x20..0x27] = padding / alignment
//   [SP+0x28..0x2F] = arg5 spill slot ← NtProtectVirtualMemory oldProtect ptr
//   [SP+0x30..0x37] = arg6 spill slot
//   [SP+0x38..0x3F] = padding to reach 64 bytes

#include "textflag.h"

// func getPEBAddress() uintptr
TEXT ·getPEBAddress(SB),NOSPLIT,$0-8
    MOVQ 0x60(GS), AX   // GS:[0x60] = PEB* on Windows AMD64
    MOVQ AX, ret+0(FP)
    RET

// func doSyscall(ssn, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr)
//
// FP layout (Go calling convention, all uintptr = 8 bytes):
//   ssn   +0(FP)
//   nargs +8(FP)   (ignored — we always spill a5/a6 unconditionally)
//   a1   +16(FP)
//   a2   +24(FP)
//   a3   +32(FP)
//   a4   +40(FP)
//   a5   +48(FP)
//   a6   +56(FP)
//   r1   +64(FP)
//   r2   +72(FP)
//   err  +80(FP)
TEXT ·doSyscall(SB),NOSPLIT,$64-88
    // Load syscall number into EAX
    MOVQ ssn+0(FP),  AX

    // Load register arguments (Windows kernel syscall ABI)
    MOVQ a1+16(FP),  R10    // arg1 → R10 (SYSCALL clobbers RCX, kernel reads R10 as arg1)
    MOVQ a2+24(FP),  DX     // arg2 → RDX
    MOVQ a3+32(FP),  R8     // arg3 → R8
    MOVQ a4+40(FP),  R9     // arg4 → R9

    // Spill arg5 and arg6 onto the stack — Windows kernel reads them from [rsp+0x28] and [rsp+0x30]
    // SP here points to the bottom of our $64 local frame, so these offsets are in-bounds.
    MOVQ a5+48(FP),  R11
    MOVQ a6+56(FP),  R12
    MOVQ R11, 0x28(SP)      // arg5 → [RSP+0x28]
    MOVQ R12, 0x30(SP)      // arg6 → [RSP+0x30]

    SYSCALL

    // Return NTSTATUS in r1; r2 and err are always zero (errors encoded in NTSTATUS)
    MOVQ AX, r1+64(FP)
    XORQ AX, AX
    MOVQ AX, r2+72(FP)
    MOVQ AX, err+80(FP)
    RET
