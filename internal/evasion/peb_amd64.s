// Plan 9 assembly stubs for AMD64 Windows.
// getPEBAddress: reads gs:[0x60] to get the Process Environment Block pointer.
// doSyscall: performs a direct SYSCALL with a dynamic syscall service number (SSN).

#include "textflag.h"

// func getPEBAddress() uintptr
TEXT ·getPEBAddress(SB),NOSPLIT,$0-8
    MOVQ 0x60(GS), AX   // GS:[0x60] = PEB* on Windows AMD64
    MOVQ AX, ret+0(FP)
    RET

// func doSyscall(ssn, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr)
// Frame size: 8 args * 8 + 3 returns * 8 = 88 bytes
TEXT ·doSyscall(SB),NOSPLIT,$0-88
    MOVQ ssn+0(FP),  AX     // syscall number → EAX
    MOVQ a1+16(FP),  R10    // arg1 → R10 (Windows x64 calling convention)
    MOVQ a2+24(FP),  DX     // arg2 → RDX
    MOVQ a3+32(FP),  R8     // arg3 → R8
    MOVQ a4+40(FP),  R9     // arg4 → R9
    // a5 and a6 must be on stack for Windows ABI (shadow space already provided by Go)
    MOVQ a5+48(FP),  R11
    MOVQ a6+56(FP),  R12
    SYSCALL
    MOVQ AX, r1+64(FP)      // return value
    XORQ AX, AX
    MOVQ AX, r2+72(FP)
    MOVQ AX, err+80(FP)
    RET
