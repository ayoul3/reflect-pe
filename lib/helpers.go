package lib

import (
	. "unsafe"
)

// safely duplicate a pointer before converting it to uintptr to keep GC from cleaning it
func ptrValue(ptr Pointer) uintptr {
	return uintptr(Pointer(ptr))
}

func uint16Val(ptr Pointer, offset uint) uint16 {
	return *(*uint16)(Pointer(ptrValue(ptr) + uintptr(offset)))
}
func uint32Val(ptr Pointer, offset uint) uint32 {
	return *(*uint32)(Pointer(ptrValue(ptr) + uintptr(offset)))
}

func ptrOffset(ptr Pointer, offset uintptr) Pointer {
	return Pointer(ptrValue(ptr) + offset)
}

func addrOffset(addr uintptr, offset uintptr) Pointer {
	return Pointer(addr + offset)
}

func isMSBSet(num uint) bool {
	uintSize := 32 << (^uint(0) >> 32 & 1)
	return num>>(uintSize-1) == 1
}
