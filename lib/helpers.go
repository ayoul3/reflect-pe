package lib

import (
	"math/rand"
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

func randInt(min, max int) int {
	return rand.Intn(max-min) + min
}

func reverse(s string) string {
	rns := []rune(s)
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		rns[i], rns[j] = rns[j], rns[i]
	}

	return string(rns)
}

func intToByteArray(num uintptr) []byte {
	size := int(Sizeof(num))
	arr := make([]byte, size)
	for i := 0; i < size; i++ {
		byt := *(*uint8)(Pointer(uintptr(Pointer(&num)) + uintptr(i)))
		arr[i] = byt
	}
	return arr
}
