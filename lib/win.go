package lib

import (
	"syscall"
	"unicode/utf16"
	. "unsafe"
)

type WinAPI interface {
	Memcopy(src, dst, size uintptr)
	VirtualAlloc(size uint) (Pointer, error)
	CstrVal(ptr Pointer) (out []byte)
	UstrVal(ptr Pointer) []rune
	LoadLibrary(ptrName string) (Pointer, error)
	GetProcAddress(libraryAddress, ptrName Pointer) (uintptr, error)
	Incr64(src Pointer, val uint64)
	Incr32(src Pointer, val uint32)
	Incr16(src Pointer, val uint16)
	NtFlushInstructionCache(ptr, size uintptr) error
	CreateThread(ptr Pointer) (uintptr, error)
	WaitForSingleObject(handle uintptr) error
	CloseHandle(handle uintptr)
	VirtualProtect(ptr uintptr, size uintptr, exec, write bool) error
	ResumeThread(addr uintptr) error
	ReadBytes(ptr Pointer, size uint) (out []byte)
	UpdateExecMemory(funcAddr uintptr, sc []byte) (err error)
}

type Win struct {
}

func (w *Win) VirtualAlloc(size uint) (Pointer, error) {
	ret, _, err := virtualAlloc.Call(
		uintptr(0),
		uintptr(size),
		uintptr(0x00001000|0x00002000), // MEM_COMMIT | MEM_RESERVE
		uintptr(0x04))                  // PAGE_READWRITE

	if err != syscall.Errno(0) {
		return nil, err
	}
	return Pointer(ret), nil
}

func (w *Win) Memcopy(src, dst, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		*(*uint8)(Pointer(dst + i)) = *(*uint8)(Pointer(src + i))
	}
}

func (w *Win) Incr64(src Pointer, val uint64) {
	*(*uint64)(src) += val
}
func (w *Win) Incr32(src Pointer, val uint32) {
	*(*uint32)(src) += val
}
func (w *Win) Incr16(src Pointer, val uint16) {
	*(*uint16)(src) += val
}

func (w *Win) CstrVal(ptr Pointer) (out []byte) {
	var byteVal byte
	out = make([]byte, 0)
	for i := 0; ; i++ {
		byteVal = *(*byte)(Pointer(ptr))
		if byteVal == 0x00 {
			break
		}
		out = append(out, byteVal)
		ptr = ptrOffset(ptr, 1)
	}
	return out
}

func (w *Win) UstrVal(ptr Pointer) []rune {
	var byteVal uint16
	out := make([]uint16, 0)
	for i := 0; ; i++ {
		byteVal = *(*uint16)(Pointer(ptr))
		if byteVal == 0x0000 {
			break
		}
		out = append(out, byteVal)
		ptr = ptrOffset(ptr, 2)
	}
	return utf16.Decode(out)
}

func (w *Win) ReadBytes(ptr Pointer, size uint) (out []byte) {
	var byteVal byte
	out = make([]byte, 0)
	for i := uint(0); i < size; i++ {
		byteVal = *(*byte)(Pointer(ptr))
		out = append(out, byteVal)
		ptr = ptrOffset(ptr, 1)
	}
	return out
}

func (w *Win) LoadLibrary(name string) (Pointer, error) {
	ret, err := syscall.LoadDLL(name)

	return Pointer(ret.Handle), err
}

func (w *Win) GetProcAddress(libraryAddress, ptrName Pointer) (uintptr, error) {
	ret, _, err := getProcAddress.Call(
		ptrValue(libraryAddress),
		ptrValue(ptrName))

	if err != syscall.Errno(0) {
		return 0, err
	}
	return ret, nil
}

func (w *Win) NtFlushInstructionCache(ptr, size uintptr) error {
	_, _, err := ntFlushInstructionCache.Call(
		uintptr(0),
		ptr,
		size)

	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

func (w *Win) CreateThread(ptr Pointer) (uintptr, error) {
	ret, _, err := createThread.Call(
		uintptr(0),
		uintptr(0),
		ptrValue(ptr),
		uintptr(0),
		uintptr(0x00000004),
		uintptr(0))
	if err != syscall.Errno(0) {
		return 0, err
	}
	return ret, nil
}
func (w *Win) ResumeThread(addr uintptr) error {
	_, _, err := resumeThread.Call(addr)
	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

func (w *Win) WaitForSingleObject(handle uintptr) error {
	_, _, err := waitForSingleObject.Call(
		handle,
		syscall.INFINITE)
	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

func (w *Win) UpdateExecMemory(funcAddr uintptr, sc []byte) (err error) {

	if err = w.VirtualProtect(funcAddr, uintptr(len(sc)), false, true); err != nil {
		return err
	}

	w.Memcopy(uintptr(Pointer(&sc[0])), funcAddr, uintptr(len(sc)))

	if err = w.VirtualProtect(funcAddr, uintptr(len(sc)), true, false); err != nil {
		return err
	}

	return nil
}
func (w *Win) VirtualProtect(ptr uintptr, size uintptr, exec, write bool) error {
	var empty uint32
	flag := 0x02
	if exec {
		flag = 0x20
	}
	if write {
		flag = 0x04
	}
	_, _, err := virtualProtect.Call(
		ptr,
		size,
		uintptr(flag),
		ptrValue(Pointer(&empty)))
	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

func (w *Win) CloseHandle(handle uintptr) {
	syscall.CloseHandle(syscall.Handle(handle))
}

type ImageImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type DebugDirectory struct {
	Characteristics  uint32
	TimeDateStamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             uint32
	SizeOfData       uint32
	AddressOfRawData uint32
	PointerToRawData uint32
}

type ImageExportDescriptor struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfName         uint32
	AddressOfNameOrdinals uint32
}

const IMAGE_REL_BASED_HIGH = 0x1
const IMAGE_REL_BASED_LOW = 0x2
const IMAGE_REL_BASED_HIGHLOW = 0x3
const IMAGE_REL_BASED_DIR64 = 0xa

type ImageBaseRelocation struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

type ImageReloc struct {
	OffsetType uint16
}

func (c *ImageReloc) GetOffset() uint16 {
	return c.OffsetType & 0x0fff
}

func (c *ImageReloc) GetType() uint16 {
	return (c.OffsetType & 0xf000) >> 12
}

type OriginalImageThunkData struct {
	Ordinal uint
}
type ImageThunkData struct {
	AddressOfData uintptr
}
type ImageImportByName struct {
	Hint uint16
	Name byte
}

var (
	kernel32                = syscall.MustLoadDLL("kernel32.dll")
	ntdll                   = syscall.MustLoadDLL("ntdll.dll")
	virtualAlloc            = kernel32.MustFindProc("VirtualAlloc")
	virtualProtect          = kernel32.MustFindProc("VirtualProtect")
	getProcAddress          = kernel32.MustFindProc("GetProcAddress")
	createThread            = kernel32.MustFindProc("CreateThread")
	resumeThread            = kernel32.MustFindProc("ResumeThread")
	waitForSingleObject     = kernel32.MustFindProc("WaitForSingleObject")
	ntFlushInstructionCache = ntdll.MustFindProc("NtFlushInstructionCache")
)
