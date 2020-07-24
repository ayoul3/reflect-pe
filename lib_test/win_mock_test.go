package lib_test

import (
	"errors"
	"unsafe"
	. "unsafe"
)

type MockWin struct {
	ShouldFailLibrary  bool
	ShouldFailFunction bool
}

func (w *MockWin) VirtualAlloc(size uint) (unsafe.Pointer, error) {
	ret := 10000
	return Pointer(&ret), nil
}

func (w *MockWin) Memcopy(src, dst, size uintptr) {

}

func (w *MockWin) Incr64(src Pointer, val uint64) {
	*(*uint64)(src) += val
}
func (w *MockWin) Incr32(src Pointer, val uint32) {
	*(*uint32)(src) += val
}
func (w *MockWin) Incr16(src Pointer, val uint16) {
	*(*uint16)(src) += val
}

func (w *MockWin) CstrVal(ptr Pointer) (out []byte) {
	return []byte("name")
}

func (w *MockWin) UstrVal(ptr Pointer) []rune {
	return []rune("e")
}

func (w *MockWin) ReadBytes(ptr Pointer, size uint) (out []byte) {
	return []byte("er")
}

func (w *MockWin) LoadLibrary(name string) (Pointer, error) {
	if w.ShouldFailLibrary {
		return nil, errors.New("error")
	}
	ret := 10000
	return Pointer(&ret), nil
}

func (w *MockWin) GetProcAddress(libraryAddress, ptrName Pointer) (uintptr, error) {
	if w.ShouldFailFunction {
		return 0, errors.New("error")
	}
	return 1000, nil
}

func (w *MockWin) NtFlushInstructionCache(ptr, size uintptr) error {
	return nil
}

func (w *MockWin) CreateThread(ptr Pointer) (uintptr, error) {
	return 10000, nil
}

func (w *MockWin) ResumeThread(addr uintptr) error {
	return nil
}

func (w *MockWin) WaitForSingleObject(handle uintptr) error {

	return nil
}

func (w *MockWin) UpdateExecMemory(funcAddr uintptr, sc []byte) (err error) {

	return nil
}
func (w *MockWin) VirtualProtect(ptr uintptr, size uintptr, exec, write bool) error {

	return nil
}

func (w *MockWin) CloseHandle(handle uintptr) {
}
