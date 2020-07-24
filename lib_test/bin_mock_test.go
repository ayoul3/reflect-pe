package lib_test

import (
	. "unsafe"

	"github.com/ayoul3/reflect-pe/lib"
)

type MockBin struct {
	ShouldBe64      bool
	ShouldBeDynamic bool
	Data            []byte
	Address         Pointer
	Sections        []lib.Section
	Modules         []lib.Module
	Functions       []lib.Function
}

func (c *MockBin) Is64() bool {
	if c.ShouldBe64 {
		return true
	}
	return false
}

func (c *MockBin) IsDynamic() bool {
	if c.ShouldBeDynamic {
		return true
	}
	return false
}

func (c *MockBin) FillFileHeader() {

}

func (c *MockBin) FillOptionalHeader() {

}

func (c *MockBin) FillImports() {

}

func (c *MockBin) UpdateData(data []byte) {
	c.Data = data
}

func (c *MockBin) GetData() []byte {
	return c.Data
}

func (c *MockBin) GetOptionalHeader() Pointer {
	return c.Address
}

func (c *MockBin) GetImageSize() uint {
	return 1000
}
func (c *MockBin) GetImageBase() uintptr {
	return 10000
}

func (c *MockBin) GetHeaderSize() uint {
	return 100
}

func (c *MockBin) GetAddr() uintptr {
	return uintptr(Pointer(c.Address))
}
func (c *MockBin) GetArgs() (int, []string) {
	return 1, []string{"hello", "arg"}
}

func (c *MockBin) GetNumSections() uint {
	return 2
}

func (c *MockBin) GetRelocAddr() *lib.ImageBaseRelocation {
	return &lib.ImageBaseRelocation{}
}

func (c *MockBin) GetDebugAddr() *lib.DebugDirectory {
	return &lib.DebugDirectory{}
}

func (c *MockBin) GetSizeOptionalHeader() uintptr {
	return 0
}
func (c *MockBin) GetModules() []lib.Module {
	return c.Modules
}

func (c *MockBin) GetFunctions() []lib.Function {
	return c.Functions
}

func (c *MockBin) GetSections() []lib.Section {
	return c.Sections
}

func (c *MockBin) GetEntryPoint() Pointer {
	i := 1000
	return Pointer(&i)
}

func (c *MockBin) AddSection(section lib.Section) {
	c.Sections = append(c.Sections, section)
}

func (c *MockBin) AddModule(ptr Pointer, name string, importAddress *lib.ImageImportDescriptor) {
	module := lib.Module{Name: name, Address: ptr, FirstThunkRVA: importAddress.FirstThunk, OriginalFirstThunkRVA: importAddress.OriginalFirstThunk}
	c.Modules = append(c.Modules, module)

}

func (c *MockBin) AddFunction(addr uintptr, name string, module *lib.Module) {
	function := lib.Function{Name: name, Address: addr, Module: module}
	c.Functions = append(c.Functions, function)
}

func (c *MockBin) GetFirstImport() *lib.ImageImportDescriptor {
	return (*lib.ImageImportDescriptor)(c.Address)
}

func (c *MockBin) TranslateToRVA(rawAddr uintptr) uintptr {
	return 1000
}
