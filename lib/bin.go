package lib

import (
	"debug/pe"
	. "unsafe"
)

type BinAPI interface {
	FillFileHeader()
	FillOptionalHeader()
	FillImports()
	GetAddr() uintptr
	GetHeaderSize() uint
	GetNumSections() uint
	GetSizeOptionalHeader() uintptr
	GetOptionalHeader() Pointer
	AddSection(section Section)
	GetFirstImport() *ImageImportDescriptor
	GetImageBase() uintptr
	GetModules() []Module
	GetRelocAddr() *ImageBaseRelocation
	GetDebugAddr() *DebugDirectory
	AddModule(ptr Pointer, name string, importAddress *ImageImportDescriptor)
	TranslateToRVA(rawAddr uintptr) uintptr
	GetEntryPoint() Pointer
}

type Bin struct {
	Address          Pointer
	FileHeader       *pe.FileHeader
	OptionalHeader32 *pe.OptionalHeader32
	OptionalHeader64 *pe.OptionalHeader64
	Sections         []Section
	Modules          []Module
	HasReloc         bool
	HasDebug         bool
}

type Section struct {
	Name    string
	Address Pointer
	RVA     uintptr // Relative Virtual address
	RRA     uintptr // Relative Raw address
	Size    uint
}
type Module struct {
	Name                  string
	Address               Pointer
	FirstThunkRVA         uint32
	OriginalFirstThunkRVA uint32
}

func (c *Bin) Is64() bool {
	val := c.FileHeader.Machine
	return val == 0x8664 || val == 0xaa64 || val == 0x200
}

func (c *Bin) FillFileHeader() {
	fileHeaderOffset := uint16Val(c.Address, 0x3C)
	c.FileHeader = (*pe.FileHeader)(ptrOffset(c.Address, uintptr(fileHeaderOffset+4)))
}

func (c *Bin) FillOptionalHeader() {
	sizeFileHeader := Sizeof(*c.FileHeader)
	optionalHeader := ptrOffset(Pointer(c.FileHeader), sizeFileHeader)
	if c.Is64() {
		c.OptionalHeader64 = (*pe.OptionalHeader64)(optionalHeader)
	} else {
		c.OptionalHeader32 = (*pe.OptionalHeader32)(optionalHeader)
	}
}

func (c *Bin) FillImports() {
	fileHeaderOffset := uint16Val(c.Address, 0x3C)
	c.FileHeader = (*pe.FileHeader)(ptrOffset(c.Address, uintptr(fileHeaderOffset+4)))
}

func (c *Bin) GetOptionalHeader() Pointer {
	if c.Is64() {
		return Pointer(c.OptionalHeader64)
	} else {
		return Pointer(c.OptionalHeader32)
	}
}

func (c *Bin) GetImageSize() uint {
	if c.Is64() {
		return uint(c.OptionalHeader64.SizeOfImage)
	} else {
		return uint(c.OptionalHeader32.SizeOfImage)
	}
}
func (c *Bin) GetImageBase() uintptr {
	if c.Is64() {
		return uintptr(c.OptionalHeader64.ImageBase)
	} else {
		return uintptr(c.OptionalHeader32.ImageBase)
	}
}

func (c *Bin) GetHeaderSize() uint {
	if c.Is64() {
		return uint(c.OptionalHeader64.SizeOfHeaders)
	} else {
		return uint(c.OptionalHeader32.SizeOfHeaders)
	}
}

func (c *Bin) GetAddr() uintptr {
	return ptrValue(c.Address)
}

func (c *Bin) GetNumSections() uint {
	return uint(c.FileHeader.NumberOfSections)
}

func (c *Bin) GetRelocAddr() *ImageBaseRelocation {
	var offsetImport pe.DataDirectory
	if c.Is64() {
		offsetImport = c.OptionalHeader64.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	} else {
		offsetImport = c.OptionalHeader32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	}

	offset := offsetImport.VirtualAddress
	ptr := ptrOffset(c.Address, uintptr(offset))

	return (*ImageBaseRelocation)(ptr)
}

func (c *Bin) GetDebugAddr() *DebugDirectory {
	var offsetImport pe.DataDirectory
	if c.Is64() {
		offsetImport = c.OptionalHeader64.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG]
	} else {
		offsetImport = c.OptionalHeader32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG]
	}

	offset := offsetImport.VirtualAddress
	ptr := ptrOffset(c.Address, uintptr(offset))

	return (*DebugDirectory)(ptr)
}

func (c *Bin) GetSizeOptionalHeader() uintptr {
	return uintptr(c.FileHeader.SizeOfOptionalHeader)
}
func (c *Bin) GetModules() []Module {
	return c.Modules
}

func (c *Bin) GetEntryPoint() Pointer {
	var entryPoint uint32
	if c.Is64() {
		entryPoint = c.OptionalHeader64.AddressOfEntryPoint
	} else {
		entryPoint = c.OptionalHeader32.AddressOfEntryPoint
	}
	return ptrOffset(c.Address, uintptr(entryPoint))
}

func (c *Bin) AddSection(section Section) {
	c.Sections = append(c.Sections, section)
}
func (c *Bin) AddModule(ptr Pointer, name string, importAddress *ImageImportDescriptor) {
	module := Module{Name: name, Address: ptr, FirstThunkRVA: importAddress.FirstThunk, OriginalFirstThunkRVA: importAddress.OriginalFirstThunk}
	c.Modules = append(c.Modules, module)
}

func (c *Bin) GetFirstImport() *ImageImportDescriptor {
	var offsetImport pe.DataDirectory
	if c.Is64() {
		offsetImport = c.OptionalHeader64.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	} else {
		offsetImport = c.OptionalHeader32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	}
	offset := offsetImport.VirtualAddress
	ptr := ptrOffset(c.Address, uintptr(offset))
	return (*ImageImportDescriptor)(ptr)
}

func (c *Bin) TranslateToRVA(rawAddr uintptr) uintptr {
	var targetSection Section
	for _, section := range c.Sections {
		if rawAddr < section.RRA {
			break
		}
		targetSection = section
	}
	return rawAddr + (targetSection.RVA - targetSection.RRA)
}
