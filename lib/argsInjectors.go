package lib

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
	. "unsafe"
)

func InjectArgv(funcAddr uintptr, api WinAPI, bin BinAPI) (err error) {

	var sc []byte
	_, argv := bin.GetArgs()
	ptrArgs := buildArgvPointers(argv)

	// movabs rax, entrypoint
	// ret
	opcode := fmt.Sprintf("48b8%xc3", formatPtr(ptrArgs))
	if sc, err = hex.DecodeString(opcode); err != nil {
		return err
	}

	return api.UpdateExecMemory(funcAddr, sc)
}

func InjectArgc(funcAddr uintptr, api WinAPI, bin BinAPI) (err error) {
	var sc []byte
	argc, _ := bin.GetArgs()
	argcBytes := formatAddr(uintptr(argc))
	addrArgc := Pointer(&argcBytes[0])

	// movabs rax, entrypoint
	// ret
	opcode := fmt.Sprintf("48b8%xc3", formatPtr(addrArgc))
	if sc, err = hex.DecodeString(opcode); err != nil {
		return err
	}

	return api.UpdateExecMemory(funcAddr, sc)
}

func InjectCommandLineA(funcAddr uintptr, api WinAPI, bin BinAPI) (err error) {
	var sc []byte
	_, argv := bin.GetArgs()
	cmdLine := strings.Join(argv, " ")
	addrCmdLine := createStrPtr(cmdLine)

	// movabs rax, entrypoint
	// ret
	opcode := fmt.Sprintf("48b8%xc3", formatPtr(addrCmdLine))
	if sc, err = hex.DecodeString(opcode); err != nil {
		return err
	}

	return api.UpdateExecMemory(funcAddr, sc)
}

func InjectCommandLineW(funcAddr uintptr, api WinAPI, bin BinAPI) (err error) {
	var sc []byte
	_, argv := bin.GetArgs()
	cmdLine := strings.Join(argv, " ")
	runes := utf16.Encode([]rune(cmdLine))
	addrCmdLine := Pointer(&runes[0])

	// movabs rax, entrypoint
	// ret
	opcode := fmt.Sprintf("48b8%xc3", formatPtr(addrCmdLine))
	if sc, err = hex.DecodeString(opcode); err != nil {
		return err
	}

	return api.UpdateExecMemory(funcAddr, sc)
}

// Not used
func InjectCommandLineToArgvW(funcAddr uintptr, api WinAPI, bin BinAPI) (err error) {

	var sc, fixArgc []byte
	argc, argv := bin.GetArgs()
	ptrArgs := buildArgvPointerUnicode(argv)

	// mov dword ds:[rdx], argc
	fixArgcStr := fmt.Sprintf("c702%x", formatAddrVar(uintptr(argc), 4))

	if fixArgc, err = hex.DecodeString(fixArgcStr); err != nil {
		return err
	}

	// movabs rax, entrypoint
	// ret
	opcode := fmt.Sprintf("%x48b8%xc3", fixArgc, formatPtr(ptrArgs))
	if sc, err = hex.DecodeString(opcode); err != nil {
		return err
	}

	err = api.UpdateExecMemory(funcAddr, sc)
	return err
}

func InjectCmdLn(funcAddr uintptr, api WinAPI, bin BinAPI) (err error) {
	var wCmdLine, aCmdLine uintptr

	msvcrtDLL, err := api.LoadLibrary("msvcrt.dll")
	if err != nil {
		return err
	}
	if wCmdLine, err = api.GetProcAddress(msvcrtDLL, createStrPtr("_wcmdln")); err != nil {
		return err
	}
	if aCmdLine, err = api.GetProcAddress(msvcrtDLL, createStrPtr("_acmdln")); err != nil {
		return err
	}
	_, argv := bin.GetArgs()

	cmdLine := strings.Join(argv, " ")
	addrCmdLine := createStrPtr(cmdLine)

	runes := utf16.Encode([]rune(cmdLine))
	runes = append(runes, 0x00)
	addrCmdLineUnicode := Pointer(&runes[0])

	if err = api.VirtualProtect(wCmdLine, Sizeof(uintptr(0)), false, true); err != nil {
		return err
	}
	if err = api.VirtualProtect(aCmdLine, Sizeof(uintptr(0)), false, true); err != nil {
		return err
	}

	api.Memcopy(ptrValue(Pointer(&addrCmdLineUnicode)), wCmdLine, Sizeof(uintptr(0)))
	api.Memcopy(ptrValue(Pointer(&addrCmdLine)), aCmdLine, Sizeof(uintptr(0)))

	return err
}
