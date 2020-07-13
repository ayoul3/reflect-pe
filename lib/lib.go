package lib

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	. "unsafe"

	log "github.com/sirupsen/logrus"
)

var (
	Binary *Bin
	Final  *Bin
	Wapi   *Win
)

type ArgInjector func(addr uintptr, api WinAPI, bin BinAPI) error

var ArgInjectors = map[string]ArgInjector{
	"__p___argv": func(addr uintptr, api WinAPI, bin BinAPI) error {
		return InjectArgv(addr, api, bin)
	},
	"__p___argc": func(addr uintptr, api WinAPI, bin BinAPI) error {
		return InjectArgc(addr, api, bin)
	},
	"GetCommandLineA": func(addr uintptr, api WinAPI, bin BinAPI) error {
		return InjectCommandLineA(addr, api, bin)
	},
	"GetCommandLineW": func(addr uintptr, api WinAPI, bin BinAPI) error {
		return InjectCommandLineW(addr, api, bin)
	},
	"__wgetmainargs": func(addr uintptr, api WinAPI, bin BinAPI) error {
		return InjectCmdLn(addr, api, bin)
	},
	"__getmainargs": func(addr uintptr, api WinAPI, bin BinAPI) error {
		return InjectCmdLn(addr, api, bin)
	},
}

func NewWinAPI() *Win {
	return &Win{}
}

func NewBinaryFromDisk(path string) (*Bin, error) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if dat[0] != 77 || dat[1] != 90 {
		return nil, errors.New("Not a valid PE file")
	}
	return &Bin{Address: Pointer(&dat[0])}, nil
}

func NewBinaryFromHTTP(path string) (*Bin, error) {
	var body []byte
	client := &http.Client{}
	req, _ := http.NewRequest("GET", path, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)

	return &Bin{Address: Pointer(&body[0])}, nil
}

func NewBinaryFromPath(path string) (*Bin, error) {
	if strings.HasPrefix(strings.ToLower(path), "http") {
		return NewBinaryFromHTTP(path)
	}
	return NewBinaryFromDisk(path)
}

func NewBinary(api *Win, size uint) (*Bin, error) {
	addr, err := api.VirtualAlloc(size)
	if err != nil {
		return nil, err
	}
	return &Bin{Address: Pointer(addr)}, nil
}

func AllocateMemory() (err error) {
	log.Infof("Loaded initial binary at address 0x%x", Binary.Address)

	PreparePEHeaders(Binary)

	Final, err = NewBinary(Wapi, Binary.GetImageSize())
	if err != nil {
		return err
	}

	log.Infof("Allocated new space for binary at address: 0x%x", Final.Address)

	return nil
}

func CopyData() (err error) {
	CopyHeaders(Wapi, Binary, Final)
	log.Infof("Copied %d bytes of headers to new location", Binary.GetHeaderSize())

	PreparePEHeaders(Final)

	CopySections(Wapi, Binary, Final)
	log.Infof("Copied %d sections to new location", len(Final.Sections))

	err = LoadLibraries(Wapi, Final)
	if err != nil {
		return err
	}
	log.Infof("Loaded %d DLLs", len(Final.Modules))

	err = LoadFunctions(Wapi, Final)
	if err != nil {
		return err
	}
	log.Infof("Loaded their functions")

	return nil
}

func FixOffsets() (err error) {

	if Final.IsDynamic() {
		FixRelocations(Wapi, Final)
	} else {
		log.Warn("Static pe file - Trying to manually fixing offsets - May break!")
		FixingHardcodedOffsets(Wapi, Final)
	}

	return nil
}

func PrepareArguments(args string) (err error) {
	if len(args) < 1 {
		return nil
	}
	Final.Argv = strings.Split(args, " ")
	Final.Argc = len(Final.Argv)

	log.Infof("Injecting arguments")
	for _, function := range Final.GetFunctions() {
		if injectorFunc, ok := ArgInjectors[function.Name]; ok {
			log.Infof("Calling args injector for: %s\n", function.Name)
			injectorFunc(function.Address, Wapi, Final)
		}
	}

	return err
}

func Execute(method string) (err error) {

	//*(*uint32)(Final.GetEntryPoint()) = 0xCCCCCCCC

	UpdateSectionProtections(Wapi, Final)
	log.Infof("Updated memory protections")

	switch method {
	case "function":
		err = ExecuteInFunction(Wapi, Final)
	case "wait":
		err = StartThreadWait(Wapi, Final, true)
	default:
		err = StartThreadWait(Wapi, Final, false)
	}

	if err != nil {
		log.Fatalf("Error creating thread %s", err)
	}

	return nil
}
