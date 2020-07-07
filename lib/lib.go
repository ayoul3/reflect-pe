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
	FixDebugSymbols(Wapi, Final)

	if Final.IsDynamic() {
		FixRelocations(Wapi, Final)
	} else {
		log.Infof("Static pe file - Manually fixing offsets")
		FixingHardcodedOffsets(Wapi, Final)
	}

	return nil
}

func Execute() (err error) {

	//*(*uint32)(Final.GetEntryPoint()) = 0x90CCFF48
	//*(*uint32)(ptrOffset(Final.GetEntryPoint(), 4)) = 0x90909090
	//*(*uint32)(ptrOffset(Final.GetEntryPoint(), 9)) = 0x88C48348
	//*(*uint32)(ptrOffset(Final.GetEntryPoint(), 20)) = 0x88C48348

	UpdateSectionProtections(Wapi, Final)
	log.Infof("Updated memory protections")

	log.Infof("Jumping to entry point %x", Final.GetEntryPoint())
	err = StartThread(Wapi, Final)
	if err != nil {
		log.Fatalf("Error creating thread %s", err)
	}

	return nil
}
