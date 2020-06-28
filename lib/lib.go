package lib

import (
	"io/ioutil"

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

func NewBinaryFromPath(path string) (*Bin, error) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &Bin{Address: Pointer(&dat[0])}, nil
}

func NewBinary(api *Win, size uint) (*Bin, error) {
	addr, err := api.VirtualAlloc(size)
	if err != nil {
		return nil, err
	}
	return &Bin{Address: Pointer(addr)}, nil
}

func LoadInMemory() (err error) {
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

	LoadLibraries(Wapi, Final)

	LoadFunctions(Wapi, Final)

	FixRelocations(Wapi, Final)

	FixDebugSymbols(Wapi, Final)

	StartThread(Wapi, Final)

	return nil
}
