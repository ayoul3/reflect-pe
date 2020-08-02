package lib

import (
	"github.com/pkg/errors"
	"github.com/ropnop/go-clr"
	log "github.com/sirupsen/logrus"
)

func PreparePE(bin BinAPI, config *Configuration) {

	if len(config.Keywords) > 0 {
		ObfuscateStrings(bin, config.Keywords)
	}
	ParsePEHeaders(bin)
	AppendArgs(bin, config.ReflectArgs)
}

func Reflect(api WinAPI, bin BinAPI, config *Configuration) (err error) {
	if bin.IsManaged() {
		return loadCLRAssembly(bin, config)
	}
	return loadUnmanaged(api, bin, config)
}

func loadCLRAssembly(bin BinAPI, config *Configuration) (err error) {
	log.Infof("Assembly detected. Loading CLR")
	_, err = clr.ExecuteByteArray(config.CLRRuntime, bin.GetData(), bin.GetArguments())
	if err != nil {
		return errors.Wrapf(err, "Error loading assembly:")
	}
	return nil
}

func loadUnmanaged(api WinAPI, bin BinAPI, config *Configuration) (err error) {
	var final BinAPI

	final, err = AllocateMemory(api, bin)
	if err != nil {
		return errors.Wrapf(err, "Could not allocate new memory for binary")
	}

	if err = CopyData(api, bin, final); err != nil {
		return errors.Wrapf(err, "Could not copy data to new memory location :")
	}

	if err = FixOffsets(api, final); err != nil {
		return errors.Wrapf(err, "Could not fix some offsets ")
	}

	if err = PrepareArguments(api, final); err != nil {
		return errors.Wrapf(err, "Could not inject arguments ")
	}

	return Execute(api, final, config.ReflectMethod)
}
