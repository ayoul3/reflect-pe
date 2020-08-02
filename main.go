package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/ayoul3/reflect-pe/lib"
)

var (
	config *lib.Configuration
)

func init() {

	config = lib.GetConfig()
	config.SetLogLevel()

}

func main() {
	var err error

	lib.Wapi = lib.NewWinAPI()
	lib.Binary, err = lib.NewBinaryFromPath(config.BinaryPath)
	if err != nil {
		log.Fatalf("Could not load binary from %s: %s", config.BinaryPath, err)
	}

	if len(config.Keywords) > 0 {
		lib.ObfuscateStrings(config.Keywords)
	}

	err = lib.AllocateMemory()
	if err != nil {
		log.Fatalf("Could not allocate new memory for binary : %s", err)
	}

	if lib.IsManaged() {
		log.Infof("Assembly detected. Loading CLR")
		if err = lib.LoadAssembly(config.CLRRuntime, config.ReflectArgs); err != nil {
			log.Fatalf("Error loading assembly : %s", err)
		}
		return
	}

	err = lib.CopyData()
	if err != nil {
		log.Fatalf("Could not copy data to new memory location : %s", err)
	}

	err = lib.FixOffsets()
	if err != nil {
		log.Fatalf("Could not fix some offsets : %s", err)
	}

	err = lib.PrepareArguments(config.ReflectArgs)
	if err != nil {
		log.Fatalf("Could not inject arguments : %s", err)
	}
	lib.Execute(config.ReflectMethod)
}
