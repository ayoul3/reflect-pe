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

	wapi := lib.NewWinAPI()
	binary, err := lib.NewBinaryFromPath(config.BinaryPath)

	if err != nil {
		log.Fatalf("Could not load binary from %s: %s", config.BinaryPath, err)
	}

	lib.PreparePE(binary, config)

	if err = lib.Reflect(wapi, binary, config); err != nil {
		log.Fatal(err)
	}
}
