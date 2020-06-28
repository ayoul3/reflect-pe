package main

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/ayoul3/reflect-pe/lib"
)

var (
	path  string
	debug bool
)

func init() {
	flag.StringVar(&path, "path", "", "URL or local path of a PE file")
	flag.BoolVar(&debug, "debug", false, "Show debug & info logs")
	flag.Parse()
	if path == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	log.SetLevel(log.WarnLevel)
	if debug {
		log.SetLevel(log.DebugLevel)
	}
}

func main() {
	var err error
	lib.Wapi = lib.NewWinAPI()
	lib.Binary, err = lib.NewBinaryFromPath(path)
	if err != nil {
		log.Fatalf("Could not load binary from %s: %s", path, err)
	}

	err = lib.LoadInMemory()
	if err != nil {
		log.Fatalf("Could not allocate new memory for binary : %s", err)
	}

	err = lib.CopyData()
	if err != nil {
		log.Fatalf("Could not copy data to new memory location : %s", err)
	}

}
