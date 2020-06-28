package main

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/ayoul3/reflect-pe/lib"
)

var (
	path  string
	debug int64
)

func init() {
	debugLevels := map[int64]log.Level{0: log.WarnLevel, 1: log.InfoLevel, 2: log.DebugLevel}

	flag.StringVar(&path, "path", "", "URL or local path of a PE file")
	flag.Int64Var(&debug, "debug", 0, "1: show info logs. 2 show debug logs")
	flag.Parse()
	if path == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	log.SetLevel(debugLevels[debug])

}

func main() {
	var err error
	lib.Wapi = lib.NewWinAPI()
	lib.Binary, err = lib.NewBinaryFromPath(path)
	if err != nil {
		log.Fatalf("Could not load binary from %s: %s", path, err)
	}

	err = lib.AllocateMemory()
	if err != nil {
		log.Fatalf("Could not allocate new memory for binary : %s", err)
	}

	err = lib.CopyData()
	if err != nil {
		log.Fatalf("Could not copy data to new memory location : %s", err)
	}
	err = lib.FixOffsets()
	if err != nil {
		log.Fatalf("Could not fix some offsets : %s", err)
	}

	lib.Execute()

}
