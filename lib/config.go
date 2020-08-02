package lib

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Configuration struct {
	BinaryPath    string   `yaml:"BinaryPath"`
	ReflectArgs   string   `yaml:"ReflectArgs"`
	ReflectMethod string   `yaml:"ReflectMethod"`
	CLRRuntime    string   `yaml:"CLRRuntime"`
	LogLevel      int64    `yaml:"LogLevel"`
	Keywords      []string `yaml:"Keywords"`
}

func GetConfig() *Configuration {
	var config Configuration

	yamlFile, err := ioutil.ReadFile("config.yml")
	if err != nil {
		log.Fatalf("Error when reading config.yml: %s", err)
	}

	if err = yaml.Unmarshal(yamlFile, &config); err != nil {
		log.Fatalf("Error parsing config file: %s", err)
	}

	if config.BinaryPath == "" {
		log.Fatal("BinaryPath is empty. Please configure a valid path in config.yml")
	}
	if config.CLRRuntime == "" {
		config.CLRRuntime = "v2"
	}

	return &config
}

func (c *Configuration) SetLogLevel() {
	logLevels := map[int64]log.Level{0: log.WarnLevel, 1: log.InfoLevel, 2: log.DebugLevel}

	log.SetLevel(logLevels[c.LogLevel])
}
