package main

import (
	"fmt"
	"os"

	ip "github.com/redstonecraftgg/montelli-antiproxy/checks"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Localhost bool `yaml:"localhost"`
	Bogon     bool `yaml:"bogon"`
}

const configName = "Montelli-Config.yaml"

func ensureConfig() (*Config, error) {
	if _, err := os.Stat(configName); os.IsNotExist(err) {
		defaultConfig := Config{
			Localhost: false,
			Bogon:     true,
		}

		f, err := os.Create(configName)
		if err != nil {
			return nil, fmt.Errorf("failed to create config file: %v", err)
		}
		defer f.Close()
		encoder := yaml.NewEncoder(f)
		if err := encoder.Encode(&defaultConfig); err != nil {
			return nil, fmt.Errorf("failed to write config file: %v", err)
		}
		return &defaultConfig, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to access config file: %v", err)
	}

	f, err := os.Open(configName)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer f.Close()
	var conf Config
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&conf); err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	return &conf, nil
}

func CheckIP(Address string) (bool, string) {
	if Address == "" {
		return false, "Address is empty"
	}

	conf, err := ensureConfig()
	if err != nil {
		fmt.Println(err.Error())
	}

	// Enable Manually
	if conf.Localhost && ip.IsLocalhost(Address) {
		return false, "Address is localhost"
	}

	if ip.IsPrivate(Address) {
		return false, "Address is private"
	}

	if conf.Bogon && ip.IsBogonIP(Address) {
		return false, "Address is bogon"
	}

	return true, ""
}
