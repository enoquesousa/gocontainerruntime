package main

import (
	"errors"
	"sort"
	"strings"
)

const (
	containerPath       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	maxEnvironmentBytes = 64 << 10
	maxEnvironmentVars  = 256
)

func baseEnvironment() []string {
	return []string{"HOME=/root", "LANG=C", "PATH=" + containerPath}
}

// selectedEnvironment reads only explicitly named variables. Values never enter argv.
func selectedEnvironment(names []string, lookup func(string) (string, bool)) ([]string, error) {
	if len(names) > maxEnvironmentVars {
		return nil, errors.New("too many environment imports")
	}
	values := map[string]string{"HOME": "/root", "LANG": "C", "PATH": containerPath}
	for _, name := range names {
		if !validEnvironmentName(name) {
			return nil, errors.New("environment imports require a variable name, not NAME=value")
		}
		value, present := lookup(name)
		if !present {
			return nil, errors.New("an imported environment variable is not set")
		}
		if strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("an imported environment value contains a null byte")
		}
		values[name] = value
	}
	environment := make([]string, 0, len(values))
	for name, value := range values {
		environment = append(environment, name+"="+value)
	}
	sort.Strings(environment)
	if err := validateEnvironment(environment); err != nil {
		return nil, err
	}
	return environment, nil
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index := range len(name) {
		char := name[index]
		letter := char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char == '_'
		digit := char >= '0' && char <= '9'
		if !letter && (index == 0 || !digit) {
			return false
		}
	}
	return true
}

func validateEnvironment(environment []string) error {
	if len(environment) > maxEnvironmentVars {
		return errors.New("too many environment entries")
	}
	seen := make(map[string]bool, len(environment))
	size := 0
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if !found || !validEnvironmentName(name) || seen[name] || strings.IndexByte(entry, 0) >= 0 {
			return errors.New("invalid environment handoff")
		}
		if len(entry)+1 > maxEnvironmentBytes-size {
			return errors.New("container environment exceeds 64 KiB")
		}
		size += len(entry) + 1
		seen[name] = true
	}
	if !seen["HOME"] || !seen["LANG"] || !seen["PATH"] {
		return errors.New("environment handoff is missing required defaults")
	}
	return nil
}

type runConfig struct {
	rootfs      string
	argv        []string
	environment []string
	useCache    bool
}

func parseRunConfig(args, names []string, lookup func(string) (string, bool)) (runConfig, error) {
	if len(args) == 0 {
		return runConfig{}, errors.New("run requires a container command")
	}
	config := runConfig{rootfs: cacheDir, argv: args, useCache: true}
	if len(args) > 1 {
		config.rootfs, config.argv, config.useCache = args[0], args[1:], false
	}
	if err := validateCommand(config.rootfs, config.argv); err != nil {
		return runConfig{}, err
	}
	var err error
	config.environment, err = selectedEnvironment(names, lookup)
	config.argv = append([]string(nil), config.argv...)
	return config, err
}

func validateCommand(rootfs string, argv []string) error {
	if rootfs == "" || len(argv) == 0 || argv[0] == "" {
		return errors.New("a rootfs and container command are required")
	}
	for _, value := range append([]string{rootfs}, argv...) {
		if strings.IndexByte(value, 0) >= 0 {
			return errors.New("runtime arguments cannot contain null bytes")
		}
	}
	return nil
}
