package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	handoffFD       = 3
	maxHandoffBytes = 128 << 10
)

var namespaceNames = [...]string{"pid", "uts", "mnt", "net"}

type namespaceState [4]string

type childHandoff struct {
	// JSON encodes []byte as base64, preserving arbitrary non-NUL environment bytes.
	Environment []byte         `json:"environment"`
	Parent      namespaceState `json:"parent_namespaces"`
}

type handoffPipe struct {
	reader *os.File
	writer *os.File
	data   []byte
}

func prepareHandoff(environment []string) (*handoffPipe, error) {
	parent, err := currentNamespaces()
	if err != nil {
		return nil, err
	}
	data, err := encodeHandoff(environment, parent)
	if err != nil {
		return nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, errors.New("cannot create the environment handoff pipe")
	}
	return &handoffPipe{reader, writer, data}, nil
}

func (pipe *handoffPipe) close() {
	closeRuntimeFile(pipe.reader)
	closeRuntimeFile(pipe.writer)
}

func receiveChildEnvironment() ([]string, error) {
	if os.Getpid() != 1 {
		return nil, errors.New("child requires a newly created PID namespace")
	}
	file := os.NewFile(handoffFD, "runtime handoff")
	environment, parent, err := readHandoff(file)
	if err != nil {
		return nil, err
	}
	current, err := currentNamespaces()
	if err != nil {
		return nil, err
	}
	if err := validateChildContext(os.Getpid(), parent, current); err != nil {
		return nil, err
	}
	return environment, nil
}

func currentNamespaces() (namespaceState, error) {
	var state namespaceState
	for index, name := range namespaceNames {
		identity, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil {
			return namespaceState{}, errors.New("cannot inspect runtime namespaces")
		}
		state[index] = identity
	}
	return state, nil
}

func validateChildContext(pid int, parent, current namespaceState) error {
	if pid != 1 {
		return errors.New("child requires a newly created PID namespace")
	}
	for index := range namespaceNames {
		if parent[index] == "" || current[index] == "" || parent[index] == current[index] {
			return errors.New("child requires distinct PID, UTS, mount and network namespaces")
		}
	}
	return nil
}

func encodeHandoff(environment []string, parent namespaceState) ([]byte, error) {
	if err := validateEnvironment(environment); err != nil {
		return nil, err
	}
	data, err := json.Marshal(childHandoff{[]byte(strings.Join(environment, "\x00")), parent})
	if err != nil || len(data) > maxHandoffBytes {
		return nil, errors.New("cannot encode the bounded environment handoff")
	}
	return data, nil
}

func decodeHandoff(data []byte) ([]string, namespaceState, error) {
	if len(data) > maxHandoffBytes {
		return nil, namespaceState{}, errors.New("environment handoff exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var payload childHandoff
	if err := decoder.Decode(&payload); err != nil {
		return nil, namespaceState{}, errors.New("invalid environment handoff")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, namespaceState{}, errors.New("invalid trailing handoff data")
	}
	environment := strings.Split(string(payload.Environment), "\x00")
	if err := validateEnvironment(environment); err != nil {
		return nil, namespaceState{}, err
	}
	return environment, payload.Parent, nil
}

func readHandoff(file *os.File) ([]string, namespaceState, error) {
	defer closeRuntimeFile(file)
	data, err := io.ReadAll(io.LimitReader(file, maxHandoffBytes+1))
	if err != nil {
		return nil, namespaceState{}, errors.New("cannot read the environment handoff")
	}
	return decodeHandoff(data)
}

func sendHandoff(file *os.File, data []byte) error {
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("cannot send the environment handoff")
	}
	return nil
}

func closeRuntimeFile(file *os.File) {
	if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		fmt.Fprintln(os.Stderr, "Warning: could not close a runtime handoff descriptor")
	}
}
