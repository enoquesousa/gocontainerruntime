package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func environmentValues(environment []string) map[string]string {
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	return values
}

func TestEnvironmentDefaultsDoNotReadTheHost(t *testing.T) {
	got, err := selectedEnvironment(nil, func(string) (string, bool) {
		t.Fatal("default environment must not inspect host variables")
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, baseEnvironment()) {
		t.Fatal("default environment must contain only the fixed HOME, LANG and PATH")
	}
}

func TestEnvironmentImportsOnlyNamedVariablesAndPreservesBytes(t *testing.T) {
	values := map[string]string{
		"APP_KEY": "synthetic=value\nwith-bytes\xff", "EMPTY": "", "PATH": "/workload/bin",
		"AWS_SECRET_ACCESS_KEY": "must-not-be-inherited",
	}
	var lookedUp []string
	environment, err := selectedEnvironment([]string{"PATH", "EMPTY", "APP_KEY", "APP_KEY"}, func(name string) (string, bool) {
		lookedUp = append(lookedUp, name)
		value, found := values[name]
		return value, found
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"HOME": "/root", "LANG": "C", "PATH": "/workload/bin", "EMPTY": "", "APP_KEY": values["APP_KEY"]}
	if !reflect.DeepEqual(environmentValues(environment), want) {
		t.Fatal("only named variables may override the defaults, without changing their bytes")
	}
	if !reflect.DeepEqual(lookedUp, []string{"PATH", "EMPTY", "APP_KEY", "APP_KEY"}) {
		t.Fatal("lookup must be restricted to the explicitly named variables")
	}
}

func TestEnvironmentRejectsInvalidImportsWithoutEcho(t *testing.T) {
	const marker = "synthetic-private-import"
	for _, name := range []string{"", "1NAME", "A-B", "A B", "A,B", "CHÁVE", "A\x00B", "NAME=" + marker} {
		t.Run(fmt.Sprintf("name-%x", name), func(t *testing.T) {
			_, err := selectedEnvironment([]string{name}, func(string) (string, bool) {
				t.Fatal("invalid names must fail before lookup")
				return "", false
			})
			if err == nil || strings.Contains(err.Error(), marker) {
				t.Fatal("invalid imports require a fixed error")
			}
		})
	}
	for _, test := range []struct {
		value   string
		present bool
	}{{marker, false}, {marker + "\x00", true}} {
		_, err := selectedEnvironment([]string{"APP_KEY"}, func(string) (string, bool) { return test.value, test.present })
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Fatal("missing or null-containing values require a fixed error")
		}
	}
}

func TestEnvironmentSizeLimitCountsAllEntriesAndTerminators(t *testing.T) {
	baseSize := 0
	for _, entry := range baseEnvironment() {
		baseSize += len(entry) + 1
	}
	value := strings.Repeat("x", maxEnvironmentBytes-baseSize-len("EXTRA=")-1)
	lookup := func(string) (string, bool) { return value, true }
	if _, err := selectedEnvironment([]string{"EXTRA"}, lookup); err != nil {
		t.Fatalf("exact environment limit should be accepted: %v", err)
	}
	value += "x"
	if _, err := selectedEnvironment([]string{"EXTRA"}, lookup); err == nil {
		t.Fatal("one byte beyond the environment limit must be rejected")
	}
	names := make([]string, maxEnvironmentVars+1)
	if _, err := selectedEnvironment(names, lookup); err == nil {
		t.Fatal("too many imports must be rejected before lookup")
	}
}

func TestRunConfigPreservesCommandArguments(t *testing.T) {
	for _, test := range []struct {
		name, rootfs string
		input, argv  []string
		cached       bool
	}{
		{"cached", cacheDir, []string{"/bin/sh"}, []string{"/bin/sh"}, true},
		{"explicit", "/trusted-rootfs", []string{"/trusted-rootfs", "/bin/echo", "hello"}, []string{"/bin/echo", "hello"}, false},
		{"flags", "/trusted-rootfs", []string{"/trusted-rootfs", "/bin/sh", "-c", "printf hello", "--env", "value"}, []string{"/bin/sh", "-c", "printf hello", "--env", "value"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := parseRunConfig(test.input, nil, os.LookupEnv)
			if err != nil {
				t.Fatal(err)
			}
			if config.rootfs != test.rootfs || config.useCache != test.cached || !reflect.DeepEqual(config.argv, test.argv) {
				t.Fatal("rootfs selection or container argv changed")
			}
			test.input[len(test.input)-1] = "mutated input"
			if !reflect.DeepEqual(config.argv, test.argv) {
				t.Fatal("the command must keep an independent argument snapshot")
			}
		})
	}
}

func TestRunOptionsStopAtTheFirstPositionalArgument(t *testing.T) {
	t.Setenv("APP_KEY", "synthetic-allowed")
	t.Setenv("NOT_IMPORTED", "synthetic-unselected")
	for _, prefix := range [][]string{{"--env", "APP_KEY"}, {"--env=APP_KEY", "--"}} {
		var received runConfig
		command := newRunCommand(func(config runConfig) error { received = config; return nil })
		command.SetArgs(append(prefix, "/trusted-rootfs", "/bin/sh", "--env", "NOT_IMPORTED", "--help", "-c", "echo"))
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
		want := []string{"/bin/sh", "--env", "NOT_IMPORTED", "--help", "-c", "echo"}
		if !reflect.DeepEqual(received.argv, want) || environmentValues(received.environment)["APP_KEY"] != "synthetic-allowed" {
			t.Fatal("runtime options or container flags were parsed in the wrong phase")
		}
		if _, inherited := environmentValues(received.environment)["NOT_IMPORTED"]; inherited {
			t.Fatal("container arguments must never select environment imports")
		}
	}
}

func TestRuntimeOptionErrorsDoNotExposeValuesOrStartAContainer(t *testing.T) {
	const marker = "synthetic-private-option"
	for _, args := range [][]string{
		{"run", "--env", "NAME=" + marker, "/trusted-rootfs", "/bin/sh"},
		{"run", "--" + marker},
		{"run", "--env"},
	} {
		command := newRootCommand()
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		command.SetArgs(args)
		err := command.Execute()
		if err == nil || strings.Contains(err.Error()+output.String(), marker) {
			t.Fatal("invalid runtime options must fail before any operation, without echoing values")
		}
	}
}

func TestReexecUsesMinimalEnvironmentAndDoesNotDuplicateTheCommand(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-host-only")
	config := runConfig{
		rootfs: "/trusted-rootfs", argv: []string{"/bin/sh", "-c", "echo hello"},
		environment: append(baseEnvironment(), "APP_KEY=synthetic-workload-only"),
	}
	cmd := newChildProcess(config, nil)
	want := []string{"/proc/self/exe", "child", "/trusted-rootfs", "/bin/sh", "-c", "echo hello"}
	if !reflect.DeepEqual(cmd.Args, want) || !reflect.DeepEqual(cmd.Env, baseEnvironment()) {
		t.Fatal("first reexec must use exact argv and only the fixed environment")
	}
	if cmd.Stdin != os.Stdin || cmd.Stdout != os.Stdout || cmd.Stderr != os.Stderr {
		t.Fatal("standard streams must be preserved")
	}
	flags := syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET
	if cmd.SysProcAttr.Cloneflags != uintptr(flags) {
		t.Fatal("namespace flags must be preserved")
	}
	host := newHostProcess("/unused-host-tool", "argument")
	if !reflect.DeepEqual(host.Env, baseEnvironment()) {
		t.Fatal("host setup tools must also receive only the fixed environment")
	}
}

func TestChildCommandRejectsInvalidArityAndManualInvocation(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("This safety test never invokes child as PID 1")
	}
	before, err := currentNamespaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"child"}, {"child", "/rootfs"}, {"child", "/rootfs", "/bin/sh", "-c", "echo"}} {
		command := newRootCommand()
		command.SetArgs(args)
		if err := command.Execute(); err == nil {
			t.Fatal("manual child invocation must fail before mutating the host")
		}
	}
	after, err := currentNamespaces()
	if err != nil || before != after {
		t.Fatal("rejected child commands must not change namespace context")
	}
}

func TestChildContextRequiresAllFourNewNamespaces(t *testing.T) {
	parent := namespaceState{"pid:[1]", "uts:[2]", "mnt:[3]", "net:[4]"}
	current := namespaceState{"pid:[5]", "uts:[6]", "mnt:[7]", "net:[8]"}
	if err := validateChildContext(1, parent, current); err != nil {
		t.Fatal(err)
	}
	if err := validateChildContext(2, parent, current); err == nil {
		t.Fatal("a child must be PID 1")
	}
	for index := range parent {
		unchanged := current
		unchanged[index] = parent[index]
		if err := validateChildContext(1, parent, unchanged); err == nil {
			t.Fatal("every requested namespace must differ from the parent")
		}
		incomplete := parent
		incomplete[index] = ""
		if err := validateChildContext(1, incomplete, current); err == nil {
			t.Fatal("missing namespace metadata must fail closed")
		}
	}
}

func TestHandoffPreservesEnvironmentBytes(t *testing.T) {
	environment := append(baseEnvironment(), "APP_BYTES=\xff\xfevalue\nwith=equals")
	parent := namespaceState{"pid:[1]", "uts:[2]", "mnt:[3]", "net:[4]"}
	data, err := encodeHandoff(environment, parent)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodedParent, err := decodeHandoff(data)
	if err != nil || !reflect.DeepEqual(decoded, environment) || decodedParent != parent {
		t.Fatal("handoff must preserve arbitrary non-NUL bytes and namespace metadata")
	}
}

func TestHandoffRejectsMalformedOrOversizedDataWithoutEcho(t *testing.T) {
	const marker = "synthetic-private-handoff"
	valid, err := encodeHandoff(baseEnvironment(), namespaceState{})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{
		[]byte(marker), []byte(`{"environment":"` + marker + `"}`),
		[]byte(`{"unexpected":"` + marker + `"}`), append(valid, []byte(` {}`)...),
		bytes.Repeat([]byte("x"), maxHandoffBytes+1),
	} {
		if _, _, err := decodeHandoff(data); err == nil || strings.Contains(err.Error(), marker) {
			t.Fatal("malformed handoff data must return a fixed error")
		}
	}
	for _, environment := range [][]string{
		{"APP_KEY=" + marker}, append(baseEnvironment(), "PATH="+marker),
		append(baseEnvironment(), "BAD"), append(baseEnvironment(), "APP_KEY="+marker+"\x00"),
	} {
		if _, err := encodeHandoff(environment, namespaceState{}); err == nil || strings.Contains(err.Error(), marker) {
			t.Fatal("malformed environments must be rejected without echoing their contents")
		}
	}
}

func TestReadHandoffBoundsTheInputAndClosesItsDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "handoff-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeRuntimeFile(file) })
	if _, err := file.Write(bytes.Repeat([]byte("x"), maxHandoffBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readHandoff(file); err == nil {
		t.Fatal("oversized descriptor input must be rejected")
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("the handoff descriptor must be closed even on failure")
	}
}

type environmentReport struct {
	Stage       string `json:"stage"`
	Environment []byte `json:"environment"`
	Closed      bool   `json:"handoff_closed"`
}

func TestEnvironmentRealReexecAndWorkloadExec(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-host-secret")
	t.Setenv("GODEBUG", "synthetic-host-runtime-setting")
	t.Setenv("APP_KEY", strings.Repeat("synthetic-imported-secret", 1500))
	t.Setenv("APP_BYTES", "preserve\xff\xfe")
	environment, err := selectedEnvironment([]string{"APP_KEY", "APP_BYTES"}, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := prepareHandoff(environment)
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.close()
	output := runEnvironmentHelper(t, environment, pipe)
	checkEnvironmentReports(t, output, environment)
}

func runEnvironmentHelper(t *testing.T, environment []string, pipe *handoffPipe) []byte {
	t.Helper()
	cmd := newChildProcess(runConfig{rootfs: "/unused", argv: []string{"unused"}, environment: environment}, pipe.reader)
	// Exercise the real environment/descriptor boundary without requesting namespaces.
	cmd.SysProcAttr = nil
	cmd.Args = []string{os.Args[0], "-test.run=^TestEnvironmentProcessHelper$", "--", "handoff-stage"}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopChild(cmd)
	closeRuntimeFile(pipe.reader)
	if err := sendHandoff(pipe.writer, pipe.data); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("harmless environment helper failed: %v", err)
	}
	return output.Bytes()
}

func checkEnvironmentReports(t *testing.T, output []byte, environment []string) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(output))
	for index, expected := range [][]string{baseEnvironment(), environment} {
		var report environmentReport
		if err := decoder.Decode(&report); err != nil {
			t.Fatal("helper must return two structured environment reports")
		}
		actual := strings.Split(string(report.Environment), "\x00")
		if !reflect.DeepEqual(environmentValues(actual), environmentValues(expected)) {
			t.Fatalf("unexpected environment at stage %d", index)
		}
		if index == 0 && (!report.Closed || report.Stage != "handoff-stage") {
			t.Fatal("the private descriptor must close before final exec")
		}
		if index == 1 && report.Stage != "workload-stage" {
			t.Fatal("syscall.Exec must reach the intended harmless workload")
		}
	}
}

func TestEnvironmentProcessHelper(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if mode != "handoff-stage" && mode != "workload-stage" {
		return
	}
	if mode == "workload-stage" {
		emitEnvironmentReport(mode, false)
		os.Exit(0)
	}
	environment, _, err := readHandoff(os.NewFile(handoffFD, "test handoff"))
	if err != nil {
		os.Exit(2)
	}
	var stat syscall.Stat_t
	closed := errors.Is(syscall.Fstat(handoffFD, &stat), syscall.EBADF)
	emitEnvironmentReport(mode, closed)
	argv := []string{os.Args[0], "-test.run=^TestEnvironmentProcessHelper$", "--", "workload-stage"}
	if err := syscall.Exec("/proc/self/exe", argv, environment); err != nil {
		os.Exit(3)
	}
}

func emitEnvironmentReport(stage string, closed bool) {
	report := environmentReport{stage, []byte(strings.Join(os.Environ(), "\x00")), closed}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		os.Exit(4)
	}
}
