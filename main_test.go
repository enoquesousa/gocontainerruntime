//go:build linux

package main

import (
	"os"
	"os/exec"
	"testing"
)

// TestRunCommand checks if the basic structure is sound
func TestRunCommand(t *testing.T) {
	if os.Getenv("GOCONTAINER_PRIVILEGED_TESTS") != "1" {
		t.Skip("Privileged integration is opt-in: set GOCONTAINER_PRIVILEGED_TESTS=1 only in a disposable VM")
	}
	rootfs := os.Getenv("GOCONTAINER_TEST_ROOTFS")
	if rootfs == "" {
		t.Fatal("GOCONTAINER_TEST_ROOTFS must name a trusted, prepared rootfs")
	}
	// Root alone never enables namespace, cgroup or network mutations in tests.
	if os.Getuid() != 0 {
		t.Skip("Skip test because it requires root privileges to create namespaces.")
	}

	// Try to execute the runtime with a simple command inside a container
	// This ensures the Stages 1 and 2 are talking correctly
	cmd := exec.Command("./gocontainer", "run", rootfs, "/bin/echo", "hello")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("Failed to run container: %v, output: %s", err, string(output))
	}

	if string(output) == "" {
		t.Errorf("No output from container")
	}
}
