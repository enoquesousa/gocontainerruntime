//go:build windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("This Go Container Runtime uses Linux-specific Namespaces (UTS, PID, Mount).")
	fmt.Println("It cannot be executed natively on Windows.")
	fmt.Println("\nTo test it:")
	fmt.Println("1. Use WSL2 (Windows Subsystem for Linux).")
	fmt.Println("2. In the WSL terminal, run: go build -o runtime .")
	fmt.Println("3. Execute with root privileges: sudo ./runtime run /bin/bash")
	os.Exit(0)
}
