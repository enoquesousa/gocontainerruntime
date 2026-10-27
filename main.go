//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
)

// cacheDir is the local directory where the rootfs will be extracted.
var cacheDir = "./cache/alpine_rootfs"

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "gocontainer",
		Short:         "An educational container runtime for trusted workloads",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, _ error) error {
		return errors.New("invalid runtime options; use --help and pass only variable names to --env")
	})
	pullCmd := &cobra.Command{
		Use:   "pull",
		Short: "Download a basic Alpine rootfs for the container",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return pull()
		},
	}
	childCmd := &cobra.Command{
		Use:                "child ROOTFS COMMAND [ARGS...]",
		Hidden:             true,
		DisableFlagParsing: true,
		Args:               cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return child(args[0], args[1:])
		},
	}
	rootCmd.AddCommand(pullCmd, newRunCommand(executeRun), childCmd)
	return rootCmd
}

func newRunCommand(execute func(runConfig) error) *cobra.Command {
	var names []string
	command := &cobra.Command{
		Use:   "run [--env NAME] [rootfs_path] command [args...]",
		Short: "Run a trusted command with a minimal environment",
		Long: "Pass runtime options before the first positional argument. A single command uses " +
			"the cached rootfs; to pass command arguments, specify the rootfs first.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			config, err := parseRunConfig(args, names, os.LookupEnv)
			if err != nil {
				return err
			}
			return execute(config)
		},
	}
	command.Flags().StringArrayVar(&names, "env", nil, "Import one named variable from the caller; repeat for multiple names")
	command.Flags().SetInterspersed(false)
	return command
}

func executeRun(config runConfig) error {
	if config.useCache {
		if _, err := os.Stat(config.rootfs); errors.Is(err, os.ErrNotExist) {
			fmt.Println("No rootfs provided and cache is empty. Running 'pull' first...")
			if err := pull(); err != nil {
				return err
			}
		}
	}
	info, err := os.Stat(config.rootfs)
	if err != nil || !info.IsDir() {
		return errors.New("rootfs must be an accessible directory")
	}
	return run(config)
}

// run performs the first stage of container creation: setting up Namespaces and Cgroups.
// It then re-executes itself with the 'child' command inside the new isolation layers.
func run(config runConfig) error {
	fmt.Printf("Running Stage 1 (PID: %d)\n", os.Getpid())
	pipe, err := prepareHandoff(config.environment)
	if err != nil {
		return err
	}
	defer pipe.close()
	cleanupCgroups, err := setupCgroups()
	if err != nil {
		return err
	}
	defer cleanupCgroups()
	cmd := newChildProcess(config, pipe.reader)
	if err := cmd.Start(); err != nil {
		return errors.New("cannot start the namespace child")
	}
	closeRuntimeFile(pipe.reader)
	defer stopChild(cmd)
	cleanupNetwork, err := setupNetwork(cmd.Process.Pid)
	if err != nil {
		return err
	}
	defer cleanupNetwork()
	if err := releaseChild(cmd.Process.Pid, pipe); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return errors.New("container process failed")
	}
	return nil
}

func newChildProcess(config runConfig, handoff *os.File) *exec.Cmd {
	// Re-execute itself with 'child' as the first argument to run inside the namespace.
	args := append([]string{"child", config.rootfs}, config.argv...)
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Env = baseEnvironment()
	cmd.ExtraFiles = []*os.File{handoff}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func setupCgroups() (func(), error) {
	dirs := []string{"/sys/fs/cgroup/memory/gocontainer", "/sys/fs/cgroup/cpu/gocontainer"}
	created := make([]string, 0, len(dirs))
	cleanup := func() {
		for _, dir := range created {
			if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Warning: could not remove a runtime cgroup")
			}
		}
	}
	for _, dir := range dirs {
		if err := os.Mkdir(dir, 0755); err != nil {
			cleanup()
			return nil, errors.New("cannot create exclusive cgroups v1 directories")
		}
		created = append(created, dir)
	}
	if err := writeCgroupLimits(dirs); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, nil
}

func writeCgroupLimits(dirs []string) error {
	if err := os.WriteFile(dirs[0]+"/memory.limit_in_bytes", []byte("104857600"), 0644); err != nil {
		return errors.New("cannot configure the memory cgroup")
	}
	if err := os.WriteFile(dirs[1]+"/cpu.shares", []byte("512"), 0644); err != nil {
		return errors.New("cannot configure the CPU cgroup")
	}
	return nil
}

func setupNetwork(pid int) (func(), error) {
	if err := hostCommand("ip", "link", "add", "veth-host", "type", "veth", "peer", "name", "veth-child"); err != nil {
		return nil, err
	}
	cleanup := func() {
		if err := hostCommand("ip", "link", "delete", "veth-host"); err != nil {
			fmt.Fprintln(os.Stderr, "Warning: could not remove the runtime network link")
		}
	}
	pidString := fmt.Sprintf("%d", pid)
	commands := [][]string{
		{"ip", "link", "set", "veth-child", "netns", pidString},
		{"ip", "addr", "add", "10.0.0.1/24", "dev", "veth-host"},
		{"ip", "link", "set", "veth-host", "up"},
		{"nsenter", "-t", pidString, "-n", "ip", "addr", "add", "10.0.0.2/24", "dev", "veth-child"},
		{"nsenter", "-t", pidString, "-n", "ip", "link", "set", "veth-child", "up"},
		{"nsenter", "-t", pidString, "-n", "ip", "link", "set", "lo", "up"},
	}
	for _, command := range commands {
		if err := hostCommand(command[0], command[1:]...); err != nil {
			cleanup()
			return nil, err
		}
	}
	return cleanup, nil
}

func hostCommand(name string, args ...string) error {
	if err := newHostProcess(name, args...).Run(); err != nil {
		return errors.New("host network setup command failed")
	}
	return nil
}

func newHostProcess(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = baseEnvironment()
	return cmd
}

func releaseChild(pid int, pipe *handoffPipe) error {
	for _, controller := range []string{"memory", "cpu"} {
		path := "/sys/fs/cgroup/" + controller + "/gocontainer/cgroup.procs"
		if err := os.WriteFile(path, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
			return errors.New("cannot attach the child to its cgroups")
		}
	}
	// The child waits for EOF before any hostname, chroot, mount or workload operation.
	return sendHandoff(pipe.writer, pipe.data)
}

func stopChild(cmd *exec.Cmd) {
	if cmd.ProcessState != nil {
		return
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		fmt.Fprintln(os.Stderr, "Warning: could not stop the namespace child")
	}
	var exitError *exec.ExitError
	if err := cmd.Wait(); err != nil && !errors.As(err, &exitError) {
		fmt.Fprintln(os.Stderr, "Warning: could not reap the namespace child")
	}
}

// child performs the second stage of container setup inside the isolated namespaces.
// It sets the hostname, chroots into the filesystem, and mounts /proc.
func child(rootfs string, argv []string) error {
	if err := validateCommand(rootfs, argv); err != nil {
		return err
	}
	environment, err := receiveChildEnvironment()
	if err != nil {
		return err
	}
	fmt.Printf("Running Stage 2 (PID: %d in container)\n", os.Getpid())
	if err := enterRootFS(rootfs); err != nil {
		return err
	}
	// LookPath uses the stage's fixed PATH, before opt-in values reach the workload.
	cmdPath, err := exec.LookPath(argv[0])
	if err != nil {
		return errors.New("container command was not found or is not executable")
	}
	if err := syscall.Exec(cmdPath, argv, environment); err != nil {
		return errors.New("cannot execute the container command")
	}
	return nil
}

func enterRootFS(rootfs string) error {
	if err := syscall.Sethostname([]byte("gocontainer")); err != nil {
		return errors.New("cannot set the container hostname")
	}
	if err := syscall.Chroot(rootfs); err != nil {
		return errors.New("cannot enter the container rootfs")
	}
	if err := os.Chdir("/"); err != nil {
		return errors.New("cannot enter the container working directory")
	}
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return errors.New("cannot mount the container proc filesystem")
	}
	return nil
}
