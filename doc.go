// Package main implements a minimal container runtime using Linux namespaces and cgroups.
//
// # Implementation Details
//
// The runtime uses several Linux isolation features:
//
// 1. Namespaces (CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWPID, CLONE_NEWNET):
// Provides isolation for mount points, hostname, process IDs, and network stack.
//
// 2. Control Groups (cgroups v1):
// Limits resource usage for memory and CPU.
//
// 3. Chroot:
// Changes the root directory for the container process to a specified Alpine rootfs.
//
// 4. Networking:
// Sets up a veth pair to connect the container to the host network namespace.
//
// # Architecture
//
// The execution follows a two-stage process:
//   - [run]: The first stage sets up namespaces and cgroups, then re-executes itself.
//   - [child]: The second stage (running inside the namespaces) sets up the hostname,
//     chroot, and finally executes the user-requested command.
package main
