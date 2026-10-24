# Security Policy

## Supported Versions

The following versions of `gocontainerruntime` are currently being supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

This repository does not currently list a verified private reporting address.
Arrange a private channel with the maintainer before sharing sensitive details.
Do not put credentials, private data or sensitive exploit details in a public
issue. Include a minimal reproduction without real secrets.

## Trust boundary

This is an educational Linux runtime for trusted operators, root filesystems and
workloads. It runs with root privileges and does not implement a user namespace,
capability reduction, seccomp policy or a production OCI security boundary.
Namespace setup and chroot do not make hostile code safe to run as root. The
Linux [chroot documentation](https://man7.org/linux/man-pages/man2/chroot.2.html)
describes why changing the filesystem root is not a full sandbox.

Keep the repository, working directory, image cache and supplied rootfs under
operator control. Do not use this runtime to execute uploaded images or commands
from untrusted users. The existing cgroups v1 and network demonstration also
requires an appropriate disposable host; unit test success does not validate
those privileged operations.

## Credential flow

There is no HTTP authentication layer, user database, JWT, session cookie or
refresh token. The operating system and any sudo policy authorize execution.

| Stage | Environment/credential handling |
|---|---|
| Parent CLI | Reads only the environment names explicitly selected with `run --env NAME`; invalid or missing selections fail without printing their values. |
| Internal re-exec | Starts with a fixed `PATH`, `HOME=/root` and `LANG=C`; selected values travel through a bounded internal pipe, not through argv or the initial child environment. |
| Workload | Receives the minimal environment plus explicit selections after filesystem setup. Imported values can be read by that process and its descendants. |
| Other host variables | Are not copied to the workload automatically. This includes API/cloud keys, proxy credentials, SSH agent sockets and loader configuration. |

The pipe is a local process handoff, not encryption or an authentication token.
Explicit imports such as loader settings are intended for the workload and must
not affect the runtime's own re-exec. The internal `child` command is a runtime
implementation detail; its validation prevents accidental direct use, not an
attacker who already controls a privileged process.

Host helpers (`ip` and `nsenter`) are selected using the operator's trusted
`PATH`; their launched environment is minimized separately. Keep that search
path and the selected host executables under operator control.

Environment minimization prevents accidental credential inheritance. It does not
protect host secrets from a malicious root workload, from privileged observers,
or from secrets deliberately baked into the supplied filesystem. Rotate an
imported key at its provider, update its source and restart the workload; this
runtime does not provide a secret store or live rotation protocol.

## Root filesystem download

The built-in pull uses a pinned Alpine x86_64 minirootfs over HTTPS, refuses
redirects and non-success status, limits download/extraction size and verifies a
SHA-256 embedded in the source before extraction. A runtime download of a second
checksum file is not used as the trust decision.

Archive extraction uses Go's traversal-resistant `os.Root` API and validates
entry/link paths. It rejects escaping paths and unsupported special entries.
Absolute links from the image are converted to relative links with the same
meaning inside the rootfs. Partial downloads or failed extraction are cleaned
up, and an existing cache is not silently replaced. These checks constrain
archive writes; they do not certify that the image's programs are safe.

The expected image version and digest must be reviewed together when updating
the source. Existing caches and custom root filesystems are not re-verified by
`run`, and are not automatically upgraded. For background on the filesystem APIs, see the Go team's
[path traversal explanation](https://go.dev/blog/osroot).
