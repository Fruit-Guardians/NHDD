# KernelSU tracefs permission patch

NHDD's fast capture creates and removes its own isolated tracefs instance.
On some KernelSU devices SELinux remains `Enforcing`, but the `ksu` domain
cannot create an instance or write raw syscall event controls. Apply the rules
in `nhdd_tracefs.sepolicy.rule` through the KernelSU/APatch policy mechanism,
then restart NHDD. The rules do not set SELinux permissive, do not grant
general `/proc` or filesystem access, and do not authorize the `shell` or `su`
domains.

For a temporary live test on a rooted device with KernelSU's `ksud` available:

```sh
ksud sepolicy apply /path/to/nhdd_tracefs.sepolicy.rule
```

On APatch/Magisk environments, the equivalent live loader is
`magiskpolicy --live --apply`.

For persistence, install the same rule through the device's KernelSU policy
module flow and reboot. NHDD does not need a boot service or a pre-created
instance. Verify with `getenforce`, `id -Z`, and NHDD's `--events tracefs`
diagnostics before relying on fast capture.
