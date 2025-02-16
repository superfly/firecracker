// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use seccomp::{allow_syscall, allow_syscall_if, SyscallRuleSet};

/// Returns a list of rules that allow syscalls required for running a rust program.
pub fn rust_required_rules() -> Vec<SyscallRuleSet> {
    vec![
        allow_syscall(libc::SYS_exit_group),
        allow_syscall(libc::SYS_futex),
        allow_syscall(libc::SYS_munmap),
        allow_syscall(libc::SYS_rt_sigaction),
        allow_syscall(libc::SYS_rt_sigprocmask),
        allow_syscall(libc::SYS_sigaltstack),
        allow_syscall(libc::SYS_tkill),
    ]
}

/// Returns a list of rules that allow syscalls required for executing another program.
pub fn jailer_required_rules() -> Vec<SyscallRuleSet> {
    vec![
        allow_syscall(libc::SYS_execve),
        allow_syscall(libc::SYS_mmap),
        allow_syscall(libc::SYS_mprotect),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_arch_prctl),
        allow_syscall(libc::SYS_set_tid_address),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_readlink),
        #[cfg(target_arch = "x86_64")]
        allow_syscall(libc::SYS_open),
        allow_syscall(libc::SYS_read),
        allow_syscall(libc::SYS_close),
        allow_syscall(libc::SYS_brk),
        allow_syscall(libc::SYS_sched_getaffinity),
    ]
}
