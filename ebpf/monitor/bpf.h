/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _BPF_H_
#define _BPF_H_

__attribute__((always_inline)) static u64 load_protect_bpf() {
    u64 protect_bpf = 0;
    LOAD_CONSTANT("protect_bpf", protect_bpf);
    return protect_bpf;
}

SYSCALL_KPROBE3(bpf, int, cmd, union bpf_attr *, uattr, unsigned int, size) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // check if the current process is allowed to use the bpf syscall
    u32 *cookie = bpf_map_lookup_elem(&tgid_cookie, &tgid);
    if (cookie == NULL) {
        if (load_protect_bpf() == 1) {
            bpf_override_return(ctx, -EPERM);
        }
        return 0;
    }
    bpf_printk("cmd: %d\n", cmd);
    return 0;
}

#endif