/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONTEXT_H_
#define _CONTEXT_H_

struct bpf_context_t {
    int cmd;
    u32 map_id;
    u32 prog_id;
    int retval;
    u64 helpers[3];
    union bpf_attr attr;
};

struct bpf_map_def SEC("maps/bpf_context") bpf_context = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct bpf_context_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/bpf_context_gen") bpf_context_gen = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct bpf_context_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

// reset_context resets and return the context associated to the current thread
__attribute__((always_inline)) struct bpf_context_t *reset_ctx() {
    u32 key_gen = 0;
    struct bpf_context_t *bpf_ctx = bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (bpf_ctx == NULL) {
        // should never happen
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bpf_context, &id, bpf_ctx, BPF_ANY);
    return bpf_map_lookup_elem(&bpf_context, &id);
}

// get_context returns the current context associated to the current thread
__attribute__((always_inline)) struct bpf_context_t *get_ctx() {
    u64 id = bpf_get_current_pid_tgid();
    return bpf_map_lookup_elem(&bpf_context, &id);
}

#endif