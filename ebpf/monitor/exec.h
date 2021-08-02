/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _EXEC_H_
#define _EXEC_H_

struct sched_process_exec_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int data_loc_filename;
    pid_t pid;
    pid_t old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct sched_process_exec_args *ctx)
{
    unsigned short __offset = ctx->data_loc_filename & 0xFFFF;
    char *filename = (char *)ctx + __offset;
    struct path_t path = {};
    bpf_probe_read_str(&path.filename, PATH_MAX_LEN, filename);

    u32 *match = bpf_map_lookup_elem(&allowed_binaries, &path.filename);
    if (match == NULL) {
        return 0;
    }

    // create new cookie for this binary
    u32 cookie = bpf_get_prandom_u32();
    bpf_map_update_elem(&allowed_cookies, &cookie, &cookie, BPF_ANY);

    // set the cookie of the current tgid
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&tgid_cookie, &tgid, &cookie, BPF_ANY);
    return 0;
};

struct sched_process_fork_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct sched_process_fork_args *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();

    // fetch parent cookie if it exists
    u32 *parent_cookie = bpf_map_lookup_elem(&tgid_cookie, &pid);
    if (parent_cookie == NULL) {
        // this process is not tracked, ignore
        return 0;
    }

    // The child pid here might be a tgid or a pid, ideally we'd only care about tgids, but since we expire the cookie
    // and not the tgid_cookie entries on exit, it doesn't matter.
    u32 child_id = (u32) ctx->child_pid;

    // inherit cookie
    u32 child_cookie = *parent_cookie;
    bpf_map_update_elem(&tgid_cookie, &child_id, &child_cookie, BPF_ANY);
    return 0;
}

struct sched_process_exit_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char comm[16];
    pid_t pid;
    int prio;
};

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct sched_process_exit_args *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid;

    if (tgid == pid) {
        u32 *cookie = bpf_map_lookup_elem(&tgid_cookie, &tgid);
        if (cookie == NULL) {
            // this process is not tracked, ignore
            return 0;
        }

        // remove cookie
        u32 to_delete = *cookie;
        bpf_map_delete_elem(&allowed_cookies, &to_delete);
    }
    return 0;
}

#endif
