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
    return 0;
}

__attribute__((always_inline)) void save_obj_fd(struct bpf_context_t *bpf_ctx) {
    struct tgid_fd_t key = {
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .fd = bpf_ctx->retval,
    };

    switch (bpf_ctx->cmd) {
    case BPF_MAP_CREATE:
    case BPF_MAP_GET_FD_BY_ID:
        bpf_map_update_elem(&tgid_fd_map_id, &key, &bpf_ctx->map_id, BPF_ANY);
        break;
    case BPF_PROG_LOAD:
    case BPF_PROG_GET_FD_BY_ID:
        bpf_map_update_elem(&tgid_fd_prog_id, &key, &bpf_ctx->prog_id, BPF_ANY);
        break;
    }
}

__attribute__((always_inline)) u32 fetch_map_id(int fd) {
    struct tgid_fd_t key = {
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .fd = fd,
    };

    u32 *map_id = bpf_map_lookup_elem(&tgid_fd_map_id, &key);
    if (map_id == NULL) {
        return 0;
    }
    return *map_id;
}

__attribute__((always_inline)) u32 fetch_prog_id(int fd) {
    struct tgid_fd_t key = {
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .fd = fd,
    };

    u32 *map_id = bpf_map_lookup_elem(&tgid_fd_prog_id, &key);
    if (map_id == NULL) {
        return 0;
    }
    return *map_id;
}

__attribute__((always_inline)) void populate_map_id_and_prog_id(struct bpf_context_t *bpf_ctx) {
    switch (bpf_ctx->cmd) {
    case BPF_MAP_LOOKUP_ELEM:
    case BPF_MAP_UPDATE_ELEM:
    case BPF_MAP_DELETE_ELEM:
    case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
    case BPF_MAP_GET_NEXT_KEY:
    case BPF_MAP_FREEZE:
        bpf_ctx->map_id = fetch_map_id(bpf_ctx->attr.map_fd);
        break;
    case BPF_PROG_ATTACH:
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.attach_bpf_fd);
        break;
    case BPF_PROG_DETACH:
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.target_fd);
        break;
    case BPF_PROG_QUERY:
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.query.target_fd);
        break;
    case BPF_PROG_TEST_RUN:
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.test.prog_fd);
        break;
    case BPF_PROG_GET_NEXT_ID:
        bpf_ctx->prog_id = bpf_ctx->attr.start_id;
        break;
    case BPF_MAP_GET_NEXT_ID:
        bpf_ctx->map_id = bpf_ctx->attr.start_id;
        break;
    case BPF_OBJ_GET_INFO_BY_FD:
        bpf_ctx->map_id = fetch_map_id(bpf_ctx->attr.info.bpf_fd);
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.info.bpf_fd);
        break;
    case BPF_OBJ_PIN:
        bpf_ctx->map_id = fetch_map_id(bpf_ctx->attr.bpf_fd);
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.bpf_fd);
        break;
    case BPF_RAW_TRACEPOINT_OPEN:
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.raw_tracepoint.prog_fd);
        break;
    case BPF_TASK_FD_QUERY:
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.task_fd_query.fd);
        break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    case BPF_MAP_LOOKUP_BATCH:
    case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
    case BPF_MAP_UPDATE_BATCH:
    case BPF_MAP_DELETE_BATCH:
        bpf_ctx->map_id = fetch_map_id(bpf_ctx->attr.batch.map_fd);
        break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    case BPF_LINK_CREATE:
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.link_create.prog_fd);
        break;
    case BPF_LINK_UPDATE:
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.link_update.old_prog_fd);
        break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    case BPF_PROG_BIND_MAP:
        bpf_ctx->map_id = fetch_map_id(bpf_ctx->attr.prog_bind_map.map_fd);
        bpf_ctx->prog_id = fetch_prog_id(bpf_ctx->attr.prog_bind_map.prog_fd);
        break;
#endif
    }
}

__attribute__((always_inline)) void send_event(struct pt_regs *ctx, struct bpf_context_t *bpf_ctx) {
    struct bpf_event_t evt = {
        .timestamp = bpf_ktime_get_ns(),
        .cmd = bpf_ctx->cmd,
    };
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // select map if applicable
    if (bpf_ctx->map_id != 0) {
        struct map_t *map = bpf_map_lookup_elem(&bpf_maps, &bpf_ctx->map_id);
        if (map != NULL) {
            evt.map = *map;
            // bpf_printk("cmd:%d map:%s\n", bpf_ctx->cmd, evt.map.name);
        }
    }

    // select prog if applicable
    if (bpf_ctx->prog_id != 0) {
        struct prog_t *prog = bpf_map_lookup_elem(&bpf_progs, &bpf_ctx->prog_id);
        if (prog != NULL) {
            evt.prog = *prog;
            // bpf_printk("cmd:%d prog:%s helpers:%lu\n", bpf_ctx->cmd, evt.prog.name, bpf_ctx->helpers[0]);
        }
    }

    // send event
    u64 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &events, cpu, &evt, sizeof(evt));
    return;
}

SYSCALL_KRETPROBE(bpf) {
    struct bpf_context_t *bpf_ctx = get_ctx();
    if (bpf_ctx == NULL) {
        // should never happen
        return 0;
    }
    bpf_ctx->retval = (int)PT_REGS_RC(ctx);

    // save file descriptor <-> map_id mapping if applicable
    if (bpf_ctx->map_id != 0 || bpf_ctx->prog_id != 0) {
        save_obj_fd(bpf_ctx);
    }

    // populate map_id or prog_id if applicable
    populate_map_id_and_prog_id(bpf_ctx);

    // send monitoring event
    send_event(ctx, bpf_ctx);
    return 0;
}

SEC("kprobe/security_bpf")
int kprobe_security_bpf(struct pt_regs *ctx) {
    struct bpf_context_t *bpf_ctx = reset_ctx();
    if (bpf_ctx == NULL) {
        // should never happen
        return 0;
    }

    bpf_ctx->cmd = (int)PT_REGS_PARM1(ctx);
    bpf_probe_read(&bpf_ctx->attr, sizeof(bpf_ctx->attr), (union bpf_attr *)PT_REGS_PARM2(ctx));
    return 0;
}

SEC("kprobe/security_bpf_map")
int kprobe_security_bpf_map(struct pt_regs *ctx) {
    struct bpf_map *map = (struct bpf_map *)PT_REGS_PARM1(ctx);

    // collect relevant map metadata
    struct map_t m = {};
    bpf_probe_read(&m.id, sizeof(m.id), &map->id);
    bpf_probe_read(&m.name, sizeof(m.name), &map->name);
    bpf_probe_read(&m.map_type, sizeof(m.map_type), &map->map_type);

    // save map metadata
    bpf_map_update_elem(&bpf_maps, &m.id, &m, BPF_ANY);

    // update context
    struct bpf_context_t *bpf_ctx = get_ctx();
    if (bpf_ctx == NULL) {
        // should never happen
        return 0;
    }
    bpf_ctx->map_id = m.id;
    return 0;
}

SEC("kprobe/security_bpf_prog")
int kprobe_security_bpf_prg(struct pt_regs *ctx) {
    struct bpf_prog *prog = (struct bpf_prog *)PT_REGS_PARM1(ctx);
    struct bpf_prog_aux *prog_aux = 0;
    bpf_probe_read(&prog_aux, sizeof(prog_aux), &prog->aux);

    // collect relevant prog metadata
    struct prog_t p = {};
    bpf_probe_read(&p.id, sizeof(p.id), &prog_aux->id);
    bpf_probe_read(&p.prog_type, sizeof(p.prog_type), &prog->type);
    bpf_probe_read(&p.attach_type, sizeof(p.attach_type), &prog->expected_attach_type);
    bpf_probe_read(&p.name, sizeof(p.name), &prog_aux->name);

    // update context
    struct bpf_context_t *bpf_ctx = get_ctx();
    if (bpf_ctx == NULL) {
        // should never happen
        return 0;
    }
    bpf_ctx->prog_id = p.id;

    // add prog helpers
    p.helpers[0] = bpf_ctx->helpers[0];
    p.helpers[1] = bpf_ctx->helpers[1];
    p.helpers[2] = bpf_ctx->helpers[2];

    // save prog metadata
    bpf_map_update_elem(&bpf_progs, &p.id, &p, BPF_ANY);
    return 0;
}

SEC("kprobe/check_helper_call")
int kprobe_check_helper_call(struct pt_regs *ctx) {
    int func_id = 0;
    struct bpf_context_t *bpf_ctx = get_ctx();
    if (bpf_ctx == NULL) {
        // should never happen
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
    struct bpf_insn *insn = (struct bpf_insn *)PT_REGS_PARM2(ctx);
    int ret = bpf_probe_read(&func_id, sizeof(func_id), &insn->imm);
#else
    func_id = (int)PT_REGS_PARM2(ctx);
#endif

    if (func_id >= 128) {
        bpf_ctx->helpers[2] |= (u64) 1 << (func_id - 128);
    } else if (func_id >= 64) {
        bpf_ctx->helpers[1] |= (u64) 1 << (func_id - 64);
    } else if (func_id >= 0) {
        bpf_ctx->helpers[0] |= (u64) 1 << (func_id);
    }
    return 0;
}

#endif