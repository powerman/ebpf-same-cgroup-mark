// SPDX-License-Identifier: GPL-2.0 OR MIT

#include <stdbool.h>
#include <asm-generic/socket.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_SAME_CGROUP_MARK 0x40000000U
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOL_SOCKET 1

struct same_cgroup_mark_config {
	__u32 mark_mask;
};

struct same_cgroup_socket_cgroup {
	__u64 cgroup_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct same_cgroup_mark_config);
} same_cgroup_mark_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct same_cgroup_socket_cgroup);
} same_cgroup_socket_cgroup SEC(".maps");

static __always_inline __u32 same_cgroup_mark_mask(void)
{
	__u32 key = 0;
	struct same_cgroup_mark_config *cfg;

	cfg = bpf_map_lookup_elem(&same_cgroup_mark_cfg, &key);
	if (cfg && cfg->mark_mask)
		return cfg->mark_mask;

	return DEFAULT_SAME_CGROUP_MARK;
}

static __always_inline int maybe_mark_connect(struct bpf_sock_addr *ctx,
					      struct bpf_sock_tuple *tuple,
					      __u32 tuple_len)
{
	struct same_cgroup_socket_cgroup *storage;
	struct bpf_sock *peer_sk;
	__u32 current_mark = 0;
	__u32 mark_mask;
	__u64 current_cgroup;

	peer_sk = bpf_sk_lookup_tcp(ctx, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
	if (!peer_sk)
		return 1;

	if (peer_sk->state != BPF_TCP_LISTEN)
		goto out;

	storage = bpf_sk_storage_get(&same_cgroup_socket_cgroup, peer_sk, 0, 0);
	current_cgroup = bpf_get_current_cgroup_id();
	if (!storage || !current_cgroup || storage->cgroup_id != current_cgroup)
		goto out;

	mark_mask = same_cgroup_mark_mask();
	if (!mark_mask)
		goto out;

	if (bpf_getsockopt(ctx, SOL_SOCKET, SO_MARK, &current_mark, sizeof(current_mark)))
		current_mark = 0;
	current_mark |= mark_mask;
	(void)bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &current_mark, sizeof(current_mark));

out:
	bpf_sk_release(peer_sk);
	return 1;
}

SEC("cgroup/bind4")
int same_cgroup_bind4(struct bpf_sock_addr *ctx)
{
	struct same_cgroup_socket_cgroup *storage;
	__u64 current_cgroup;

	if (!ctx->sk || ctx->type != SOCK_STREAM || ctx->protocol != IPPROTO_TCP)
		return 1;

	current_cgroup = bpf_get_current_cgroup_id();
	if (!current_cgroup)
		return 1;

	storage = bpf_sk_storage_get(&same_cgroup_socket_cgroup, ctx->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 1;

	storage->cgroup_id = current_cgroup;
	return 1;
}

SEC("cgroup/bind6")
int same_cgroup_bind6(struct bpf_sock_addr *ctx)
{
	struct same_cgroup_socket_cgroup *storage;
	__u64 current_cgroup;

	if (!ctx->sk || ctx->type != SOCK_STREAM || ctx->protocol != IPPROTO_TCP)
		return 1;

	current_cgroup = bpf_get_current_cgroup_id();
	if (!current_cgroup)
		return 1;

	storage = bpf_sk_storage_get(&same_cgroup_socket_cgroup, ctx->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 1;

	storage->cgroup_id = current_cgroup;
	return 1;
}

SEC("cgroup/connect4")
int same_cgroup_connect4(struct bpf_sock_addr *ctx)
{
	struct bpf_sock_tuple tuple = {};

	tuple.ipv4.daddr = ctx->user_ip4;
	tuple.ipv4.dport = (__u16)ctx->user_port;
	return maybe_mark_connect(ctx, &tuple, sizeof(tuple.ipv4));
}

SEC("cgroup/connect6")
int same_cgroup_connect6(struct bpf_sock_addr *ctx)
{
	struct bpf_sock_tuple tuple = {};

	tuple.ipv6.daddr[0] = ctx->user_ip6[0];
	tuple.ipv6.daddr[1] = ctx->user_ip6[1];
	tuple.ipv6.daddr[2] = ctx->user_ip6[2];
	tuple.ipv6.daddr[3] = ctx->user_ip6[3];
	tuple.ipv6.dport = (__u16)ctx->user_port;
	return maybe_mark_connect(ctx, &tuple, sizeof(tuple.ipv6));
}

char _license[] SEC("license") = "Dual MIT/GPL";
