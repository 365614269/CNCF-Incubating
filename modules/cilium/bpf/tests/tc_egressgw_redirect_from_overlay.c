// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE_IPV4
#define ENABLE_MASQUERADE_IPV6
#define ENCAP_IFINDEX	42
#define IFACE_IFINDEX	44

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused);

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused);

#define skb_get_tunnel_key mock_skb_get_tunnel_key
static int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
				   struct bpf_tunnel_key *to,
				   __maybe_unused __u32 size,
				   __maybe_unused __u32 flags)
{
	to->remote_ipv4 = v4_node_one;
	/* 0xfffff is the default SECLABEL */
	to->tunnel_id = 0xfffff;
	return 0;
}

#include "bpf_overlay.c"

#include "lib/egressgw.h"
#include "lib/ipcache.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == IFACE_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_OK;
}

static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	params->ifindex = IFACE_IFINDEX;
	return 0;
}

#define FROM_OVERLAY 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_OVERLAY] = &cil_from_overlay,
	},
};

/* Test that a packet matching an egress gateway policy on the from-overlay program
 * gets correctly redirected to the target netdev.
 */
PKTGEN("tc", "tc_egressgw_redirect_from_overlay")
int egressgw_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT,
			.redirect = true,
		});
}

SETUP("tc", "tc_egressgw_redirect_from_overlay")
int egressgw_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, GATEWAY_NODE_IP,
				  EGRESS_IP);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_redirect_from_overlay")
int egressgw_redirect_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	return ret;
}

/* Test that a packet matching an excluded CIDR egress gateway policy on the
 * from-overlay program does not get redirected to the target netdev.
 */
PKTGEN("tc", "tc_egressgw_skip_excluded_cidr_redirect_from_overlay")
int egressgw_skip_excluded_cidr_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT_EXCL_CIDR,
		});
}

SETUP("tc", "tc_egressgw_skip_excluded_cidr_redirect_from_overlay")
int egressgw_skip_excluded_cidr_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, GATEWAY_NODE_IP,
				  EGRESS_IP);
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, EGRESS_GATEWAY_EXCLUDED_CIDR,
				  EGRESS_IP);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_skip_excluded_cidr_redirect_from_overlay")
int egressgw_skip_excluded_cidr_redirect_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_OK,
	});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);
	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);

	return ret;
}

/* Test that a packet matching an egress gateway policy without a gateway on the
 * from-overlay program does not get redirected to the target netdev.
 */
PKTGEN("tc", "tc_egressgw_skip_no_gateway_redirect_from_overlay")
int egressgw_skip_no_gateway_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT_SKIP_NO_GATEWAY,
		});
}

SETUP("tc", "tc_egressgw_skip_no_gateway_redirect_from_overlay")
int egressgw_skip_no_gateway_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, EGRESS_GATEWAY_NO_GATEWAY,
				  EGRESS_IP);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_skip_no_gateway_redirect_from_overlay")
int egressgw_skip_no_gateway_redirect_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_OK,
	});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);

	return ret;
}

/* Test that a packet matching an egress gateway policy without an egressIP on the
 * from-overlay program gets dropped.
 */
PKTGEN("tc", "tc_egressgw_drop_no_egress_ip_from_overlay")
int egressgw_drop_no_egress_ip_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_DROP_NO_EGRESS_IP,
		});
}

SETUP("tc", "tc_egressgw_drop_no_egress_ip_from_overlay")
int egressgw_drop_no_egress_ip_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, GATEWAY_NODE_IP,
				  EGRESS_GATEWAY_NO_EGRESS_IP);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_drop_no_egress_ip_from_overlay")
int egressgw_drop_no_egress_ip_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = CTX_ACT_DROP,
	});

	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);

	return ret;
}

/* Test that a packet matching an egress gateway policy on the from-overlay program
 * gets correctly redirected to the target netdev for IPv6.
 */
PKTGEN("tc", "tc_egressgw_redirect_from_overlay_v6")
int egressgw_redirect_pktgen_v6(struct __ctx_buff *ctx)
{
	return egressgw_pktgen_v6(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT,
			.redirect = true,
		});
}

SETUP("tc", "tc_egressgw_redirect_from_overlay_v6")
int egressgw_redirect_setup_v6(struct __ctx_buff *ctx)
{
	union v6addr ext_svc_ip = EXTERNAL_SVC_IP_V6;
	union v6addr client_ip = CLIENT_IP_V6;
	union v6addr egress_ip = EGRESS_IP_V6;

	add_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, IPV6_SUBNET_PREFIX, GATEWAY_NODE_IP,
				     &egress_ip);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_redirect_from_overlay_v6")
int egressgw_redirect_check_v6(const struct __ctx_buff *ctx)
{
	union v6addr ext_svc_ip = EXTERNAL_SVC_IP_V6;
	union v6addr client_ip = CLIENT_IP_V6;

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});

	del_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, IPV6_SUBNET_PREFIX);

	return ret;
}

/* Test that a packet matching an excluded CIDR egress gateway policy on the
 * from-overlay program does not get redirected to the target netdev.
 */
PKTGEN("tc", "tc_egressgw_skip_excluded_cidr_redirect_from_overlay_v6")
int egressgw_skip_excluded_cidr_redirect_pktgen_v6(struct __ctx_buff *ctx)
{
	return egressgw_pktgen_v6(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT_EXCL_CIDR,
		});
}

SETUP("tc", "tc_egressgw_skip_excluded_cidr_redirect_from_overlay_v6")
int egressgw_skip_excluded_cidr_redirect_setup_v6(struct __ctx_buff *ctx)
{
	union v6addr ext_svc_ip = EXTERNAL_SVC_IP_V6;
	union v6addr client_ip = CLIENT_IP_V6;
	union v6addr egress_ip = EGRESS_IP_V6;

	add_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, IPV6_SUBNET_PREFIX, GATEWAY_NODE_IP,
				     &egress_ip);
	add_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, 128, EGRESS_GATEWAY_EXCLUDED_CIDR,
				     &egress_ip);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_skip_excluded_cidr_redirect_from_overlay_v6")
int egressgw_skip_excluded_cidr_redirect_check_v6(const struct __ctx_buff *ctx)
{
	union v6addr ext_svc_ip = EXTERNAL_SVC_IP_V6;
	union v6addr client_ip = CLIENT_IP_V6;

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_OK,
	});

	del_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, IPV6_SUBNET_PREFIX);
	del_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, 128);

	return ret;
}

/* Test that a packet matching an egress gateway policy without a gateway on the
 * from-overlay program does not get redirected to the target netdev.
 */
PKTGEN("tc", "tc_egressgw_skip_no_gateway_redirect_from_overlay_v6")
int egressgw_skip_no_gateway_redirect_pktgen_v6(struct __ctx_buff *ctx)
{
	return egressgw_pktgen_v6(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT_SKIP_NO_GATEWAY,
		});
}

SETUP("tc", "tc_egressgw_skip_no_gateway_redirect_from_overlay_v6")
int egressgw_skip_no_gateway_redirect_setup_v6(struct __ctx_buff *ctx)
{
	union v6addr ext_svc_ip = EXTERNAL_SVC_IP_V6;
	union v6addr client_ip = CLIENT_IP_V6;
	union v6addr egress_ip = EGRESS_IP_V6;

	add_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, 128, EGRESS_GATEWAY_NO_GATEWAY,
				     &egress_ip);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_skip_no_gateway_redirect_from_overlay_v6")
int egressgw_skip_no_gateway_redirect_check_v6(const struct __ctx_buff *ctx)
{
	union v6addr ext_svc_ip = EXTERNAL_SVC_IP_V6;
	union v6addr client_ip = CLIENT_IP_V6;

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_OK,
	});

	del_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, 128);

	return ret;
}

/* Test that a packet matching an egress gateway policy without an egressIP on the
 * from-overlay program gets dropped.
 */
PKTGEN("tc", "tc_egressgw_drop_no_egress_ip_from_overlay_v6")
int egressgw_drop_no_egress_ip_pktgen_v6(struct __ctx_buff *ctx)
{
	return egressgw_pktgen_v6(ctx, (struct egressgw_test_ctx) {
			.test = TEST_DROP_NO_EGRESS_IP,
		});
}

SETUP("tc", "tc_egressgw_drop_no_egress_ip_from_overlay_v6")
int egressgw_drop_no_egress_ip_setup_v6(struct __ctx_buff *ctx)
{
	union v6addr ext_svc_ip = EXTERNAL_SVC_IP_V6;
	union v6addr client_ip = CLIENT_IP_V6;
	union v6addr no_egress_ip = EGRESS_GATEWAY_NO_EGRESS_IP_V6;

	add_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, 128, GATEWAY_NODE_IP,
				     &no_egress_ip);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_OVERLAY);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_egressgw_drop_no_egress_ip_from_overlay_v6")
int egressgw_drop_no_egress_ip_check_v6(const struct __ctx_buff *ctx)
{
	union v6addr ext_svc_ip = EXTERNAL_SVC_IP_V6;
	union v6addr client_ip = CLIENT_IP_V6;

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = CTX_ACT_DROP,
	});

	del_egressgw_policy_entry_v6(&client_ip, &ext_svc_ip, 128);

	return ret;
}
