#!/bin/bash
set -euo pipefail

BINARY=.cache/ebpf-same-cgroup-mark
TABLE=same_cgroup_mark_test
CGROUP_ROOT=/sys/fs/cgroup/ebpf-same-cgroup-mark-test
OTHER_CGROUP="$CGROUP_ROOT/other"

MARK=0x80000000
PORT_SAME=18080
PORT_OTHER=18081

info() { echo "[$(date '+%H:%M:%S')] $*" >&2; }

socat_listen() {
    socat "TCP-LISTEN:$1,bind=127.0.0.1,reuseaddr" \
        OPEN:/dev/null,trunc &
}

socat_connect() {
    printf 'ping\n' | socat - \
        "TCP:127.0.0.1:$1,connect-timeout=5" >/dev/null
}

wait_port() {
    local port="$1"
    local pid="${2:-}"
    for _ in $(seq 100); do
        if ss -ltn "sport = :$port" | grep -q LISTEN; then
            return 0
        fi
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        sleep 0.1
    done
    return 1
}

rule_packets() {
    nft list chain inet "$TABLE" output |
        grep "dport $1" |
        sed -E 's/.*counter packets ([0-9]+).*/\1/'
}

trap dmesg EXIT

# Setup cgroup hierarchy.
info "setting up cgroup hierarchy"
mkdir -p "$CGROUP_ROOT/same" "$OTHER_CGROUP"

# Pre-check: verify basic TCP works before loading BPF.
info "pre-check: verifying basic TCP works before loading BPF"
socat_listen 18082
PRE_CHECK_PID=$!
wait_port 18082 "$PRE_CHECK_PID"
socat_connect 18082
wait "$PRE_CHECK_PID" 2>/dev/null || true

# nftables rules to catch marked packets.
info "configuring nftables rules"
nft add table inet "$TABLE"
nft add chain inet "$TABLE" output \
    '{ type filter hook output priority 0; policy accept; }'
nft add rule inet "$TABLE" output \
    tcp dport "$PORT_SAME" meta mark \& "$MARK" == "$MARK" counter
nft add rule inet "$TABLE" output \
    tcp dport "$PORT_OTHER" meta mark \& "$MARK" == "$MARK" counter

# Load BPF program.
info "loading BPF program"
"$BINARY" load -m "$MARK"

# Positive test: same cgroup connection gets marked.
info "positive test: same-cgroup connection on port $PORT_SAME"
socat_listen "$PORT_SAME"
PID_POS=$!
wait_port "$PORT_SAME" "$PID_POS"
socat_connect "$PORT_SAME"
wait "$PID_POS"

POSITIVE_PACKETS="$(rule_packets "$PORT_SAME")"
test "${POSITIVE_PACKETS:-0}" -gt 0
info "positive test: OK (${POSITIVE_PACKETS} marked packets)"

# Negative test: cross-cgroup connection is NOT marked.
info "negative test: cross-cgroup connection on port $PORT_OTHER"
socat_listen "$PORT_OTHER"
PID_NEG=$!
wait_port "$PORT_OTHER" "$PID_NEG"
(
    echo "$BASHPID" >"$OTHER_CGROUP/cgroup.procs"
    printf 'ping\n' | timeout 10 socat - \
        "TCP:127.0.0.1:$PORT_OTHER,connect-timeout=5" >/dev/null
)
wait "$PID_NEG"

NEGATIVE_PACKETS="$(rule_packets "$PORT_OTHER")"
test "${NEGATIVE_PACKETS:-0}" -eq 0
info "negative test: OK (0 marked packets)"
