#!/usr/bin/env bash
#
# Runs tunnel_linux.rs's netns_teardown_tests: the Linux tunnel's teardown on a
# real network stack (MR-764: a dropped or failed start leaves no birdo0; bug B:
# a failed start leaves another VPN's routes alone; MR-2018: a symlinked
# /etc/resolv.conf comes back as the same symlink, after a disconnect and after
# a journal-driven crash recovery; MR-740: that recovery also removes the
# endpoint route a killed session left via the uplink, whose record it keeps
# in /run/birdovpn - the namespace's private /run below; MR-2051: an endpoint
# route an earlier session left exactly as a start adds it is taken as ours
# and removed at the disconnect; MR-2040: an idle tunnel neither polls birdo0
# nor wakes in a loop, and a packet from the relay is decrypted onto birdo0).
#
# Those tests create birdo0, add and delete routes and rewrite
# /etc/resolv.conf, so they run only in the private namespace built here, and
# refuse to run anywhere else. Nothing below touches the host:
#   - a private NETWORK namespace: a dummy uplink with a default route that
#     goes nowhere (start() pins its endpoint route via that gateway), and the
#     relay's address 10.99.0.7 on lo, where the tests run a WireGuard
#     responder: start() handshakes before it adds a route or touches DNS;
#   - a private MOUNT namespace: overlays over /etc and /var/lib (upper dirs
#     on a tmpfs; the DNS journal lives in /var/lib/birdovpn, MR-2050), and a
#     tmpfs over /run, which also hides the host's D-Bus socket;
#   - systemctl / resolvectl stand-ins first on PATH, so the code takes its
#     plain-resolv.conf path and can never reconfigure the host's
#     systemd-resolved (which would act on HOST interface indexes).
#
# Usage (CI runs exactly this, from src-tauri/):
#   sudo -E unshare --net --mount --fork --propagation private \
#     bash ../scripts/ci/linux-netns-tests.sh "$(command -v cargo)"
set -euo pipefail

cargo=${1:?usage: linux-netns-tests.sh <path to cargo>}

die() {
  echo "linux-netns-tests: $*" >&2
  exit 97
}

# ---- isolation guards: nothing below may run in the host's namespaces ----
[ "$(id -u)" = 0 ] || die "must run as root (sudo unshare ...)"
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] || die "still in the HOST network namespace"
[ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ] || die "still in the HOST mount namespace"

scratch=$(mktemp -d)
mount -t tmpfs birdo-netns "$scratch"
mkdir -p "$scratch/upper" "$scratch/work" "$scratch/bin" "$scratch/xdg"
mkdir -p "$scratch/varlib-upper" "$scratch/varlib-work"
mount -t overlay birdo-etc -o "lowerdir=/etc,upperdir=$scratch/upper,workdir=$scratch/work" /etc
[ "$(findmnt -n -o FSTYPE --mountpoint /etc | tail -1)" = overlay ] || die "/etc is not the overlay"
touch /etc/.birdo-netns-probe
[ -e "$scratch/upper/.birdo-netns-probe" ] || die "/etc writes do not land in the scratch overlay"
rm -f /etc/.birdo-netns-probe
mount -t overlay birdo-varlib -o "lowerdir=/var/lib,upperdir=$scratch/varlib-upper,workdir=$scratch/varlib-work" /var/lib
[ "$(findmnt -n -o FSTYPE --mountpoint /var/lib | tail -1)" = overlay ] || die "/var/lib is not the overlay"
touch /var/lib/.birdo-netns-probe
[ -e "$scratch/varlib-upper/.birdo-netns-probe" ] || die "/var/lib writes do not land in the scratch overlay"
rm -f /var/lib/.birdo-netns-probe
mount -t tmpfs birdo-run /run

# systemd-resolved is "inactive" here; resolvectl must never reach the host's.
printf '#!/bin/sh\nexit 3\n' > "$scratch/bin/systemctl"
printf '#!/bin/sh\necho "resolvectl is not available in the test namespace" >&2\nexit 1\n' > "$scratch/bin/resolvectl"
chmod 755 "$scratch/bin/systemctl" "$scratch/bin/resolvectl"
export PATH="$scratch/bin:$PATH"
[ "$(command -v resolvectl)" = "$scratch/bin/resolvectl" ] || die "the resolvectl stand-in is not first on PATH"

# ---- the network: an uplink that goes nowhere, the relay on lo ----
ip link set lo up
ip addr add 10.99.0.7/32 dev lo
ip link add uplink0 type dummy
ip link set uplink0 up
ip addr add 10.99.0.2/24 dev uplink0
ip route add default via 10.99.0.1 dev uplink0

# The DNS journal goes to /var/lib/birdovpn, the overlay above; the old
# per-HOME folder it is taken over from stays in the scratch dir.
export XDG_DATA_HOME="$scratch/xdg" BIRDO_NETNS_TESTS=1

# --offline: this namespace has no internet. The earlier root steps of the job
# built the same test binary, so this only runs it.
# --test-threads=1: every test shares the namespace's routing table and
# /etc/resolv.conf.
exec "$cargo" test --locked --offline --lib netns_teardown_tests -- --ignored --nocapture --test-threads=1
