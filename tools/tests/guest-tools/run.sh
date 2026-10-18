#!/bin/sh
# The guest-tools packages (QEMU guest agent, VMware tools) are refused on the cloud image,
# which already carries them, and install on standard systems. A copy that is already
# installed may still be updated. Checks the PRE-INSTALL step of both packages in a scratch root.
set -u
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
fail=0

check() {
	script=$1 xml=$2 name=$3
	rm -rf "$root"/*
	mkdir -p "$root/usr/local/sbin" "$root/usr/local/pkg"
	PKG_ROOTDIR=$root sh "$script" x PRE-INSTALL >/dev/null 2>&1 || { echo "FAIL $name: refused on a standard system"; fail=1; }
	printf '#!/bin/sh\n' > "$root/usr/local/sbin/freesense-cloud-init"
	chmod +x "$root/usr/local/sbin/freesense-cloud-init"
	out=$(PKG_ROOTDIR=$root sh "$script" x PRE-INSTALL 2>&1)
	rc=$?
	[ "$rc" -ne 0 ] || { echo "FAIL $name: installed on the cloud image"; fail=1; }
	echo "$out" | grep -q "cloud image" || { echo "FAIL $name: no reason given on the cloud image"; fail=1; }
	: > "$root/usr/local/pkg/$xml"
	PKG_ROOTDIR=$root sh "$script" x PRE-INSTALL >/dev/null 2>&1 || { echo "FAIL $name: an installed copy cannot be updated on the cloud image"; fail=1; }
	PKG_ROOTDIR=$root sh "$script" x PRE-DEINSTALL >/dev/null 2>&1 || { echo "FAIL $name: other pkg phases must pass"; fail=1; }
}

here=$(cd "$(dirname "$0")/../../.." && pwd)
check "$here/emulators/FreeSense-pkg-Qemu-Guest-Agent/files/pkg-install.in" qemu-guest-agent.xml qemu-guest-agent
check "$here/emulators/FreeSense-pkg-Open-VM-Tools/files/pkg-install.in" open-vm-tools.xml open-vm-tools
[ "$fail" -eq 0 ] && echo "guest tools packages: ok"
exit "$fail"
