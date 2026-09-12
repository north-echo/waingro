#!/usr/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    /usr/bin/printf 'backup-host.sh must run as root\n' >&2
    exit 77
fi
if [[ $(/usr/bin/hostname -s) != hanna2 ]]; then
    /usr/bin/printf 'refusing to back up any host except hanna2\n' >&2
    exit 78
fi
if [[ $# -ne 1 ]]; then
    /usr/bin/printf 'usage: %s /mounted/offline-destination\n' "$0" >&2
    exit 64
fi

DESTINATION=$(/usr/bin/readlink -f -- "$1")
test -d "${DESTINATION}"
DEST_SOURCE=$(/usr/bin/findmnt -n -o SOURCE --target "${DESTINATION}")
ROOT_SOURCE=$(/usr/bin/findmnt -n -o SOURCE --target /)
if [[ ${DEST_SOURCE} == "${ROOT_SOURCE}" ]]; then
    /usr/bin/printf 'backup destination must not be the root filesystem\n' >&2
    exit 77
fi
if [[ ${DEST_SOURCE} != /dev/* ]]; then
    /usr/bin/printf 'backup destination must be a separately mounted block device\n' >&2
    exit 77
fi

for command in xfsdump xfsrestore zstd sha256sum sfdisk vgcfgbackup lvcreate lvremove; do
    if ! command -v "${command}" >/dev/null; then
        /usr/bin/printf 'missing required command: %s\n' "${command}" >&2
        exit 69
    fi
done

AVAILABLE=$(/usr/bin/df --output=avail -B1 "${DESTINATION}" | /usr/bin/tail -1 | /usr/bin/tr -d ' ')
if (( AVAILABLE < 161061273600 )); then
    /usr/bin/printf 'backup destination needs at least 150 GiB free\n' >&2
    exit 77
fi

STAMP=$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)
SNAPSHOT=waingro_backup_${STAMP}
SNAPSHOT_DEVICE=/dev/fedora/${SNAPSHOT}
MOUNTPOINT=/run/waingro-backup-${STAMP}
PARTIAL=${DESTINATION}/hanna2-pre-campaign-${STAMP}.partial
FINAL=${DESTINATION}/hanna2-pre-campaign-${STAMP}

cleanup() {
    /usr/bin/umount "${MOUNTPOINT}" >/dev/null 2>&1 || true
    /usr/sbin/lvremove -f "${SNAPSHOT_DEVICE}" >/dev/null 2>&1 || true
    /usr/bin/rmdir "${MOUNTPOINT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

/usr/bin/install -d -o root -g root -m 0700 "${PARTIAL}" "${MOUNTPOINT}"
/usr/sbin/lvcreate --snapshot --size 32G --name "${SNAPSHOT}" /dev/fedora/root
/usr/bin/mount -o ro,nouuid "${SNAPSHOT_DEVICE}" "${MOUNTPOINT}"

/usr/sbin/sfdisk --dump /dev/nvme0n1 >"${PARTIAL}/nvme0n1.partition-table.sfdisk"
/usr/sbin/vgcfgbackup -f "${PARTIAL}/fedora.vgcfg" fedora
/usr/bin/efibootmgr -v >"${PARTIAL}/efibootmgr.txt"
/usr/bin/lsblk -e7 -O --json >"${PARTIAL}/lsblk.json"
/usr/bin/rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' \
    | /usr/bin/sort >"${PARTIAL}/packages.tsv"
/usr/bin/systemctl list-unit-files --no-pager >"${PARTIAL}/systemd-unit-files.txt"
/usr/bin/firewall-cmd --list-all-zones >"${PARTIAL}/firewalld-zones.txt"
/usr/bin/tar --acls --xattrs --selinux --numeric-owner -C /boot -cpf - . \
    | /usr/bin/zstd -T0 -19 -o "${PARTIAL}/boot.tar.zst"
/usr/sbin/xfsdump -J -l 0 -f - "${MOUNTPOINT}" \
    | /usr/bin/zstd -T0 -10 -o "${PARTIAL}/root.xfsdump.zst"

/usr/bin/zstd -t "${PARTIAL}/boot.tar.zst" "${PARTIAL}/root.xfsdump.zst"
(
    cd "${PARTIAL}"
    /usr/bin/sha256sum ./* >SHA256SUMS
    /usr/bin/sha256sum -c SHA256SUMS
)
/usr/bin/sync -f "${PARTIAL}"
cleanup
trap - EXIT INT TERM
/usr/bin/mv "${PARTIAL}" "${FINAL}"
/usr/bin/sync -f "${DESTINATION}"
/usr/bin/printf 'verified backup: %s\n' "${FINAL}"
/usr/bin/printf 'disconnect or power down the destination device before dynamic testing\n'
