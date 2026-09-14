#!/usr/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    /usr/bin/printf 'restore-drill.sh must run as root\n' >&2
    exit 77
fi
if [[ $(/usr/bin/hostname -s) != hanna2 ]]; then
    /usr/bin/printf 'refusing to run a restore drill on any host except hanna2\n' >&2
    exit 78
fi
if [[ $# -ne 1 ]]; then
    /usr/bin/printf 'usage: %s /mounted/offline-destination/hanna2-pre-campaign-TIMESTAMP\n' \
        "$0" >&2
    exit 64
fi

BACKUP=$(/usr/bin/readlink -f -- "$1")
if [[ ! -d ${BACKUP} || $(/usr/bin/basename "${BACKUP}") != hanna2-pre-campaign-* ]]; then
    /usr/bin/printf 'backup path name or type violates restore-drill policy\n' >&2
    exit 77
fi
BACKUP_SOURCE=$(/usr/bin/findmnt -n -o SOURCE --target "${BACKUP}")
ROOT_SOURCE=$(/usr/bin/findmnt -n -o SOURCE --target /)
BACKUP_DISK=$(/usr/bin/lsblk -srno PATH,TYPE "${BACKUP_SOURCE}" \
    | /usr/bin/awk '$2 == "disk" {print $1; exit}')
ROOT_DISK=$(/usr/bin/lsblk -srno PATH,TYPE "${ROOT_SOURCE}" \
    | /usr/bin/awk '$2 == "disk" {print $1; exit}')
if [[ \
    ${BACKUP_SOURCE} != /dev/* \
    || -z ${BACKUP_DISK} \
    || -z ${ROOT_DISK} \
    || ${BACKUP_DISK} == "${ROOT_DISK}" \
]]; then
    /usr/bin/printf 'backup must be mounted from a separate physical disk\n' >&2
    exit 77
fi

for required in \
    SHA256SUMS boot.tar.zst root.xfsdump.zst root-verification-files.sha256 \
    fedora.vgcfg nvme0n1.partition-table.sfdisk; do
    if [[ ! -f ${BACKUP}/${required} || -L ${BACKUP}/${required} ]]; then
        /usr/bin/printf 'required backup file is missing or unsafe: %s\n' "${required}" >&2
        exit 77
    fi
done

for command in awk basename date find findmnt lsblk lvcreate lvremove lvs \
    mkdir mkfs.xfs mount mv readlink rmdir sha256sum sync tar umount \
    xfsrestore zstd; do
    if ! command -v "${command}" >/dev/null; then
        /usr/bin/printf 'missing required command: %s\n' "${command}" >&2
        exit 69
    fi
done

(
    cd "${BACKUP}"
    /usr/bin/sha256sum -c SHA256SUMS
)

STAMP=$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)
DRILL=waingro_restore_drill_${STAMP}
DRILL_DEVICE=/dev/fedora/${DRILL}
MOUNTPOINT=/run/${DRILL}
REPORT_PARTIAL=${BACKUP}/restore-drill-${STAMP}.txt.partial
REPORT=${BACKUP}/restore-drill-${STAMP}.txt
CREATED=false
MOUNTED=false

cleanup() {
    if [[ ${MOUNTED} == true ]]; then
        /usr/bin/umount "${MOUNTPOINT}" >/dev/null 2>&1 || true
    fi
    if [[ ${CREATED} == true ]]; then
        /usr/sbin/lvremove -f "${DRILL_DEVICE}" >/dev/null 2>&1 || true
    fi
    /usr/bin/rmdir "${MOUNTPOINT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if /usr/sbin/lvs "${DRILL_DEVICE}" >/dev/null 2>&1 || [[ -e ${MOUNTPOINT} ]]; then
    /usr/bin/printf 'restore-drill target already exists\n' >&2
    exit 77
fi

/usr/sbin/lvcreate --yes --size 200G --name "${DRILL}" fedora
CREATED=true
/usr/sbin/mkfs.xfs -f "${DRILL_DEVICE}"
/usr/bin/mkdir -m 0700 "${MOUNTPOINT}"
/usr/bin/mount -o nosuid,nodev,noexec "${DRILL_DEVICE}" "${MOUNTPOINT}"
MOUNTED=true

/usr/bin/zstd --decompress --stdout "${BACKUP}/root.xfsdump.zst" \
    | /usr/sbin/xfsrestore -J - "${MOUNTPOINT}"
(
    cd "${MOUNTPOINT}"
    /usr/bin/sha256sum -c "${BACKUP}/root-verification-files.sha256"
)

BOOT_CHECK=${MOUNTPOINT}/waingro-boot-archive-check
/usr/bin/mkdir -m 0700 "${BOOT_CHECK}"
/usr/bin/zstd --decompress --stdout "${BACKUP}/boot.tar.zst" \
    | /usr/bin/tar --extract --preserve-permissions --file - --directory "${BOOT_CHECK}"
if [[ -z $(/usr/bin/find "${BOOT_CHECK}" -mindepth 1 -print -quit) ]]; then
    /usr/bin/printf 'restored boot archive is empty\n' >&2
    exit 77
fi

{
    /usr/bin/printf 'schema_version=1.0\n'
    /usr/bin/printf 'host=hanna2\n'
    /usr/bin/printf 'backup=%s\n' "$(/usr/bin/basename "${BACKUP}")"
    /usr/bin/printf 'backup_disk=%s\n' "${BACKUP_DISK}"
    /usr/bin/printf 'temporary_device=%s\n' "${DRILL_DEVICE}"
    /usr/bin/printf 'root_dump_restore=verified\n'
    /usr/bin/printf 'root_file_hashes=verified\n'
    /usr/bin/printf 'boot_archive_restore=verified\n'
    /usr/bin/printf 'completed_at=%s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"${REPORT_PARTIAL}"
/usr/bin/sync -f "${REPORT_PARTIAL}"
cleanup
CREATED=false
MOUNTED=false
trap - EXIT INT TERM
/usr/bin/mv "${REPORT_PARTIAL}" "${REPORT}"
/usr/bin/sha256sum "${REPORT}" >"${REPORT}.sha256"
/usr/bin/sync -f "${BACKUP}"
/usr/bin/printf 'verified restore drill: %s\n' "${REPORT}"
