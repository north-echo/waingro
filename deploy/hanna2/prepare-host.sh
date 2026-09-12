#!/usr/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    /usr/bin/printf 'prepare-host.sh must run as root\n' >&2
    exit 77
fi
if [[ $(/usr/bin/hostname -s) != hanna2 ]]; then
    /usr/bin/printf 'refusing to configure any host except hanna2\n' >&2
    exit 78
fi

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
RUNNER=waingro-runner
FORBIDDEN=(docker.service containerd.service podman.service kubelet.service ollama.service tailscaled.service)

for command in virsh qemu-img xorriso ssh-keygen nft firewall-cmd; do
    if ! command -v "${command}" >/dev/null; then
        /usr/bin/printf 'missing required command: %s\n' "${command}" >&2
        exit 69
    fi
done

if [[ $(/usr/sbin/getenforce) != Enforcing ]]; then
    /usr/bin/printf 'SELinux must be enforcing\n' >&2
    exit 77
fi

foreign_domains=$(/usr/bin/virsh -c qemu:///system list --all --name | /usr/bin/sed '/^$/d')
if [[ -n ${foreign_domains} ]]; then
    /usr/bin/printf 'remove all defined libvirt domains before provisioning:\n%s\n' \
        "${foreign_domains}" >&2
    exit 77
fi

foreign_networks=$(/usr/bin/virsh -c qemu:///system net-list --name \
    | /usr/bin/sed '/^$/d' \
    | /usr/bin/grep -v '^default$' || true)
if [[ -n ${foreign_networks} ]]; then
    /usr/bin/printf 'remove all non-default active libvirt networks before provisioning:\n%s\n' \
        "${foreign_networks}" >&2
    exit 77
fi

for service in "${FORBIDDEN[@]}"; do
    if /usr/bin/systemctl is-active --quiet "${service}"; then
        /usr/bin/printf 'forbidden service is active: %s\n' "${service}" >&2
        exit 77
    fi
done

/usr/bin/systemctl is-active --quiet firewalld.service
if [[ $(/usr/bin/firewall-cmd --get-default-zone) != drop ]]; then
    /usr/bin/printf 'firewalld default zone must already be drop\n' >&2
    exit 77
fi

if ! /usr/bin/id "${RUNNER}" >/dev/null 2>&1; then
    /usr/sbin/useradd --system --create-home --home-dir /var/lib/waingro-runner \
        --shell /usr/sbin/nologin "${RUNNER}"
fi
for group in kvm libvirt; do
    if /usr/bin/getent group "${group}" >/dev/null; then
        /usr/sbin/usermod -a -G "${group}" "${RUNNER}"
    fi
done
if /usr/bin/id -nG "${RUNNER}" | /usr/bin/grep -Eq '(^| )(wheel|sudo|docker|podman|lxd|incus)( |$)'; then
    /usr/bin/printf 'runner belongs to a forbidden administrative group\n' >&2
    exit 77
fi

/usr/bin/install -d -o root -g root -m 0700 /etc/waingro
/usr/bin/install -o root -g root -m 0600 \
    "${SOURCE_DIR}/host-policy.fixture.json" /etc/waingro/host-policy.json
/usr/bin/install -o root -g root -m 0600 \
    "${SOURCE_DIR}/egress-lockdown.nft" /etc/waingro/egress-lockdown.nft
/usr/bin/install -o root -g root -m 0755 \
    "${SOURCE_DIR}/waingro-egress-lockdown" /usr/local/libexec/waingro-egress-lockdown
/usr/bin/install -o root -g root -m 0644 \
    "${SOURCE_DIR}/waingro-egress-lockdown.service" \
    /etc/systemd/system/waingro-egress-lockdown.service

/usr/bin/install -d -o "${RUNNER}" -g "${RUNNER}" -m 0711 /var/lib/waingro
/usr/bin/install -d -o "${RUNNER}" -g "${RUNNER}" -m 0711 /var/lib/waingro/jobs
/usr/bin/install -d -o "${RUNNER}" -g "${RUNNER}" -m 0700 \
    /var/lib/waingro/evidence /var/lib/waingro-runner/.config
/usr/bin/chmod 0700 /var/lib/waingro-runner

if [[ ! -f /var/lib/waingro-runner/.config/runtime-signing-key ]]; then
    /usr/sbin/runuser -u "${RUNNER}" -- /usr/bin/ssh-keygen -q -t ed25519 -N '' \
        -C hanna2-waingro-runtime-v1 \
        -f /var/lib/waingro-runner/.config/runtime-signing-key
fi
/usr/bin/chmod 0600 /var/lib/waingro-runner/.config/runtime-signing-key
/usr/bin/chmod 0644 /var/lib/waingro-runner/.config/runtime-signing-key.pub

if /usr/bin/virsh -c qemu:///system net-info default >/dev/null 2>&1; then
    /usr/bin/virsh -c qemu:///system net-destroy default >/dev/null 2>&1 || true
    /usr/bin/virsh -c qemu:///system net-autostart default --disable
fi

/usr/sbin/restorecon -RF /etc/waingro /var/lib/waingro /var/lib/waingro-runner \
    /usr/local/libexec/waingro-egress-lockdown /etc/systemd/system/waingro-egress-lockdown.service
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable --now waingro-egress-lockdown.service
/usr/local/libexec/waingro-egress-lockdown status

/usr/bin/printf 'fixture-only host policy installed; corpus execution remains disabled\n'
/usr/bin/printf 'host_policy_sha256='
/usr/bin/sha256sum /etc/waingro/host-policy.json | /usr/bin/cut -d ' ' -f 1
/usr/bin/printf 'allowed_signer='
/usr/bin/cat /var/lib/waingro-runner/.config/runtime-signing-key.pub
