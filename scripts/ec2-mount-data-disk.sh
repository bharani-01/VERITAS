#!/usr/bin/env bash
# WIPE nvme1n1 + nvme2n1 and create one ~200G LVM volume at /data for VERITAS.
# Does NOT touch the root disk (nvme0n1).
set -euo pipefail

DISK1="${DISK1:-/dev/nvme1n1}"
DISK2="${DISK2:-/dev/nvme2n1}"
MOUNT_POINT="${MOUNT_POINT:-/data}"
SCAN_ROOT="${SCAN_ROOT:-$MOUNT_POINT/veritas-scans}"
ENV_FILE="${ENV_FILE:-/opt/veritas/backend/.env}"
VG_NAME="veritas_vg"
LV_NAME="data"

echo "=== BEFORE (will WIPE $DISK1 and $DISK2) ==="
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
df -h / || true

for d in "$DISK1" "$DISK2"; do
  if [[ ! -b "$d" ]]; then
    echo "Missing block device: $d" >&2
    exit 1
  fi
done

# Turn off swap on these volumes
swapoff -a || true
# Unmount anything on these disks
for mnt in "$MOUNT_POINT" /mnt/swapvol /mnt/_p1 /mnt/_p2; do
  umount -f "$mnt" 2>/dev/null || true
done
# Detach any lingering mounts by device
umount -f "$DISK1" 2>/dev/null || true
umount -f "$DISK2" 2>/dev/null || true

# Drop old LVM if present from a previous attempt
lvremove -fy "/dev/$VG_NAME/$LV_NAME" 2>/dev/null || true
vgremove -fy "$VG_NAME" 2>/dev/null || true
pvremove -fy "$DISK1" 2>/dev/null || true
pvremove -fy "$DISK2" 2>/dev/null || true

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq lvm2

echo "Wiping filesystem signatures…"
wipefs -a "$DISK1" "$DISK2"

echo "Creating LVM spanning both disks…"
pvcreate -ff -y "$DISK1" "$DISK2"
vgcreate "$VG_NAME" "$DISK1" "$DISK2"
lvcreate -y -l 100%FREE -n "$LV_NAME" "$VG_NAME"
mkfs.ext4 -F -L veritas-data "/dev/$VG_NAME/$LV_NAME"

mkdir -p "$MOUNT_POINT"

# Clean stale fstab entries for /data, swapvol, these UUIDs, and old swapfile
TMP_FSTAB="$(mktemp)"
grep -vE "[[:space:]]/data[[:space:]]|[[:space:]]/mnt/swapvol[[:space:]]|swapfile|/dev/$VG_NAME/" /etc/fstab > "$TMP_FSTAB" || true
mv "$TMP_FSTAB" /etc/fstab

UUID="$(blkid -s UUID -o value "/dev/$VG_NAME/$LV_NAME")"
echo "UUID=$UUID  $MOUNT_POINT  ext4  defaults,nofail  0  2" >> /etc/fstab
mount "$MOUNT_POINT"

mkdir -p "$SCAN_ROOT"
chown -R ubuntu:ubuntu "$MOUNT_POINT"
chmod 750 "$MOUNT_POINT" "$SCAN_ROOT"

if [[ -f "$ENV_FILE" ]]; then
  if grep -q '^VERITAS_SCAN_ROOT=' "$ENV_FILE"; then
    sed -i "s|^VERITAS_SCAN_ROOT=.*|VERITAS_SCAN_ROOT=$SCAN_ROOT|" "$ENV_FILE"
  else
    echo "VERITAS_SCAN_ROOT=$SCAN_ROOT" >> "$ENV_FILE"
  fi
fi

echo "=== AFTER ==="
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
df -h / "$MOUNT_POINT"
grep VERITAS_SCAN_ROOT "$ENV_FILE" || true
echo "DONE — ~200G at $MOUNT_POINT → $SCAN_ROOT"
