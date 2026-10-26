#!/usr/bin/env python3
"""Prepare an OFFLINE ESP copy, or pull its allocated log file read-only via adb.

Never flashes, mounts, reboots, changes GPT, or writes a device block. `prepare`
accepts regular image files only. `pull --root` uses an existing su grant for reads.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import struct
import subprocess
import sys

try:
    from . import nabu_log_export as legacy
    from . import nabu_log_volume as volume
except ImportError:
    import nabu_log_export as legacy
    import nabu_log_volume as volume


def fat_image(data):
    if len(data) % volume.BLOCK:
        raise ValueError('ESP image length is not 4K aligned')
    return volume.FatVolume(lambda first, blocks: bytes(data[first * 4096:(first + blocks) * 4096]), len(data) // 4096)


def prepare(data, token=None):
    """Return a new image and proof; source data is never mutated."""
    fat = fat_image(data)
    owners = fat.ownership()
    old_entries = list(fat.directory(fat.root))
    if any(entry[0] == volume.NAME for entry in old_entries):
        start, count, token = fat.log_extent()
        return bytes(data), {'reused_existing_log': True, 'allocation_token': token.hex(),
                             'file_relative_block': start, 'file_blocks': count,
                             'device_writes': False, 'raw_device_write_authorized': False}
    token = secrets.token_bytes(16) if token is None else token
    needed = volume.FILE_BYTES // 4096
    run, first = 0, None
    for cluster in range(2, fat.clusters + 2):
        if fat.next(cluster) == 0 and cluster not in owners:
            run += 1
            if run == needed:
                first = cluster - run + 1
                break
        else:
            run = 0
    if first is None:
        raise ValueError('no contiguous free ESP allocation for the log; never resize a partition')
    # Use an existing free root slot; do not grow/rearrange any directory.
    slot = None
    for cluster in fat.chain(fat.root):
        base = (fat.data_first + cluster - 2) * 4096
        for offset in range(0, 4096 - 32, 32):
            if data[base + offset] == 0:
                slot = base + offset
                break
        if slot is not None:
            break
    if slot is None:
        raise ValueError('ESP root directory has no free entry')
    result = bytearray(data)
    for index in range(2):
        start = (fat.fat_first + index * fat.fat_blocks) * 4096
        for i in range(needed):
            struct.pack_into('<I', result, start + (first + i) * 4,
                             first + i + 1 if i + 1 < needed else 0x0fffffff)
    entry = bytearray(32)
    entry[:11] = volume.NAME
    entry[11] = 0x20
    struct.pack_into('<H', entry, 20, first >> 16)
    struct.pack_into('<H', entry, 26, first & 0xffff)
    struct.pack_into('<I', entry, 28, volume.FILE_BYTES)
    result[slot:slot + 32] = entry
    result[slot + 32:slot + 64] = bytes(32)  # retain an end marker; tail was not live
    file_block = fat.data_first + first - 2
    file_offset = file_block * 4096
    result[file_offset:file_offset + volume.FILE_BYTES] = volume.make_config(token) + bytes(2 * volume.SLOT_BYTES)
    # Maintain valid FSInfo counters in both existing copies. No boot/GPT changes.
    info_sector, backup_sector = struct.unpack_from('<HH', data, 48)
    free_after = sum(fat.next(c) == 0 for c in range(2, fat.clusters + 2)) - needed
    next_free = next((c for c in range(2, fat.clusters + 2)
                      if not first <= c < first + needed and fat.next(c) == 0), 0xffffffff)
    for sector in (info_sector, backup_sector + info_sector):
        if not 0 < sector < fat.fat_first:
            raise ValueError('invalid FAT32 FSInfo/backup location')
        offset = sector * 4096
        if (volume.u32(data, offset) != 0x41615252 or volume.u32(data, offset + 484) != 0x61417272 or
                volume.u32(data, offset + 508) != 0xaa550000):
            raise ValueError('FSInfo signature invalid; refuse to repair implicitly')
        struct.pack_into('<II', result, offset + 488, free_after, next_free)
    verified = fat_image(result)
    verified.ownership()
    for cluster in range(2, verified.clusters + 2):
        target = verified.next(cluster)
        if first <= target < first + needed and not (first <= cluster < first + needed - 1 and target == cluster + 1):
            raise ValueError('foreign FAT reference enters log allocation')
    actual = verified.log_extent()
    if actual != (file_block, needed, token):
        raise ValueError('allocated log extent failed independent reparse')
    # Every byte change must be inside the free allocation or explicit metadata.
    allowed = [(file_offset, file_offset + volume.FILE_BYTES), (slot, slot + 64)]
    allowed += [((fat.fat_first + i * fat.fat_blocks) * 4096 + first * 4,
                 (fat.fat_first + i * fat.fat_blocks) * 4096 + (first + needed) * 4) for i in range(2)]
    allowed += [(s * 4096 + 488, s * 4096 + 496) for s in (info_sector, backup_sector + info_sector)]
    cursor = 0
    for start, end in sorted(allowed):
        if result[cursor:start] != data[cursor:start]:
            raise ValueError('unexpected modification outside the allocation proof')
        cursor = end
    if result[cursor:] != data[cursor:]:
        raise ValueError('unexpected modification after the allocation')
    return bytes(result), {
        'reused_existing_log': False, 'allocation_token': token.hex(),
        'file_relative_block': file_block, 'file_blocks': needed, 'file_cluster': first,
        'file_bytes': volume.FILE_BYTES, 'root_entry_offset': slot,
        'changed_byte_ranges': allowed, 'existing_owned_clusters': len(owners),
        'device_writes': False, 'raw_device_write_authorized': False,
    }


class AdbEsp:
    def __init__(self, adb, serial, root=False):
        if not re.fullmatch(r'[A-Za-z0-9_.:-]+', serial) or serial.startswith('-'):
            raise ValueError('invalid serial')
        self.prefix = [adb, '-s', serial]
        self.root = root
        self.device = None

    def command(self, command):
        return 'su -c ' + shlex.quote(command) if self.root else command

    def shell(self, command):
        result = subprocess.run(self.prefix + ['shell', self.command(command)], capture_output=True, timeout=20)
        if result.returncode:
            raise ValueError('read-only adb query failed: ' + command)
        return result.stdout.decode('utf-8', 'strict').strip()

    def inspect(self):
        if self.root:
            result = subprocess.run(self.prefix + ['shell', 'id -u'], capture_output=True, timeout=20)
            if result.returncode == 0 and result.stdout.strip() == b'0':
                self.root = False  # Recovery adbd is already root; it need not provide su.
        if self.shell('getprop ro.product.device') != 'nabu':
            raise ValueError('refuse non-nabu device')
        self.device = self.shell('readlink -f /dev/block/by-name/esp')
        match = re.fullmatch(r'/dev/block/(sd[a-z]+)([1-9][0-9]*)', self.device)
        if not match:
            raise ValueError('ESP is not a UFS partition path')
        parent, number = match.groups()
        values = self.shell('cat /sys/class/block/%s%s/start /sys/class/block/%s%s/size '
                            '/sys/class/block/%s/queue/logical_block_size' %
                            (parent, number, parent, number, parent)).split()
        if len(values) != 3 or not all(re.fullmatch(r'[0-9]+', s) for s in values):
            raise ValueError('invalid ESP geometry response')
        start, size, logical = map(int, values)
        byte_text = self.shell('blockdev --getsize64 ' + self.device)
        if not re.fullmatch(r'[0-9]+', byte_text):
            raise ValueError('invalid blockdev size')
        byte_size = int(byte_text)
        if logical != 4096 or start % 8 or byte_size != size * 512 or byte_size % 4096 or byte_size > 1024**3:
            raise ValueError('ESP size/alignment contract refused')
        for line in self.shell('cat /proc/mounts').splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[2] in ('vfat', 'msdos') and 'rw' in fields[3].split(','):
                source = fields[0]
                if not re.fullmatch(r'/dev/block/[A-Za-z0-9_./:-]+', source):
                    raise ValueError('cannot identify writable FAT mount source safely')
                resolved = self.shell('readlink -f ' + source)
                if resolved == self.device:
                    raise ValueError('ESP is mounted writable; do not race a filesystem writer')
        return {'device': self.device, 'partition_start_bytes': start * 512,
                'partition_bytes': byte_size, 'logical_block_bytes': logical,
                'existing_root_read_interface': self.root, 'device_writes': False}

    def read(self, first, blocks):
        if self.device is None or first < 0 or blocks <= 0 or blocks > 4096:
            raise ValueError('invalid bounded ESP read')
        command = 'dd if=%s bs=4096 skip=%d count=%d 2>/dev/null' % (self.device, first, blocks)
        result = subprocess.run(self.prefix + ['exec-out', self.command(command)], capture_output=True, timeout=60)
        if result.returncode or len(result.stdout) != blocks * 4096:
            error = ValueError('adb/dd ESP read failed or was short')
            error.partial = result.stdout
            raise error
        return result.stdout


def discover_serial(adb):
    result = subprocess.run([adb, 'devices', '-l'], capture_output=True, timeout=20, check=True)
    online = []
    for line in result.stdout.decode('utf-8', 'strict').splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] in ('device', 'recovery'):
            online.append(fields)
    nabu = [row for row in online if 'device:nabu' in row or 'product:nabu' in row]
    choices = nabu if nabu else online
    if len(choices) != 1:
        raise ValueError('no unique online nabu; specify --serial')
    return choices[0][0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare', help='new regular ESP image only; no device access')
    prep.add_argument('input', type=Path)
    prep.add_argument('--out', type=Path, required=True, help='new output directory')
    for name in ('decode-esp', 'pull'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--out', type=Path, required=name != 'pull', help='new output directory; pull defaults to a private timestamped run')
        if name == 'decode-esp':
            cmd.add_argument('input', type=Path)
        else:
            cmd.add_argument('--serial', help='auto-detect one online nabu by default')
            cmd.add_argument('--adb', default='adb')
            cmd.add_argument('--root', action='store_true', help='use an existing su grant for read-only queries')
    args = parser.parse_args(argv)
    if args.out is None:
        label = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%SZ-') + secrets.token_hex(2)
        args.out = Path(__file__).resolve().parents[1] / 'device_bringup/out' / ('nabu-log-' + label)
    out, created = args.out.resolve(), False
    info = {'tool': 'nabu_esp_log.py', 'device_writes': False,
            'captured_at_utc': datetime.now(timezone.utc).isoformat(), 'hardware_validation': 'not_claimed'}
    try:
        out.mkdir(parents=True, exist_ok=False)
        created = True
        if args.action in ('prepare', 'decode-esp'):
            source = args.input.resolve(strict=True)
            if not source.is_file() or not 0 < source.stat().st_size <= 1024**3:
                raise ValueError('input must be a regular ESP image <=1 GiB')
            data = source.read_bytes()
            info.update(input=str(source), input_sha256=hashlib.sha256(data).hexdigest())
            if args.action == 'prepare':
                result, proof = prepare(data)
                (out / 'esp-with-log.img').write_bytes(result)
                proof.update(info, output_sha256=hashlib.sha256(result).hexdigest(),
                             boot_args='nabu-log=1 nabu-log-token=' + proof['allocation_token'])
                legacy.write_json(out / 'allocation-proof.json', proof)
                print(json.dumps({'out': str(out), 'prepared': True, 'device_writes': False}))
                return 0
            fat = fat_image(data)
        else:
            adb = AdbEsp(args.adb, args.serial or discover_serial(args.adb), args.root)
            info['acquisition'] = adb.inspect()
            fat = volume.FatVolume(adb.read, info['acquisition']['partition_bytes'] // 4096)
        start, count, token = fat.log_extent()
        info['file_extent'] = {'partition_relative_block': start, 'blocks': count, 'token': token.hex()}
        raw = fat.read(start, count)
        code = legacy.export(raw, out, info, volume.CAPACITY, require_checksum=True)
        print(json.dumps({'out': str(out), 'result': info['result'], 'error': info.get('error')}, ensure_ascii=True))
        return code
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        if created:
            partial = getattr(error, 'partial', None) or getattr(error, 'stdout', None)
            if partial is not None:
                (out / 'failed-read.bin').write_bytes(partial)
            if not (out / 'boot-log-info.json').exists():
                legacy.write_json(out / 'boot-log-info.json', dict(info, result='rejected', error=str(error)))
        print(json.dumps({'result': 'rejected', 'error': str(error)}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
