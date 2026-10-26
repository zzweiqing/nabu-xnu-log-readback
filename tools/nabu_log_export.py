#!/usr/bin/env python3
"""Read-only Recovery acquisition and strict legacy UniXNU log decoding.

No flashing, rebooting, mounting, partition writes, or device-side temporary files.
NABULOG1/SWEETLOG have NO stored checksum or boot identity: structural validity
does not prove a complete, coherent, fresh kernel snapshot. See docs/NABU-LOGGING.zh-CN.md.
Python 3.9+, standard library only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone
import zlib

BLOCK = 4096
RING = 4 * 1024 * 1024
MAX_INPUT = 64 * 1024 * 1024
LAYOUTS = {
    'nabu-v1-tail32m': (32 * 1024 * 1024, b'NABULOG1'),
    'sweet-v1-tail4m': (BLOCK + RING, b'SWEETLOG'),
}


class LogError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode_log(data, ring_capacity=RING):
    """Return chronological payload and metadata, or refuse unknown/invalid data.

    NABULOG1's payload is ALREADY linearised by the writer. Its `total` counter
    saturates at capacity; dropped is a wrapping u32. SWEETLOG stores physical
    ring order, a monotonic u64 total, and a flush sequence. Do not mix formats.
    """
    if data[:8] == b'NABUCFG2':
        try:
            try:
                from .nabu_log_volume import decode_container
            except ImportError:
                from nabu_log_volume import decode_container
            return decode_container(data)
        except ValueError as error:
            raise LogError(str(error)) from error
    if len(data) < BLOCK:
        raise LogError('truncated 4096-byte header block')
    magic = data[:8]
    if magic not in (b'NABULOG1', b'SWEETLOG'):
        raise LogError('unsupported magic; expected NABULOG1 or SWEETLOG at offset 0')
    version = struct.unpack_from('<I', data, 8)[0]
    if version != 1:
        raise LogError('unsupported version: %d' % version)
    if any(data[32:BLOCK]):
        raise LogError('nonzero reserved header bytes; corrupt or unsupported writer format')
    info = {
        'format': magic.decode('ascii'), 'version': version,
        'header_block_bytes': BLOCK, 'stored_checksum': 'not_present',
        'stored_checksum_valid': None, 'snapshot_consistency': 'unverifiable',
        'boot_id': None, 'freshness': 'unverifiable', 'complete_boot_log': False,
        'warnings': [
            'Legacy format has no header/payload checksum or commit marker.',
            'Boot identity, snapshot coherence, and final unflushed bytes are unknown.',
        ],
    }
    if magic == b'NABULOG1':
        if ring_capacity not in (65536, RING):
            raise LogError('NABULOG1 capacity must match audited writer: 65536 or 4194304')
        flags, length, dropped, total = struct.unpack_from('<IIIQ', data, 12)
        if flags & ~1:
            raise LogError('unknown NABULOG1 flags')
        if total > ring_capacity or length > total:
            raise LogError('NABULOG1 length/total exceeds audited saturated-counter geometry')
        if dropped and total != ring_capacity:
            raise LogError('NABULOG1 dropped bytes with a ring that was not full')
        if len(data) < BLOCK + ((length + BLOCK - 1) // BLOCK) * BLOCK:
            raise LogError('truncated or unpadded NABULOG1 payload')
        payload = data[BLOCK:BLOCK + length]
        info.update({
            'flags': flags, 'panic_flag': bool(flags & 1), 'payload_bytes': length,
            'ring_capacity': ring_capacity, 'ring_order': 'already_linearised',
            'header_total': total, 'total_semantics': 'resident_count_saturating_at_capacity',
            'reported_dropped_u32': dropped, 'wrapped_detected': dropped > 0,
            'tail_snapshot': length < total, 'sequence': None,
            'captured_bytes_lower_bound': total + dropped,
            'lost_bytes_lower_bound': dropped + total - length,
            'lost_bytes_exact': None,
        })
        info['warnings'].append('dropped is u32; wraparound and concurrent append loss are not measurable.')
        info['warnings'].append('Writer commits header before payload; a valid header can name stale/partial data.')
    else:
        size, total, seq = struct.unpack_from('<IQQ', data, 12)
        if size != RING:
            raise LogError('unsupported SWEETLOG ring size; audited legacy writer uses 4194304')
        if seq == 0:
            raise LogError('SWEETLOG flush sequence must be nonzero')
        if len(data) < BLOCK + size:
            raise LogError('truncated SWEETLOG ring')
        ring = data[BLOCK:BLOCK + size]
        length = min(total, size)
        start = total % size if total > size else 0
        payload = (ring[start:] + ring[:start])[:length]
        info.update({
            'payload_bytes': length, 'ring_capacity': size, 'ring_order': 'physical_ring',
            'header_total': total, 'total_semantics': 'monotonic_u64_reserved_byte_count',
            'wrapped_detected': total > size, 'sequence': seq,
            'captured_bytes_lower_bound': total,
            'lost_bytes_lower_bound': max(0, total - size), 'lost_bytes_exact': None,
        })
        info['warnings'].append('Atomic reservation precedes byte stores; the writer can snapshot unfinished appends.')
    info['structural_validation'] = 'passed'
    info['payload_sha256'] = digest(payload)
    info['payload_crc32_host'] = '%08x' % (zlib.crc32(payload) & 0xffffffff)
    # This is diagnostic only: do not strip NULs or guess text encodings.
    try:
        payload.decode('utf-8', 'strict')
        info['utf8_valid'] = True
    except UnicodeDecodeError:
        info['utf8_valid'] = False
        info['warnings'].append('Invalid UTF-8 is displayed using backslash escapes; binary retains original bytes.')
    info['nul_bytes'] = payload.count(b'\0')
    if info['nul_bytes']:
        info['warnings'].append('NUL bytes present: possible incomplete snapshot or binary console content.')
    return payload, info


def window_geometry(partition_bytes, start_512, size_512, logical_block, layout):
    """Partition-relative dd offset; Linux sysfs start/size always use 512 bytes."""
    if layout not in LAYOUTS:
        raise LogError('unsupported layout')
    count_bytes = LAYOUTS[layout][0]
    if logical_block != BLOCK:
        raise LogError('expected audited nabu UFS logical block size 4096')
    if start_512 < 0 or size_512 <= 0 or partition_bytes != size_512 * 512:
        raise LogError('blockdev and sysfs partition size disagree')
    if start_512 % 8 or partition_bytes % BLOCK or partition_bytes <= count_bytes:
        raise LogError('invalid partition alignment or insufficient capacity')
    offset = partition_bytes - count_bytes
    return {
        'partition_bytes': partition_bytes, 'partition_start_bytes': start_512 * 512,
        'logical_block_bytes': logical_block, 'sysfs_sector_unit_bytes': 512,
        'layout': layout, 'read_bytes': count_bytes,
        'partition_relative_offset_bytes': offset, 'dd_bs': BLOCK,
        'dd_skip': offset // BLOCK, 'dd_count': count_bytes // BLOCK,
        'absolute_lun_offset_bytes': start_512 * 512 + offset,
        'reservation_proven': False,
        'scope': 'read location only; not authorization or proof that this region is safe to write',
    }


class RecoveryReader:
    def __init__(self, adb, serial):
        if not re.fullmatch(r'[A-Za-z0-9_.:-]+', serial) or serial.startswith('-'):
            raise LogError('invalid adb serial')
        self.prefix = [adb, '-s', serial]
        self.serial = serial

    def run(self, args, timeout=20):
        return subprocess.run(self.prefix + args, capture_output=True, timeout=timeout, check=False)

    def shell(self, command):
        result = self.run(['shell', command])
        if result.returncode:
            raise LogError('Recovery read command failed: ' + command)
        return result.stdout.decode('utf-8', 'strict').strip()

    def inspect(self, layout):
        product = self.shell('getprop ro.product.device')
        if product != 'nabu':
            raise LogError('refusing device other than nabu')
        mode = self.shell('getprop ro.bootmode')
        twrp = self.shell('getprop ro.twrp.version')
        if mode != 'recovery' and not twrp:
            raise LogError('Recovery/TWRP not identified; no automatic reboot is performed')
        mounts = self.shell('cat /proc/mounts')
        if any(len(line.split()) > 1 and line.split()[1] == '/data' for line in mounts.splitlines()):
            raise LogError('/data is mounted; acquire in Recovery with Data left unmounted')
        device = self.shell('readlink -f /dev/block/by-name/userdata')
        match = re.fullmatch(r'/dev/block/(sd[a-z]+)([1-9][0-9]*)', device)
        if not match:
            raise LogError('userdata does not resolve to an audited UFS partition path')
        parent, number = match.groups()
        name = parent + number
        values = self.shell('cat /sys/class/block/%s/start /sys/class/block/%s/size '
                            '/sys/class/block/%s/queue/logical_block_size' % (name, name, parent)).split()
        byte_text = self.shell('blockdev --getsize64 ' + device)
        if len(values) != 3 or not all(re.fullmatch(r'[0-9]+', x) for x in values + [byte_text]):
            raise LogError('invalid Recovery geometry response')
        start, size, logical = map(int, values)
        plan = window_geometry(int(byte_text), start, size, logical, layout)
        plan.update({'serial': self.serial, 'product': product, 'bootmode': mode,
                     'twrp_version': twrp, 'device': device, 'device_writes': False})
        return plan

    @staticmethod
    def command(plan):
        # All substitutions are validated device names or computed positive integers.
        # Some Recovery adb exec services merge remote stderr into stdout.
        # Suppress dd statistics on the device; byte count + exit status detect errors.
        return 'dd if=%s bs=%d skip=%d count=%d 2>/dev/null' % (
            plan['device'], BLOCK, plan['dd_skip'], plan['dd_count'])

    def acquire(self, plan):
        # exec-out has no PTY and no PowerShell redirection, preserving binary bytes.
        return self.run(['exec-out', self.command(plan)], timeout=60)


def write_json(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def export(raw, out, info, ring_capacity, expected_sha256=None, require_checksum=False,
           acquisition_error=None, expected_magic=None):
    """Always retain acquired bytes, including invalid/partial captures, without TXT on refusal."""
    (out / 'boot-log.bin').write_bytes(raw)  # out is an exclusively-created directory
    info.update({'raw_bytes': len(raw), 'raw_sha256': digest(raw),
                 'raw_crc32_host': '%08x' % (zlib.crc32(raw) & 0xffffffff),
                 'host_hash_scope': 'acquired bytes only; not an on-medium checksum',
                 'expected_sha256_match': None, 'text_exported': False})
    try:
        if acquisition_error:
            raise LogError(acquisition_error)
        if expected_sha256:
            info['expected_sha256_match'] = digest(raw) == expected_sha256.lower()
            if not info['expected_sha256_match']:
                raise LogError('raw SHA-256 does not match supplied expected digest')
        if expected_magic and raw[:8] != expected_magic:
            raise LogError('header does not match selected Recovery layout')
        payload, decoded = decode_log(raw, ring_capacity)
        info.update(decoded)
        if require_checksum and info.get('stored_checksum_valid') is not True:
            raise LogError('stored checksum required, but this legacy format has none')
        with (out / 'boot-log.txt').open('x', encoding='utf-8', newline='') as stream:
            stream.write(payload.decode('utf-8', 'backslashreplace'))
        info['text_exported'] = True
        info['result'] = ('text_exported_crc_verified' if info.get('stored_checksum_valid') is True
                          else 'legacy_text_exported_integrity_unverified')
        code = 0
    except LogError as error:
        info.update({'result': 'rejected', 'error': str(error)})
        code = 2
    write_json(out / 'boot-log-info.json', info)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    decode = sub.add_parser('decode', help='decode an existing window file; never opens a device')
    decode.add_argument('input', type=Path)
    for name in ('recovery-plan', 'recovery-export'):
        command = sub.add_parser(name, help='read-only, requires a device already in Recovery')
        command.add_argument('--adb', default='adb')
        command.add_argument('--serial', required=True)
        command.add_argument('--layout', choices=LAYOUTS, required=True)
    for command in (decode, sub.choices['recovery-export']):
        command.add_argument('--out', required=True, type=Path, help='NEW output directory; never overwritten')
        command.add_argument('--ring-capacity', type=int, choices=(65536, RING), default=RING)
        command.add_argument('--expected-sha256', help='optional independent digest of the whole input window')
        command.add_argument('--require-checksum', action='store_true', help='reject legacy formats without stored checksums')
    args = parser.parse_args(argv)
    info = {'tool': 'nabu_log_export.py', 'tool_version': 1,
            'captured_at_utc': datetime.now(timezone.utc).isoformat(),
            'device_writes': False, 'hardware_validation': 'not_claimed'}
    out = None
    created = False
    try:
        if hasattr(args, 'expected_sha256') and args.expected_sha256 and not re.fullmatch(r'[0-9a-fA-F]{64}', args.expected_sha256):
            raise LogError('expected SHA-256 must contain exactly 64 hex digits')
        if args.action == 'recovery-plan':
            plan = RecoveryReader(args.adb, args.serial).inspect(args.layout)
            print(json.dumps(plan, ensure_ascii=True, indent=2))
            return 0
        out = args.out.resolve()
        out.mkdir(parents=True, exist_ok=False)
        created = True
        error = None
        expected_magic = None
        if args.action == 'decode':
            source = args.input.resolve(strict=True)
            if not source.is_file() or source.stat().st_size > MAX_INPUT:
                raise LogError('input must be a regular window file no larger than 64 MiB')
            raw = source.read_bytes()
            info['input'] = str(source)
        else:
            reader = RecoveryReader(args.adb, args.serial)
            plan = reader.inspect(args.layout)
            info['acquisition'] = plan
            info['acquisition']['command'] = reader.command(plan)
            expected_magic = LAYOUTS[args.layout][1]
            try:
                result = reader.acquire(plan)
                raw = result.stdout
                info['acquisition']['adb_exit_code'] = result.returncode
                if result.returncode or len(raw) != plan['read_bytes']:
                    error = 'adb/dd failed or returned an incomplete window'
            except subprocess.TimeoutExpired as failure:
                raw = failure.stdout or b''
                error = 'adb read timed out; partial bytes preserved'
        code = export(raw, out, info, args.ring_capacity, args.expected_sha256,
                      args.require_checksum, error, expected_magic)
        print(json.dumps({'out': str(out), 'result': info['result'],
                          'error': info.get('error'), 'stored_checksum': info.get('stored_checksum')},
                         ensure_ascii=True))
        return code
    except (LogError, OSError, subprocess.SubprocessError, UnicodeError) as error:
        info.update({'result': 'rejected', 'error': str(error), 'text_exported': False})
        if created and not (out / 'boot-log-info.json').exists():
            write_json(out / 'boot-log-info.json', info)
        print(json.dumps({'result': 'rejected', 'error': str(error)}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
