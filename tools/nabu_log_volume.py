"""Portable FAT allocation proof and NABULOG2 contract shared by host tools.

The allocation token is a non-secret identity, not an authentication key.
CRC32 detects corruption, not malicious forgery.
"""
import hashlib
import struct
import zlib

BLOCK = 4096
CAPACITY = 4 * 1024 * 1024
SLOT_BYTES = BLOCK + CAPACITY
FILE_BYTES = BLOCK + 2 * SLOT_BYTES
NAME = b'XNU2LOG BIN'


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def crc(data):
    return zlib.crc32(data) & 0xffffffff


def header_crc(data, offset):
    return crc(data[:offset] + b'\0' * 4 + data[offset + 4:BLOCK])


def make_config(token):
    if len(token) != 16 or not any(token):
        raise ValueError('allocation token must contain 16 nonzero-identity bytes')
    data = bytearray(BLOCK)
    struct.pack_into('<8s6I', data, 0, b'NABUCFG2', 2, BLOCK, CAPACITY, SLOT_BYTES, FILE_BYTES, 0)
    data[32:48] = token
    struct.pack_into('<I', data, 48, BLOCK)
    struct.pack_into('<I', data, 56, header_crc(data, 56))
    return bytes(data)


def check_config(data):
    if len(data) < BLOCK or data[:8] != b'NABUCFG2':
        raise ValueError('missing NABUCFG2 allocation header')
    expected = (2, BLOCK, CAPACITY, SLOT_BYTES, FILE_BYTES, 0)
    if struct.unpack_from('<6I', data, 8) != expected or u32(data, 48) != BLOCK or u32(data, 52):
        raise ValueError('unsupported NABUCFG2 geometry/version')
    if not any(data[32:48]) or any(data[60:BLOCK]) or u32(data, 56) != header_crc(data[:BLOCK], 56):
        raise ValueError('NABUCFG2 reserved fields/token/CRC invalid')
    return data[32:48]


def decode_container(data):
    if len(data) != FILE_BYTES:
        raise ValueError('NABULOG2 container must have exactly %d bytes' % FILE_BYTES)
    token = check_config(data[:BLOCK])
    slots, valid = [], []
    for index in range(2):
        start = BLOCK + index * SLOT_BYTES
        header = data[start:start + BLOCK]
        entry = {'slot': index, 'valid': False}
        try:
            if header[:8] != b'NABULOG2' or struct.unpack_from('<4I', header, 8) != (2, BLOCK, 1, CAPACITY):
                raise ValueError('missing/unsupported committed slot header')
            if u32(header, 80) != header_crc(header, 80):
                raise ValueError('slot header CRC mismatch')
            if header[96:112] != token or any(header[144:]) or u32(header, 84):
                raise ValueError('slot token/reserved fields invalid')
            sequence, total, lost, first = u64(header, 24), u64(header, 48), u64(header, 56), u64(header, 64)
            length = u32(header, 72)
            if not sequence or length != min(total, CAPACITY) or first > total or total - first != length or u64(header, 88) != first:
                raise ValueError('slot length/ring counters invalid')
            payload = data[start + BLOCK:start + BLOCK + length]
            if crc(payload) != u32(header, 76):
                raise ValueError('slot payload CRC mismatch')
            entry.update(valid=True, sequence=sequence, boot_id=header[32:48].hex(),
                         committed_total=total, lost_on_contention=lost, ring_overwritten=first,
                         payload_bytes=length, build_id=header[112:144].hex())
            valid.append((entry, payload))
        except ValueError as error:
            entry['error'] = str(error)
        slots.append(entry)
    if not valid:
        raise ValueError('no complete CRC-valid NABULOG2 slot: ' + str(slots))
    valid.sort(key=lambda item: item[0]['sequence'])
    if len(valid) == 2 and valid[0][0]['sequence'] == valid[1][0]['sequence']:
        raise ValueError('ambiguous duplicate slot sequences')
    selected, payload = valid[-1]
    lost = selected['lost_on_contention'] + selected['ring_overwritten']
    info = dict(selected, format='NABULOG2', version=2, allocation_token=token.hex(),
                slots=slots, selected_slot=selected['slot'], stored_checksum='crc32_header_and_payload',
                stored_checksum_valid=True, config_checksum_valid=True,
                structural_validation='passed', ring_capacity=CAPACITY,
                ring_order='already_linearised', lost_bytes_exact=lost,
                captured_bytes_lower_bound=selected['committed_total'],
                lost_bytes_lower_bound=lost, capture_complete_through_snapshot=lost == 0,
                complete_boot_log=False, freshness='boot_id_present_requires_run_binding',
                snapshot_consistency='CRC_verified_committed_snapshot',
                payload_sha256=hashlib.sha256(payload).hexdigest(),
                warnings=['Bytes after the last completed commit may be missing.',
                          'Only bytes reaching the installed console producers are captured.'])
    info['nul_bytes'] = payload.count(b'\0')
    try:
        payload.decode('utf-8', 'strict')
        info['utf8_valid'] = True
    except UnicodeDecodeError:
        info['utf8_valid'] = False
        info['warnings'].append('Invalid UTF-8 is escaped in TXT; original bytes remain in BIN.')
    return payload, info


class FatVolume:
    """Bounded read-only parser for the same 4K FAT32 geometry as the kernel."""
    def __init__(self, read_blocks, blocks):
        self.read_blocks = read_blocks
        self.blocks = blocks
        boot = self.read(0, 1)
        bps, spc, reserved, fats = struct.unpack_from('<HBHB', boot, 11)
        self.fat_blocks = u32(boot, 36)
        self.root = u32(boot, 44)
        self.fat_first = reserved
        self.data_first = reserved + 2 * self.fat_blocks
        if (bps != BLOCK or spc != 1 or fats != 2 or not reserved or
                not 1 <= self.fat_blocks <= 256 or u32(boot, 32) != blocks or
                self.data_first >= blocks or any(boot[40:44]) or
                any(boot[17:21]) or any(boot[22:24]) or boot[510:512] != b'\x55\xaa' or
                boot[82:87] != b'FAT32'):
            raise ValueError('unsupported or malformed 4K FAT32 ESP')
        self.clusters = blocks - self.data_first
        self.fat = self.read(reserved, self.fat_blocks)
        if not 65525 <= self.clusters or (self.clusters + 2) * 4 > len(self.fat):
            raise ValueError('invalid FAT32 cluster count/FAT capacity')
        if self.read(reserved + self.fat_blocks, self.fat_blocks) != self.fat:
            raise ValueError('FAT mirrors disagree')
        self.boot = boot

    def read(self, first, blocks):
        if first < 0 or blocks <= 0 or first >= self.blocks or blocks > self.blocks - first:
            raise ValueError('ESP read outside partition')
        data = self.read_blocks(first, blocks)
        if len(data) != blocks * BLOCK:
            raise ValueError('short ESP read')
        return data

    def next(self, cluster):
        if not 2 <= cluster < self.clusters + 2:
            raise ValueError('FAT cluster out of range')
        return u32(self.fat, cluster * 4) & 0x0fffffff

    def chain(self, first):
        seen, result = set(), []
        while first < 0x0ffffff8:
            if first in seen or len(result) > self.clusters:
                raise ValueError('cyclic FAT chain')
            seen.add(first)
            result.append(first)
            first = self.next(first)
        return result

    def directory(self, first):
        for cluster in self.chain(first):
            block = self.read(self.data_first + cluster - 2, 1)
            for at in range(0, BLOCK, 32):
                entry = block[at:at + 32]
                if entry[0] == 0:
                    return
                if entry[0] == 0xe5 or entry[11] == 15 or entry[11] & 8 or entry[0] == ord('.'):
                    continue
                start = (struct.unpack_from('<H', entry, 20)[0] << 16) | struct.unpack_from('<H', entry, 26)[0]
                yield entry[:11], entry[11], start, u32(entry, 28), (self.data_first + cluster - 2) * BLOCK + at

    def ownership(self):
        """Prove existing file/directory chains do not overlap before allocating."""
        owners, pending, directories = {}, [(self.root, '/')], set()
        while pending:
            first, label = pending.pop()
            if first in directories or len(directories) >= 1024:
                raise ValueError('cyclic/excessive directory graph')
            directories.add(first)
            for cluster in self.chain(first):
                if cluster in owners:
                    raise ValueError('cross-linked FAT directory')
                owners[cluster] = label
            for name, attr, start, size, _ in self.directory(first):
                if attr & 16:
                    pending.append((start, label + name.decode('ascii', 'replace') + '/'))
                elif start:
                    chain = self.chain(start)
                    if len(chain) * BLOCK < size:
                        raise ValueError('file chain shorter than directory length')
                    for cluster in chain:
                        if cluster in owners:
                            raise ValueError('cross-linked FAT file')
                        owners[cluster] = label + name.decode('ascii', 'replace')
                elif size:
                    raise ValueError('nonempty FAT file has no allocation')
        return owners

    def log_extent(self):
        entries = [entry for entry in self.directory(self.root) if entry[0] == NAME]
        if len(entries) != 1:
            raise ValueError('expected exactly one root XNU2LOG.BIN')
        _, attr, first, size, _ = entries[0]
        if attr != 0x20 or size != FILE_BYTES:
            raise ValueError('log file attribute/length mismatch')
        chain = self.chain(first)
        if chain != list(range(first, first + FILE_BYTES // BLOCK)):
            raise ValueError('log file is not an exact contiguous allocation')
        start = self.data_first + first - 2
        config = self.read(start, 1)
        token = check_config(config)
        return start, FILE_BYTES // BLOCK, token
