"""Host harness for the ACTUAL NABULOG2 writer headers.

The harness compiles `mac_build/unixnu-source-ci/nabu-device/ufs/NabuLog*.h`
with only the XNU scheduling/transport primitives replaced, then runs:

* normal commit through the real `nabuLogRead`/`nabuLogIo` path,
* the runtime write gate (config block and file extent are immutable),
* a transient-contention boot where a count-only retry budget would be
  exhausted but the time-bounded retry reaches the first commit,
* the distinct stop reasons (token gate, boot-window overlap, volume gate),
* payload/sync/header interruption with the previous CRC-valid slot intact.

A compiler is required. `g++`/`clang++` is used when present; otherwise the
harness is built and run through WSL. The tests skip only when neither exists.
No device, ESP backup or allocation token from a real run is needed here.
"""
import json
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

from tools import nabu_log_volume as volume

ROOT = Path(__file__).resolve().parents[1]
UFS = ROOT / 'mac_build' / 'unixnu-source-ci' / 'nabu-device' / 'ufs'
BLOCK = volume.BLOCK
FILE_BLOCKS = volume.FILE_BYTES // BLOCK
TOKEN = bytes(range(1, 17))
ESP_FIRST = 4096
RESERVED = 32
FAT_BLOCKS = 70
DATA_FIRST = RESERVED + 2 * FAT_BLOCKS
CLUSTERS = 65525
ESP_BLOCKS = DATA_FIRST + CLUSTERS
LUN_BLOCKS = ESP_FIRST + ESP_BLOCKS + 4096
FILE_CLUSTER = 4
ESP_TYPE = bytes.fromhex('28732ac11ff8d211ba4b00a0c93ec93b')

HARNESS = r'''/* Test-only host harness for the real NABULOG2 headers.
 * Inputs: gpt.bin, esp.bin, lun blocks, token hex, output journal, mode [base].
 * No block device is opened; reads come from the two files or the overlay. */
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <array>
#include <string>
#include <vector>
#include <stdint.h>
#define NABU_LOG_IMPLEMENTATION
#include "NabuLogCore.h"
#include "NabuLogVolume.h"

struct Stop {};
struct Crash {};
extern "C" { extern volatile unsigned nabu_log_writer_rounds; }

static FILE *gptFile = nullptr, *espFile = nullptr;
static uint64_t espFirst = 0, espBlocks = 0, fileFirst = 0, nabu_log_lun_blocks = 0;
static std::map<uint64_t, std::array<uint8_t, 4096> > overlay;
static std::vector<uint8_t> base;
static std::string tokenText, g_log, g_boot_args;
static int cut_write = -1, cut_sync = -1, writes = 0, syncs = 0, locks = 0;
static long busy_left = 0;
static uint64_t g_time = 1000000;
static bool pe_flag = true, pe_token = true, windows_overlap = false;
static const unsigned kDataOffset = 8192, kDataMax = 131072;
static const unsigned kMillisecondScale = 1000;
typedef int IOReturn;
static const IOReturn kIOReturnSuccess = 0;
static const int KERN_SUCCESS = 0;
typedef void *thread_t;
typedef int wait_result_t;
static uint8_t dma[kDataOffset + kDataMax];
static struct { bool ready, poisoned; void *lock; uint8_t *virt; } gHost =
    { true, false, (void *)1, dma };

static uint64_t mach_absolute_time() { return g_time++; }
static void clock_interval_to_deadline(unsigned interval, unsigned, uint64_t *deadline) {
  /* One harness time unit is one millisecond. */
  *deadline = mach_absolute_time() + interval;
}
static bool IOLockTryLock(void *) {
  if (locks) return false;
  if (busy_left > 0) { busy_left--; return false; }
  locks++; return true;
}
static void IOLockUnlock(void *) { assert(locks == 1); locks--; }
static int current_thread() { return 1; }
static void thread_terminate(int) { throw Stop(); }
static void thread_deallocate(thread_t) {}
static int kernel_thread_start(void (*)(void *, wait_result_t), void *, thread_t *) {
  return KERN_SUCCESS;
}
static void thread_yield_internal(unsigned);
static void IOLog(const char *format, ...) {
  char buf[512]; va_list ap; va_start(ap, format);
  int n = vsnprintf(buf, sizeof(buf), format, ap); va_end(ap);
  if (n > 0) {
    unsigned len = (unsigned)n < sizeof(buf) ? (unsigned)n : (unsigned)sizeof(buf) - 1;
    g_log.append(buf, len);
    nabu_capture_append(buf, len);
  }
}
static bool PE_parse_boot_argn(const char *key, void *out, int bytes) {
  /* Numeric emulation: XNU copies an integer for every argument name that does
   * not begin with '_', including a hex-looking token.  The writer must not use
   * this API for the token; the harness fails if it does. */
  if (!strcmp(key, "nabu-log-token")) {
    if (!pe_token) return false;
    int32_t numeric = 0x1234;
    memcpy(out, &numeric, (size_t)bytes < sizeof numeric ? (size_t)bytes : sizeof numeric);
    return true;
  }
  unsigned value = 0;
  if (!strcmp(key, "nabu-log")) {
    if (!pe_flag) return false;
    value = 1;
  } else if (!strcmp(key, "native-ufs-os-lba")) {
    value = windows_overlap ? (unsigned)espFirst : 64u;
  } else if (!strcmp(key, "native-ufs-os-sectors")) {
    value = windows_overlap ? (unsigned)(espBlocks * 8) : 8u;
  } else if (!strcmp(key, "native-ufs-systemos-lba")) {
    value = 128u;
  } else if (!strcmp(key, "native-ufs-systemos-sectors")) {
    value = 8u;
  } else {
    return false;
  }
  assert(bytes == 4); memcpy(out, &value, 4); return true;
}
extern "C" char *PE_boot_args(void) {
  return const_cast<char *>(g_boot_args.c_str());
}
static bool diskRead(uint64_t lba, uint8_t *out) {
  std::map<uint64_t, std::array<uint8_t, 4096> >::iterator it = overlay.find(lba);
  if (it != overlay.end()) { memcpy(out, it->second.data(), 4096); return true; }
  if (!base.empty() && lba >= fileFirst && lba - fileFirst < (uint64_t)(NB_LOG_FILE_BYTES / 4096)) {
    memcpy(out, base.data() + (lba - fileFirst) * 4096, 4096); return true;
  }
  FILE *f = lba < 6 ? gptFile : espFile;
  if (f == espFile && (lba < espFirst || lba - espFirst >= espBlocks)) return false;
  uint64_t offset = f == gptFile ? lba * 4096 : (lba - espFirst) * 4096;
  if (fseek(f, (long)offset, SEEK_SET)) return false;
  return fread(out, 1, 4096, f) == 4096;
}
static IOReturn hostScsiDir(uint8_t lun, const uint8_t *cdb, unsigned length, unsigned direction,
                            uint32_t dataBytes, uint32_t timeout, uint32_t *scsi) {
  assert(lun == 0 && length == 10 && timeout && locks == 1); *scsi = 0;
  if (cdb[0] == 0x35) {
    assert(direction == 0 && !dataBytes);
    if (cut_sync >= 0 && syncs == cut_sync) return -1;
    syncs++; return 0;
  }
  bool write = cdb[0] == 0x2a;
  assert(write || cdb[0] == 0x28);
  uint64_t lba = ((uint32_t)cdb[2] << 24) | ((uint32_t)cdb[3] << 16) |
                 ((uint32_t)cdb[4] << 8) | cdb[5];
  unsigned n = ((unsigned)cdb[7] << 8) | cdb[8];
  assert(dataBytes == n * 4096 && direction == (write ? 1u : 2u));
  for (unsigned i = 0; i < n; i++) {
    if (write) {
      assert(cdb[1] == 8 && lba + i > fileFirst &&
             lba + i < fileFirst + (uint64_t)(NB_LOG_FILE_BYTES / 4096));
      if (cut_write >= 0 && writes == cut_write) return -1;
      memcpy(overlay[lba + i].data(), dma + kDataOffset + i * 4096, 4096); writes++;
    } else if (!diskRead(lba + i, dma + kDataOffset + i * 4096)) {
      return -1;
    }
  }
  return 0;
}
#include "NabuLogUfs.h"
static void thread_yield_internal(unsigned) { if (nabu_log_writer_rounds) throw Stop(); }

int main(int argc, char **argv) {
  assert(argc >= 7);
  gptFile = fopen(argv[1], "rb"); espFile = fopen(argv[2], "rb");
  assert(gptFile && espFile);
  nabu_log_lun_blocks = strtoull(argv[3], 0, 10);
  tokenText = argv[4];
  const char *outPath = argv[5];
  std::string mode = argv[6];
  const char *basePath = argc > 7 ? argv[7] : 0;

  uint8_t table[16384];
  assert(fseek(gptFile, 8192, SEEK_SET) == 0 && fread(table, 1, sizeof(table), gptFile) == sizeof(table));
  for (unsigned i = 0; i < 128; i++) {
    if (nb_equal(table + 128 * i + 56, "e\0s\0p\0\0\0", 8)) {
      uint64_t first = nb_le64(table + 128 * i + 32), last = nb_le64(table + 128 * i + 40);
      espFirst = first; espBlocks = last - first + 1;
    }
  }
  assert(espFirst && espBlocks);
  /* Synthetic ESP layout built by the Python test: data_first=172, file=4. */
  fileFirst = espFirst + 172 + 4 - 2;
  if (basePath) {
    FILE *f = fopen(basePath, "rb"); assert(f);
    base.resize(NB_LOG_FILE_BYTES);
    assert(fread(base.data(), 1, base.size(), f) == base.size());
    fclose(f);
  }

  bool isBusy = mode.compare(0, 5, "busy:") == 0;
  bool isToken = mode.compare(0, 6, "token:") == 0;
  if (isBusy) busy_left = strtol(mode.c_str() + 5, 0, 10);
  if (isToken) {
    std::string which = mode.substr(6);
    if (which == "flag") pe_flag = false;
    else if (which == "missing") pe_token = false;
    else assert(0);
  }
  if (mode == "windows") windows_overlap = true;
  /* Raw boot arguments as the kernel sees them; the token is hex text and must
   * be found that way, not through the numeric PE_parse_boot_argn path. */
  g_boot_args = "keep-symbols=1 native-ufs-root=1";
  if (pe_flag) g_boot_args += " nabu-log=1";
  if (pe_token) g_boot_args += " nabu-log-token=" + tokenText;
  g_boot_args += " nabu-source-text=1";
  if (mode.compare(0, 9, "cutwrite:") == 0) cut_write = atoi(mode.c_str() + 9);
  if (mode.compare(0, 8, "cutsync:") == 0) cut_sync = atoi(mode.c_str() + 8);

  int gate_config = -1, gate_past = -1, gate_slot0 = -1, gate_last = -1, gate_overflow = -1;
  bool crashed = false;
  if (mode == "gate") {
    uint8_t token[16];
    assert(nabuLogToken(token));
    assert(nb_volume_open(&nabu_log_volume, nabuLogRead, 0, nabu_log_lun_blocks, token));
    fileFirst = nabu_log_volume.file_first;
    gate_config = nb_volume_write_allowed(&nabu_log_volume, fileFirst, 1);
    gate_past = nb_volume_write_allowed(&nabu_log_volume, fileFirst + NB_LOG_FILE_BYTES / 4096, 1);
    gate_slot0 = nb_volume_write_allowed(&nabu_log_volume, fileFirst + 1, 1);
    gate_last = nb_volume_write_allowed(&nabu_log_volume, fileFirst + NB_LOG_FILE_BYTES / 4096 - 1, 1);
    gate_overflow = nb_volume_write_allowed(&nabu_log_volume, fileFirst + NB_LOG_FILE_BYTES / 4096 - 1, 2);
  } else if (isToken || mode == "start") {
    nabuLogStart();
  } else {
    nabu_capture_append("console text before the first snapshot\n", 39);
    try { nabuLogThread(0, 0); }
    catch (const Crash &) { crashed = true; }
    catch (const Stop &) {}
    if (nabu_log_volume.file_first) fileFirst = nabu_log_volume.file_first;
  }

  FILE *output = fopen(outPath, "wb"); assert(output);
  if (fileFirst) {
    uint8_t block[4096];
    for (unsigned i = 0; i < (unsigned)(NB_LOG_FILE_BYTES / 4096); i++) {
      assert(diskRead(fileFirst + i, block));
      assert(fwrite(block, 1, 4096, output) == 4096);
    }
  }
  fclose(output);
  std::string logPath = std::string(outPath) + ".log";
  FILE *logFile = fopen(logPath.c_str(), "wb"); assert(logFile);
  fwrite(g_log.data(), 1, g_log.size(), logFile); fclose(logFile);
  fclose(gptFile); fclose(espFile);
  printf("{\"mode\":\"%s\",\"writes\":%d,\"syncs\":%d,\"rounds\":%u,\"state\":%u,"
         "\"gate_config\":%d,\"gate_past\":%d,\"gate_slot0\":%d,\"gate_last\":%d,"
         "\"gate_overflow\":%d,\"crashed\":%s}\n",
         mode.c_str(), writes, syncs, nabu_log_writer_rounds, nabu_log_writer_state,
         gate_config, gate_past, gate_slot0, gate_last, gate_overflow,
         crashed ? "true" : "false");
  return 0;
}
'''


def _wsl_path(path):
    text = str(Path(path).resolve())
    match = re.match(r'^([A-Za-z]):\\?(.*)$', text)
    if not match:
        return text
    return '/mnt/' + match.group(1).lower() + '/' + match.group(2).replace('\\', '/')


def _crc(data):
    return zlib.crc32(data) & 0xffffffff


def _entry(name, attr, cluster, size):
    entry = bytearray(32)
    entry[:11] = name
    entry[11] = attr
    entry[20] = (cluster >> 16) & 0xff
    entry[21] = (cluster >> 24) & 0xff
    entry[26] = cluster & 0xff
    entry[27] = (cluster >> 8) & 0xff
    struct.pack_into('<I', entry, 28, size)
    return bytes(entry)


def _slot(payload, sequence=1, token=TOKEN):
    header = bytearray(BLOCK)
    struct.pack_into('<8s4IQ', header, 0, b'NABULOG2', 2, BLOCK, 1, volume.CAPACITY, sequence)
    header[32:48] = sequence.to_bytes(16, 'little')
    struct.pack_into('<3Q', header, 48, len(payload), 0, 0)
    struct.pack_into('<2I', header, 72, len(payload), volume.crc(payload))
    struct.pack_into('<Q', header, 88, 0)
    header[96:112] = token
    header[112:144] = bytes(range(32))
    struct.pack_into('<I', header, 80, volume.header_crc(header, 80))
    return bytes(header) + payload.ljust(volume.CAPACITY, b'\0')


def _gpt_image(lun_blocks, esp_first, esp_blocks):
    header = bytearray(BLOCK)
    header[:8] = b'EFI PART'
    struct.pack_into('<I', header, 8, 0x00010000)
    struct.pack_into('<I', header, 12, 92)
    header[16:20] = b'\0' * 4
    struct.pack_into('<Q', header, 24, 1)
    struct.pack_into('<Q', header, 32, lun_blocks - 1)
    struct.pack_into('<Q', header, 40, 34)
    struct.pack_into('<Q', header, 48, lun_blocks - 34)
    header[56:72] = bytes(range(16, 32))
    struct.pack_into('<Q', header, 72, 2)
    struct.pack_into('<I', header, 80, 1)
    struct.pack_into('<I', header, 84, 128)
    entries = bytearray(BLOCK)
    entries[0:16] = ESP_TYPE
    entries[16:32] = bytes(range(16, 32))
    struct.pack_into('<Q', entries, 32, esp_first)
    struct.pack_into('<Q', entries, 40, esp_first + esp_blocks - 1)
    entries[56:62] = 'esp'.encode('utf-16-le')
    struct.pack_into('<I', header, 88, _crc(bytes(entries[:128])))
    struct.pack_into('<I', header, 16, _crc(bytes(header[:92])))
    blob = bytearray(6 * BLOCK)
    blob[BLOCK:2 * BLOCK] = header
    blob[2 * BLOCK:3 * BLOCK] = entries
    return bytes(blob)


def _esp_image(esp_blocks, token=TOKEN, corrupt_fat=False, directory=None):
    """Create a sparse ESP image and write only the blocks the proof reads."""
    blocks = {}

    boot = bytearray(BLOCK)
    struct.pack_into('<HBHB', boot, 11, BLOCK, 1, RESERVED, 2)
    struct.pack_into('<I', boot, 32, esp_blocks)
    struct.pack_into('<I', boot, 36, FAT_BLOCKS)
    struct.pack_into('<I', boot, 44, 2)
    boot[82:87] = b'FAT32'
    boot[510:512] = b'\x55\xaa'
    blocks[0] = bytes(boot)

    fat = bytearray(FAT_BLOCKS * BLOCK)
    struct.pack_into('<I', fat, 0, 0x0ffffff8)
    struct.pack_into('<I', fat, 4, 0x0fffffff)
    for cluster, nxt in ((2, 0x0fffffff), (3, 0x0fffffff)):
        struct.pack_into('<I', fat, cluster * 4, nxt)
    for index in range(FILE_BLOCKS):
        cluster = FILE_CLUSTER + index
        nxt = cluster + 1 if index + 1 < FILE_BLOCKS else 0x0fffffff
        struct.pack_into('<I', fat, cluster * 4, nxt)
    for mirror in range(2):
        for index in range(FAT_BLOCKS):
            blocks[RESERVED + mirror * FAT_BLOCKS + index] = bytes(fat[index * BLOCK:(index + 1) * BLOCK])
    if corrupt_fat:
        changed = bytearray(blocks[RESERVED + FAT_BLOCKS])
        changed[0] ^= 1
        blocks[RESERVED + FAT_BLOCKS] = bytes(changed)

    root = bytearray(BLOCK)
    offset = 0
    for entry in (_entry(b'ESPNABU    ', 0x08, 0, 0),
                  _entry(b'EFI        ', 0x10, 3, 0),
                  _entry(volume.NAME, 0x20, FILE_CLUSTER, volume.FILE_BYTES)):
        root[offset:offset + 32] = entry
        offset += 32
    blocks[DATA_FIRST] = bytes(root)
    blocks[DATA_FIRST + 1] = bytes(BLOCK)  # empty EFI directory
    blocks[DATA_FIRST + FILE_CLUSTER - 2] = volume.make_config(token)

    handle = tempfile.NamedTemporaryFile(delete=False, suffix='.img', dir=directory)
    name = handle.name
    handle.close()
    with open(name, 'wb') as handle:
        handle.truncate(esp_blocks * BLOCK)
        for index, block in blocks.items():
            handle.seek(index * BLOCK)
            handle.write(block)
    return Path(name)


class WriterHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native = shutil.which('g++') or shutil.which('clang++')
        wsl = shutil.which('wsl.exe')
        if native:
            cls.kind, cls.compiler = 'native', native
        elif wsl:
            probe = subprocess.run([wsl, '-e', 'bash', '-lc', 'command -v g++'],
                                   capture_output=True)
            if probe.returncode:
                raise unittest.SkipTest('wsl present but no g++ inside it')
            cls.kind, cls.compiler = 'wsl', wsl
        else:
            raise unittest.SkipTest('no g++/clang++ and no WSL for the writer harness')
        cls.tmp = tempfile.TemporaryDirectory(prefix='nabu-log-writer-')
        root = Path(cls.tmp.name)
        include = root / 'include'
        include.mkdir()
        (include / 'NabuLogBuild.h').write_text(
            'static const unsigned char nabu_log_build_id[32]={' +
            ','.join(str(i) for i in range(32)) + '};\n')
        source = root / 'harness.cpp'
        source.write_text(HARNESS)
        if cls.kind == 'native':
            cls.binary = str(root / 'harness.exe')
            command = [cls.compiler, '-std=gnu++17', '-O1', '-pthread',
                       '-I', str(include), '-I', str(UFS), str(source), '-o', cls.binary]
            result = subprocess.run(command, capture_output=True)
        else:
            cls.binary = '/tmp/nabu_log_writer_harness_' + str(id(cls)) + '/harness'
            script = 'mkdir -p %s && g++ -std=gnu++17 -O1 -pthread -I %s -I %s %s -o %s' % (
                shlex.quote(cls.binary.rsplit('/', 1)[0]), shlex.quote(_wsl_path(include)),
                shlex.quote(_wsl_path(UFS)), shlex.quote(_wsl_path(source)),
                shlex.quote(cls.binary))
            result = subprocess.run([cls.compiler, '-e', 'bash', '-lc', script], capture_output=True)
        if result.returncode:
            raise RuntimeError('writer harness compile failed: ' +
                               result.stderr.decode('utf-8', 'replace')[-3000:])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def volume(self, corrupt_fat=False):
        directory = Path(tempfile.mkdtemp(dir=self.tmp.name))
        gpt = directory / 'gpt.bin'
        gpt.write_bytes(_gpt_image(LUN_BLOCKS, ESP_FIRST, ESP_BLOCKS))
        esp = _esp_image(ESP_BLOCKS, corrupt_fat=corrupt_fat, directory=directory)
        return gpt, esp

    def run_harness(self, mode, esp=None, gpt=None, base=None):
        directory = Path(tempfile.mkdtemp(dir=self.tmp.name))
        if esp is None or gpt is None:
            gpt, esp = self.volume()
        out = directory / 'journal.bin'
        base_path = None
        if base is not None:
            base_path = directory / 'base.bin'
            base_path.write_bytes(base)
        if self.kind == 'native':
            arguments = [str(gpt), str(esp), str(LUN_BLOCKS), TOKEN.hex(), str(out), mode]
            if base_path is not None:
                arguments.append(str(base_path))
            result = subprocess.run([self.binary] + arguments, capture_output=True)
        else:
            arguments = [_wsl_path(gpt), _wsl_path(esp), str(LUN_BLOCKS), TOKEN.hex(),
                         _wsl_path(out), mode]
            if base_path is not None:
                arguments.append(_wsl_path(base_path))
            command = ' '.join(shlex.quote(x) for x in [self.binary] + arguments)
            result = subprocess.run([self.compiler, '-e', 'bash', '-lc', command], capture_output=True)
        stdout = result.stdout.decode('utf-8', 'replace')
        if result.returncode:
            self.fail('harness failed (%s): %s' % (mode, result.stderr.decode('utf-8', 'replace')[-3000:]))
        lines = [line for line in stdout.splitlines() if line.startswith('{')]
        self.assertTrue(lines, 'harness produced no JSON: ' + stdout[-2000:])
        report = json.loads(lines[-1])
        log = Path(str(out) + '.log').read_text(encoding='utf-8', errors='replace')
        self.assertNotIn(TOKEN.hex(), log, 'allocation token must not be logged')
        report['log'] = log
        report['journal'] = out.read_bytes() if out.stat().st_size else b''
        return report

    # -- normal path and the write gate -----------------------------------
    def test_real_transport_normal_commit_decodes(self):
        report = self.run_harness('normal')
        self.assertGreaterEqual(report['rounds'], 1)
        self.assertIn('volume verified', report['log'])
        self.assertIn('writer ready', report['log'])
        self.assertIn('first snapshot committed', report['log'])
        payload, info = volume.decode_container(report['journal'])
        self.assertEqual(info['selected_slot'], 0)
        self.assertEqual(info['sequence'], 1)
        self.assertIn(b'console text before the first snapshot', payload)

    def test_write_gate_refuses_config_and_file_end(self):
        report = self.run_harness('gate')
        self.assertEqual(report['gate_config'], 0)
        self.assertEqual(report['gate_past'], 0)
        self.assertEqual(report['gate_slot0'], 1)
        self.assertEqual(report['gate_last'], 1)
        self.assertEqual(report['gate_overflow'], 0)

    # -- retry budget ------------------------------------------------------
    def test_transient_contention_reaches_commit_without_instant_exhaustion(self):
        # Six open attempts each consume 50 try-lock failures. A count-only
        # five-attempt budget stops with zero slots; the time-bounded budget
        # keeps retrying while the boot thread still owns the host lock.
        report = self.run_harness('busy:300')
        self.assertIn('volume open failed attempt=6', report['log'])
        self.assertGreaterEqual(report['rounds'], 1)
        payload, info = volume.decode_container(report['journal'])
        self.assertEqual(info['sequence'], 1)

    def test_permanent_contention_is_bounded_and_named(self):
        report = self.run_harness('busy:100000000')
        self.assertEqual(report['rounds'], 0)
        self.assertEqual(report['writes'], 0)
        self.assertEqual(report['state'], 3)
        self.assertRegex(report['log'], 'writer stopped reason=(volume-open|open-deadline)')

    # -- named refusals ----------------------------------------------------
    def test_boot_window_overlap_stops_before_any_write(self):
        report = self.run_harness('windows')
        self.assertEqual(report['writes'], 0)
        self.assertEqual(report['state'], 3)
        self.assertIn('reason=boot-windows', report['log'])
        self.assertIn('detail=esp-overlap', report['log'])

    def test_fat_mirror_mismatch_names_the_failed_gate(self):
        directory = Path(tempfile.mkdtemp(dir=self.tmp.name))
        gpt = directory / 'gpt.bin'
        gpt.write_bytes(_gpt_image(LUN_BLOCKS, ESP_FIRST, ESP_BLOCKS))
        esp = _esp_image(ESP_BLOCKS, corrupt_fat=True, directory=directory)
        report = self.run_harness('normal', esp=esp, gpt=gpt)
        self.assertEqual(report['writes'], 0)
        self.assertIn('reason=fat-mirror', report['log'])
        self.assertRegex(report['log'], 'writer stopped reason=(volume-open|open-deadline)')

    def test_token_gate_reasons_never_print_the_token(self):
        absent = self.run_harness('token:flag')
        self.assertEqual(absent['state'], 0)
        self.assertIn('reason=token-gate detail=nabu-log-absent-or-not-1', absent['log'])
        missing = self.run_harness('token:missing')
        self.assertEqual(missing['state'], 0)
        self.assertIn('reason=token-gate detail=nabu-log-token-absent', missing['log'])

    def test_start_helper_records_the_thread_start(self):
        report = self.run_harness('start')
        self.assertEqual(report['state'], 1)
        self.assertNotIn('start skipped', report['log'])

    # -- interrupted commit keeps the old slot ----------------------------
    def test_payload_sync_and_header_cuts_keep_the_previous_slot(self):
        seeded = volume.make_config(TOKEN) + _slot(b'previous complete snapshot\n', 1) + \
            bytes(volume.SLOT_BYTES)
        for mode in ('cutwrite:0', 'cutwrite:1', 'cutsync:0'):
            report = self.run_harness(mode, base=seeded)
            self.assertEqual(report['state'], 3, mode)
            self.assertIn('writer stopped reason=commit-write', report['log'], mode)
            payload, info = volume.decode_container(report['journal'])
            self.assertEqual(info['selected_slot'], 0, mode)
            self.assertEqual(info['sequence'], 1, mode)
            self.assertEqual(payload, b'previous complete snapshot\n', mode)


class WriterSourceContract(unittest.TestCase):
    def test_volume_open_has_no_untracked_failure(self):
        text = (UFS / 'NabuLogVolume.h').read_text(encoding='utf-8')
        body = text[text.index('static inline int nb_volume_open'):]
        body = body[:body.index('static inline int nb_volume_write_allowed')]
        self.assertNotIn('return 0;', body, 'every volume refusal must set a named reason')
        reasons = set(re.findall(r'\bNBV_[A-Z_]+\b', text))
        for reason in reasons:
            self.assertRegex(text, r'case ' + reason + r': return "', 'missing label for ' + reason)

    def test_writer_logs_reasons_and_never_the_token(self):
        text = (UFS / 'NabuLogUfs.h').read_text(encoding='utf-8')
        for marker in ('reason=token-gate', 'reason=boot-windows', 'stop_reason="commit-write"',
                       'volume open failed attempt=', 'writer stopped reason=%s'):
            self.assertIn(marker, text)
        for line in text.splitlines():
            if 'IOLog' in line:
                self.assertNotIn('token[', line)
                self.assertNotIn('%s", token', line)


if __name__ == '__main__':
    unittest.main()