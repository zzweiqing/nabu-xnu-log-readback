#!/usr/bin/env python3
"""Apply the opt-in recorder after upstream XNU patches, before compilation."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Logging source drift: ' + old[:100])
    return text.replace(old, new, 1)


def patch_console(text):
    marker = '/* NABU_CAPTURE_V2_1 console producer hooks */'
    if marker in text:
        for name in ('console_write(char *str, int size)', 'console_write_unbuffered(char c)'):
            if text.count(name) != 1:
                raise ValueError('Recorder source changed after patching')
        return text
    if 'NABU_CAPTURE_' in text:
        raise ValueError('Older recorder hook present; use a fresh source tree')
    text = replace_once(text, 'void\nconsole_write(char *str, int size)\n{\n',
        marker + '\n#define NABU_LOG_IMPLEMENTATION\n#include "NabuLogCore.h"\n\n'
        'void nabu_console_write_captured(char *, int);\n'
        'static void nabu_console_write_raw(char *, int);\n'
        'void\nconsole_write(char *str, int size)\n{\n'
        '\tif (size > 0) nabu_capture_append(str, (unsigned)size);\n'
        '\tnabu_console_write_raw(str, size);\n}\n\n'
        'void\nnabu_console_write_captured(char *str, int size)\n{\n'
        '\tnabu_console_write_raw(str, size);\n}\n\n'
        'static void\nnabu_console_write_raw(char *str, int size)\n{\n')
    return replace_once(text, 'console_write_unbuffered(char c)\n{\n',
                        'console_write_unbuffered(char c)\n{\n\tnabu_capture_append(&c, 1);\n')


def patch_general(text):
    marker = '/* NABU_CAPTURE_V2 capture before printbuf truncation */'
    if marker in text:
        return text
    text = replace_once(text, 'void\nconsole_printbuf_putc(int ch, void * arg)\n{\n',
        marker + '\nextern void nabu_capture_append(const char *, unsigned);\n'
        'extern void nabu_console_write_captured(char *, int);\n'
        'void\nconsole_printbuf_putc(int ch, void * arg)\n{\n'
        '\tchar captured = (char)ch;\n\tnabu_capture_append(&captured, 1);\n')
    call = 'console_write(info->str, info->pos);'
    if text.count(call) != 3:
        raise ValueError('Expected all three printbuf flush calls')
    return text.replace(call, 'nabu_console_write_captured(info->str, info->pos);')


def patch_kprintf(text):
    marker = '/* NABU_CAPTURE_V2 hardware kprintf producer */'
    if marker in text:
        return text
    return replace_once(text, 'static void\nserial_putc_crlf(char c)\n{\n',
        marker + '\nextern void nabu_capture_append(const char *, unsigned);\n'
        'static void\nserial_putc_crlf(char c)\n{\n\tnabu_capture_append(&c, 1);\n')


def patch_bsd_init(text):
    marker = '/* NABU_CAPTURE_V2_2 opt-in diagnostic calls */'
    if marker in text:
        return text
    old = '/* NABU_CAPTURE_V2_1 opt-in USB probe call */'
    if old in text:
        # Upgrade a tree prepared by the earlier hook without re-injecting.
        text = replace_once(text, old, marker)
        return replace_once(text, '\t\tnabu_usb_probe_start();\n',
            '\t\tnabu_usb_probe_start();\n'
            '\t\textern void nabu_heartbeat_start(void);\n'
            '\t\tnabu_heartbeat_start();\n')
    return replace_once(text, '\tprintf(copyright);\n',
        '\tprintf(copyright);\n'
        '\t' + marker + '\n'
        '\t{\n'
        '\t\textern void nabu_usb_probe_start(void);\n'
        '\t\textern void nabu_heartbeat_start(void);\n'
        '\t\tnabu_usb_probe_start();\n'
        '\t\tnabu_heartbeat_start();\n'
        '\t}\n')


def patch_bsd_init_cdc(text):
    marker = '/* NABU_CAPTURE_V2_1 opt-in USB CDC call after IOKit init */'
    if marker in text:
        return text
    anchor = '\tbsd_autoconf();\n'
    return replace_once(text, anchor, anchor +
        marker + '\n'
        '\t{\n'
        '\t\textern void nabu_usb_cdc_log_start(void);\n'
        '\t\tnabu_usb_cdc_log_start();\n'
        '\t}\n')


def apply(root, device):
    xnu = root / '.cache/xnu-work'
    changed = {}
    for relative, transforms in [
            ('osfmk/console/serial_console.c', [patch_console]),
            ('osfmk/console/serial_general.c', [patch_general]),
            ('pexpert/arm/pe_kprintf.c', [patch_kprintf]),
            # The probe stays at the top of bsd_init (read-only MMIO); the CDC
            # channel starts after bsd_autoconf() so IOKit init has completed
            # and no allocator/personality is assumed before it exists.
            ('bsd/kern/bsd_init.c', [patch_bsd_init, patch_bsd_init_cdc])]:
        path = xnu / relative
        result = path.read_text(encoding='utf-8')
        for transform in transforms:
            result = transform(result)
        path.write_text(result, encoding='utf-8')
        changed[relative] = hashlib.sha256(result.encode()).hexdigest()
    for name in ('NabuLogCore.h', 'NabuLogFormat.h'):
        shutil.copyfile(device / 'ufs' / name, xnu / 'osfmk/console' / name)
    out = root / 'build/nabu-log'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'source-report.json').write_text(json.dumps({
        'version': 2, 'hooks': changed, 'capture_before_console_disable': True,
        'usb_probe_call': True, 'usb_probe_read_only': True,
        'usb_cdc_call': True, 'usb_cdc_after_iokit_init': True,
        'usb_cdc_entry': 'nabu_usb_cdc_log_start',
        'usb_cdc_static_dma': True, 'usb_cdc_boot_arg_gated': True,
        'heartbeat_call': True, 'heartbeat_entry': 'nabu_heartbeat_start',
        'heartbeat_boot_arg_gated': True, 'heartbeat_read_only': True,
        'disk_io_in_capture': False, 'runtime_qualified': False}, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--device', type=Path, required=True)
    a = p.parse_args()
    apply(a.root, a.device)
