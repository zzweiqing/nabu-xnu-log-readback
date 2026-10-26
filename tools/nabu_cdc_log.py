#!/usr/bin/env python3
"""Receive the nabu raw CDC console without sending terminal commands.

Requires pySerial. Auto-discovery matches the current nabu firmware's complete
VID/PID/serial identity; --port explicitly selects another port. Each connection
gets separate files, so disconnect/reboot boundaries are preserved. DTR is set
for CDC streaming. This tool never flashes or reboots the tablet.
"""
import argparse
import codecs
from datetime import datetime, timezone
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
VID, PID, USB_SERIAL = 0x1d6b, 0x0104, '0000000001'


def utc():
    return datetime.now(timezone.utc).isoformat()


def select_port(ports, explicit=None):
    if explicit:
        matches = [p for p in ports if p.device.casefold() == explicit.casefold()]
    else:
        matches = [p for p in ports if (p.vid, p.pid, p.serial_number) ==
                   (VID, PID, USB_SERIAL)]
    if len(matches) > 1:
        raise ValueError('multiple matching CDC ports; select one with --port')
    return matches[0] if matches else None


def receive(connection, raw, text, deadline, now=time.monotonic):
    """Preserve received bytes even when a subsequent read raises on disconnect."""
    decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
    count = 0
    try:
        while now() < deadline:
            chunk = connection.read(65536)
            if not chunk:
                continue
            raw.write(chunk)
            raw.flush()
            text.write(decoder.decode(chunk))
            text.flush()
            count += len(chunk)
    finally:
        text.write(decoder.decode(b'', final=True))
        text.flush()
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', help='explicit COM or tty port; otherwise match nabu USB identity')
    parser.add_argument('--seconds', type=float, default=300, help='total wait/capture budget, default 300 s')
    parser.add_argument('--out', type=Path, help='new output directory')
    parser.add_argument('--list', action='store_true', help='list visible serial ports and exit')
    args = parser.parse_args(argv)
    if not 0 < args.seconds <= 86400:
        parser.error('--seconds must be in (0, 86400]')
    try:
        import serial
        from serial.tools import list_ports
    except ImportError:
        parser.exit(2, 'pySerial required: py -3 -m pip install pyserial==3.5\n')
    if args.list:
        for port in list_ports.comports():
            print(json.dumps({'port': port.device, 'vid': port.vid, 'pid': port.pid,
                              'serial': port.serial_number, 'description': port.description}))
        return 0
    out = args.out or ROOT / 'device_bringup/out' / (
        'nabu-cdc-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%fZ'))
    out.mkdir(parents=True, exist_ok=False)
    report = {'started_utc': utc(), 'device_writes': False, 'terminal_commands_sent': False,
              'cdc_dtr': True, 'sessions': [], 'bytes_received': 0,
              'expected_identity': {'vid': VID, 'pid': PID, 'serial': USB_SERIAL},
              'explicit_port': args.port, 'result': 'waiting'}
    report_path = out / 'capture.json'

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    save()
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline:
            port = select_port(list_ports.comports(), args.port)
            if port is None:
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))
                continue
            index = len(report['sessions']) + 1
            session = {'port': port.device, 'started_utc': utc(), 'bytes_received': 0,
                       'raw': f'console-{index:03d}.bin', 'text': f'console-{index:03d}.txt'}
            report['sessions'].append(session)
            save()
            print(f'Connected {port.device}; saving {out / session["raw"]}', flush=True)
            with (out / session['raw']).open('xb') as raw, (
                    out / session['text']).open('x', encoding='utf-8', newline='') as text:
                try:
                    # Opening a CDC port changes USB control-line state only.
                    # No command bytes, output-buffer reset, or input discard.
                    with serial.Serial(port.device, baudrate=115200, timeout=0.5,
                                       write_timeout=0.5) as connection:
                        connection.dtr = True
                        receive(connection, raw, text, deadline)
                except (serial.SerialException, OSError) as error:
                    session['disconnect_or_open_error'] = str(error)
                finally:
                    session['bytes_received'] = raw.tell()
                    session['finished_utc'] = utc()
                    report['bytes_received'] = sum(s['bytes_received'] for s in report['sessions'])
                    save()
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        report['interrupted'] = True
    except ValueError as error:
        report['error'] = str(error)
    finally:
        report['finished_utc'] = utc()
        report['result'] = 'received' if report['bytes_received'] else 'no_bytes_received'
        save()
    print(json.dumps({'out': str(out), 'result': report['result'],
                      'bytes_received': report['bytes_received']}, ensure_ascii=True))
    return 0 if report['bytes_received'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
