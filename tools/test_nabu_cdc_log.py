"""Exercise raw CDC byte preservation, disconnect tails and device selection."""
import io
from types import SimpleNamespace
import unittest

from tools import nabu_cdc_log as cdc


class ReceiveTests(unittest.TestCase):
    def test_disconnect_preserves_bytes_and_flushes_incomplete_utf8(self):
        class Connection:
            chunks = iter([b'XNU \xe5', b'\x90\xaf\xe5'])

            def read(self, _size):
                try:
                    return next(self.chunks)
                except StopIteration:
                    raise OSError('disconnected')

        raw, text = io.BytesIO(), io.StringIO()
        with self.assertRaisesRegex(OSError, 'disconnected'):
            cdc.receive(Connection(), raw, text, 10, now=lambda: 0)
        self.assertEqual(raw.getvalue(), b'XNU \xe5\x90\xaf\xe5')
        self.assertEqual(text.getvalue(), 'XNU 启�')

    def test_identity_does_not_connect_to_unrelated_serial_device(self):
        unrelated = SimpleNamespace(device='COM1', vid=1, pid=2, serial_number='other')
        target = SimpleNamespace(device='COM8', vid=cdc.VID, pid=cdc.PID,
                                 serial_number=cdc.USB_SERIAL)
        self.assertIsNone(cdc.select_port([unrelated]))
        self.assertIs(cdc.select_port([unrelated, target]), target)
        self.assertIs(cdc.select_port([unrelated, target], 'com1'), unrelated)
        with self.assertRaisesRegex(ValueError, 'multiple'):
            cdc.select_port([target, target])

    def test_timeout_flushes_utf8_without_sending_data(self):
        class Connection:
            def read(self, size):
                self.size = size
                return b'panic: test\n'

        clock = iter([0, 2])
        raw, text = io.BytesIO(), io.StringIO()
        count = cdc.receive(Connection(), raw, text, 1, now=lambda: next(clock))
        self.assertEqual(count, len(raw.getvalue()))
        self.assertEqual(text.getvalue(), 'panic: test\n')


if __name__ == '__main__':
    unittest.main()
