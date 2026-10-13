"""Check QMP event framing and refuse input outside the fixture display/text."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from PIL import Image
from wayland_ui import Gui


class QmpTests(unittest.TestCase):
    def test_focus_releases_alt_when_virtual_keyboard_input_fails(self):
        gui = Gui.__new__(Gui)
        gui.window = lambda *args, **options: None
        events = []

        def command(name, arguments):
            events.extend(arguments['events'])
            if arguments['events'][0]['data']['key']['data'] == 'tab':
                raise RuntimeError('input failed')

        gui.command = command
        with self.assertRaisesRegex(RuntimeError, 'input failed'):
            gui.focus('firefox')
        self.assertEqual(events[-1]['data'], {'down': False, 'key': {'type': 'qcode', 'data': 'alt'}})

    def test_events_fragmented_reply_and_command_error(self):
        client, server = socket.socketpair()
        gui = Gui.__new__(Gui)
        gui.port = client.makefile('rwb', buffering=0)
        gui.buffer = b''
        gui.sequence = 0

        def peer():
            with server.makefile('rwb', buffering=0) as port:
                request = json.loads(port.readline())
                reply = (json.dumps({'event': 'RESET'}) + '\n' +
                         json.dumps({'return': {'version': 1}, 'id': request['id']}) + '\n').encode()
                port.write(reply[:7])
                port.write(reply[7:])
                request = json.loads(port.readline())
                port.write((json.dumps({'error': {'class': 'GenericError', 'desc': 'refused'},
                                       'id': request['id']}) + '\n').encode())

        thread = threading.Thread(target=peer)
        thread.start()
        try:
            self.assertEqual(gui.command('query-version'), {'version': 1})
            with self.assertRaisesRegex(RuntimeError, 'refused'):
                gui.command('unsupported')
        finally:
            gui.port.close()
            client.close()
            thread.join(timeout=5)
            server.close()
        self.assertFalse(thread.is_alive())

    def test_reject_out_of_display_click_and_non_fixture_text(self):
        gui = Gui.__new__(Gui)
        commands = []
        gui.command = lambda name, arguments=None: commands.append((name, arguments))
        with tempfile.TemporaryDirectory() as directory:
            gui.results = Path(directory)
            gui.screenshot = lambda name: Image.new('RGB', (1280, 800)).save(gui.results / f'{name}.png')
            for x, y in [(-1, 0), (1280, 0), (0, 800)]:
                with self.assertRaises(AssertionError):
                    gui.click(x, y)
            for text in ['', 'A', '\n', '한글']:
                with self.assertRaises(AssertionError):
                    gui.type(text)
            self.assertEqual(commands, [])
            gui.click(1279, 799)
            events = commands[0][1]['events']
            self.assertEqual([event['data']['value'] for event in events[:2]], [32767, 32767])
            self.assertFalse(commands[1][1]['events'][0]['data']['down'])


if __name__ == '__main__':
    unittest.main()
