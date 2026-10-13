"""Check QMP event framing and refuse input outside the fixture display/text."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

from PIL import Image
import pyatspi
from wayland_ui import Gui


class QmpTests(unittest.TestCase):
    def test_pin_readiness_requires_a_focused_native_password_field(self):
        gui = Gui.__new__(Gui)
        gui.application = mock.Mock(return_value=object())
        field = mock.MagicMock()
        gui.matches = mock.Mock(return_value=[field])
        field.getState.return_value.contains.return_value = False
        self.assertFalse(gui.pin_ready('firefox'))
        field.getState.return_value.contains.return_value = True
        self.assertTrue(gui.pin_ready('firefox'))
        gui.application.return_value = None
        self.assertFalse(gui.pin_ready('firefox'))

    def test_desktop_dispatches_pending_accessibility_updates(self):
        context = mock.MagicMock()
        context.pending.side_effect = [True, True, False]
        gui = Gui.__new__(Gui)
        with mock.patch('wayland_ui.GLib.MainContext.default', return_value=context), \
                mock.patch('wayland_ui.pyatspi.Registry.getDesktop', return_value='desktop'):
            self.assertEqual(gui.desktop(), 'desktop')
        self.assertEqual(context.iteration.call_args_list, [mock.call(False), mock.call(False)])

    def test_authentication_screen_check_excludes_white_browser_content(self):
        gui = Gui.__new__(Gui)
        with tempfile.TemporaryDirectory() as directory:
            gui.results = Path(directory)
            picture = Image.new('RGB', (1280, 800), 'white')
            gui.screenshot = lambda name: picture.save(gui.results / f'{name}.png')
            self.assertIsNone(gui.window('Authentication'))
            picture.putpixel((500, 435), (233, 84, 32))
            self.assertEqual(gui.window('Authentication'), 'auth')
            picture.putpixel((500, 190), (0, 0, 0))
            self.assertIsNone(gui.window('Authentication'))

    def test_chord_releases_keys_when_wait_fails(self):
        gui = Gui.__new__(Gui)
        events = []
        gui.command = lambda name, arguments: events.extend(arguments['events'])
        with mock.patch('wayland_ui.time.sleep', side_effect=RuntimeError('wait failed')):
            with self.assertRaisesRegex(RuntimeError, 'wait failed'):
                gui.key('ctrl+Return')
        self.assertEqual([(event['data']['key']['data'], event['data']['down']) for event in events],
                         [('ctrl', True), ('ret', True), ('ret', False), ('ctrl', False)])

    def test_focus_follows_native_running_icons_instead_of_favorites_or_order(self):
        gui = Gui.__new__(Gui)
        gui.click = mock.Mock()
        shell, hidden, favorite, chromium, firefox = [mock.MagicMock() for _ in range(5)]
        shell.getRole.return_value = pyatspi.ROLE_APPLICATION
        shell.__iter__.return_value = [hidden, favorite, firefox, chromium]
        hidden.getState.return_value.contains.return_value = False
        for node, name, y in [(favorite, 'Firefox', 161), (chromium, 'chromium-browser', 292),
                              (firefox, 'firefox', 228)]:
            node.name = name
            node.getRole.return_value = pyatspi.ROLE_PUSH_BUTTON
            node.getState.return_value.contains.return_value = True
            node.queryComponent.return_value.getExtents.return_value = (1, y, 64, 64)
        gui.application = mock.Mock(return_value=shell)
        with mock.patch('wayland_ui.time.sleep'):
            gui.focus('chromium')
            gui.focus('firefox')
            chromium.getState.return_value.contains.return_value = False
            firefox.queryComponent.return_value.getExtents.return_value = (1, 164, 64, 64)
            gui.focus('firefox')
        self.assertEqual(gui.click.call_args_list, [mock.call(33, 324), mock.call(33, 260), mock.call(33, 196)])
        hidden.__iter__.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'dock button not found'):
            gui.focus('chromium')
        with self.assertRaises(AssertionError):
            gui.focus('unknown')

    def test_native_button_search_skips_hidden_buttons_and_other_apps(self):
        shell = mock.MagicMock()
        shell.name = 'gnome-shell'
        firefox = mock.MagicMock()
        firefox.name = 'Firefox'
        hidden, visible = mock.MagicMock(), mock.MagicMock()
        for button in (hidden, visible):
            button.name = 'Allow'
            button.getRole.return_value = pyatspi.ROLE_PUSH_BUTTON
        hidden.getState.return_value.contains.return_value = False
        visible.getState.return_value.contains.return_value = True
        firefox.get_collection_iface.return_value.get_matches.return_value = [hidden, visible]
        gui = Gui.__new__(Gui)
        with mock.patch('wayland_ui.pyatspi.Registry.getDesktop', return_value=[shell, firefox]):
            self.assertIs(gui.button('firefox', r'^Allow$'), visible)
        shell.__iter__.assert_not_called()

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
