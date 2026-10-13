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
    def test_desktop_dispatches_pending_accessibility_updates(self):
        context = mock.MagicMock()
        context.pending.side_effect = [True, True, False]
        gui = Gui.__new__(Gui)
        with mock.patch('wayland_ui.GLib.MainContext.default', return_value=context), \
                mock.patch('wayland_ui.pyatspi.Registry.getDesktop', return_value='desktop'):
            self.assertEqual(gui.desktop(), 'desktop')
        self.assertEqual(context.iteration.call_args_list, [mock.call(False), mock.call(False)])

    def test_authentication_search_uses_shell_not_browser_page_content(self):
        browser = mock.MagicMock()
        browser.name = 'Chromium'
        shell = mock.MagicMock()
        shell.name = 'gnome-shell'
        dialog = mock.MagicMock()
        dialog.name = 'Authentication Required'
        shell.get_collection_iface.return_value.get_matches.return_value = [dialog]
        closed = mock.MagicMock()
        type(closed).name = mock.PropertyMock(side_effect=RuntimeError('application no longer exists'))
        gui = Gui.__new__(Gui)
        with mock.patch('wayland_ui.pyatspi.Registry.getDesktop', return_value=[browser, closed, shell]):
            self.assertEqual(gui.window('Authentication'), 'auth')
        browser.__iter__.assert_not_called()

    def test_chord_releases_keys_when_wait_fails(self):
        gui = Gui.__new__(Gui)
        events = []
        gui.command = lambda name, arguments: events.extend(arguments['events'])
        with mock.patch('wayland_ui.time.sleep', side_effect=RuntimeError('wait failed')):
            with self.assertRaisesRegex(RuntimeError, 'wait failed'):
                gui.key('ctrl+Return')
        self.assertEqual([(event['data']['key']['data'], event['data']['down']) for event in events],
                         [('ctrl', True), ('ret', True), ('ret', False), ('ctrl', False)])

    def test_focus_uses_the_matching_browser_favorite(self):
        gui = Gui.__new__(Gui)
        gui.key = mock.Mock()
        with mock.patch('wayland_ui.time.sleep'):
            gui.focus('chromium')
            gui.focus('firefox')
        self.assertEqual(gui.key.call_args_list, [mock.call('Super_L+2'), mock.call('Super_L+3')])
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
