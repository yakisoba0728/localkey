"""Operate only this VM's virtual keyboard/display through its private QMP port."""
import json
import re
import select
import shutil
import time
from pathlib import Path

from PIL import Image
import pyatspi
from gi.repository import GLib, Atspi


class Gui:
    def __init__(self, run, results):
        self.run = run
        self.results = results
        self.port = open('/dev/virtio-ports/localkey.test-qmp', 'r+b', buffering=0)
        self.buffer = b''
        self.sequence = 0
        try:
            self.command('qmp_capabilities')
        except RuntimeError as error:
            # The QMP connection survives guest reboot; negotiate only once.
            if 'qmp_capabilities' not in str(error) and 'already complete' not in str(error):
                raise
        self.command('query-version')

    def command(self, name, arguments=None):
        self.sequence += 1
        identifier = f'guest-{self.sequence}'
        self.port.write(json.dumps({'execute': name, 'arguments': arguments or {}, 'id': identifier}).encode() + b'\n')
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if b'\n' not in self.buffer:
                if not select.select([self.port], [], [], 1)[0]:
                    continue
                chunk = self.port.read(65536)
                if not chunk:
                    raise RuntimeError('VM QMP port closed')
                self.buffer += chunk
                if len(self.buffer) > 1048576:
                    raise RuntimeError('oversized QMP response')
                continue
            line, self.buffer = self.buffer.split(b'\n', 1)
            message = json.loads(line)
            if message.get('id') != identifier:
                continue
            if 'error' in message:
                raise RuntimeError(message['error'])
            return message['return']
        raise TimeoutError(name)

    def screenshot(self, name):
        self.command('screendump', {'filename': '/out/screens/desktop.png', 'format': 'png'})
        shutil.copyfile('/localkey/screens/desktop.png', self.results / f'{name}.png')

    def key(self, *chords):
        aliases = {'Super_L': 'meta_l', 'Return': 'ret', 'Escape': 'esc', 'Tab': 'tab', 'space': 'spc'}
        for chord in chords:
            keys = [aliases.get(key, key.lower()) for key in chord.split('+')]
            event = lambda key, down: {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': key}}}
            # QEMU's virtual-clock key-release timer can lag during emulated browser startup.
            self.command('input-send-event', {'events': [event(key, True) for key in keys]})
            try:
                time.sleep(.06)
            finally:
                self.command('input-send-event', {'events': [event(key, False) for key in reversed(keys)]})
            time.sleep(.12)

    def type(self, text):
        assert re.fullmatch(r'[a-z0-9-]+', text), 'fixture text must use simple keyboard characters'
        for character in text:
            self.key('minus' if character == '-' else character)

    def click(self, x, y):
        self.screenshot('pointer-before-click')
        with Image.open(self.results / 'pointer-before-click.png') as picture:
            width, height = picture.size
        assert 0 <= x < width and 0 <= y < height
        self.command('input-send-event', {'events': [
            {'type': 'abs', 'data': {'axis': 'x', 'value': round(x * 32767 / (width - 1))}},
            {'type': 'abs', 'data': {'axis': 'y', 'value': round(y * 32767 / (height - 1))}},
            {'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
        self.command('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': False}}]})

    def application(self, pattern):
        for app in self.desktop():
            try:
                if re.search(pattern, app.name or '', re.I):
                    return app
            except Exception:
                continue
        return None

    def matches(self, app, role, showing=True):
        states = Atspi.StateSet.new([])
        if showing:
            states.add(Atspi.StateType.SHOWING)
        rule = Atspi.MatchRule.new(states, Atspi.CollectionMatchType.ALL,
                                  {}, Atspi.CollectionMatchType.ALL,
                                  [role], Atspi.CollectionMatchType.ANY,
                                  [], Atspi.CollectionMatchType.ALL, False)
        # Query in the application: a per-node walk can exceed FIDO's presence timeout.
        return app.get_collection_iface().get_matches(rule, Atspi.CollectionSortOrder.CANONICAL, 0, True)

    def window(self, pattern, field='--name'):
        if pattern.startswith('localkey'):
            result = self.run('xdotool', 'search', '--onlyvisible', '--name', pattern, check=False)
            return result.stdout.splitlines()[-1] if result.returncode == 0 and result.stdout.strip() else None
        if pattern == 'Authentication':
            # shortcut: Ubuntu GNOME 50 light-theme 1280x800 native polkit dialog.
            self.screenshot('authentication-state')
            with Image.open(self.results / 'authentication-state.png') as picture:
                red, green, blue = picture.convert('RGB').getpixel((500, 435))
                panel = picture.convert('RGB').getpixel((500, 190))
            if red > 180 and 40 < green < 130 and blue < 100 and min(panel) > 235:
                return 'auth'
            return None
        return pattern if self.application(pattern) is not None else None

    def desktop(self):
        # Dispatch AT-SPI's queued cache updates without a blocking main loop.
        context = GLib.MainContext.default()
        for _ in range(1000):
            if not context.pending():
                break
            context.iteration(False)
        return pyatspi.Registry.getDesktop(0)

    def focus(self, identifier):
        if identifier == 'auth':
            return  # GNOME's native polkit modal already owns keyboard focus.
        if identifier.isdigit():
            expected = self.run('xdotool', 'getwindowname', identifier).stdout.strip()
            focused = self.run('xdotool', 'getwindowfocus', 'getwindowname', check=False).stdout.strip()
            if expected and focused == expected:
                return
            self.key('Super_L+1')
            time.sleep(1)
            focused = self.run('xdotool', 'getwindowfocus', 'getwindowname', check=False).stdout.strip()
            assert expected and focused == expected, (expected, focused)
            return
        assert identifier in ('chromium', 'firefox'), identifier
        # Match the installed Snap desktop IDs when WebDriver launches native Wayland windows.
        self.key('Super_L+' + ('2' if identifier == 'chromium' else '3'))
        time.sleep(1)

    def xdotool(self, arguments):
        command = arguments[0]
        if command == 'windowactivate':
            self.focus(arguments[-1])
        elif command == 'key':
            self.key(*arguments[1:])
        elif command == 'type':
            self.type(arguments[-1])
        elif command == 'mousemove' and arguments[3:] == ('click', '1'):
            self.click(int(arguments[1]), int(arguments[2]))
        else:
            raise ValueError(f'unsupported fixture UI command: {arguments}')

    def button(self, application, pattern):
        app = self.application('^' + re.escape(application) + '$')
        if app is not None:
            for button in self.matches(app, Atspi.Role.PUSH_BUTTON):
                try:
                    if (re.search(pattern, button.name or '', re.I) and
                            button.getState().contains(pyatspi.STATE_SHOWING)):
                        return button
                except Exception:
                    continue
        return None
