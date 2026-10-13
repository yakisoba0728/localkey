"""Operate only this VM's virtual keyboard/display through its private QMP port."""
import json
import re
import select
import shutil
import time
from pathlib import Path

from PIL import Image
import pyatspi


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
            self.command('send-key', {'keys': [{'type': 'qcode', 'data': key} for key in keys], 'hold-time': 60})
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

    def window(self, pattern, field='--name', active=False):
        if pattern.startswith('localkey'):
            result = self.run('xdotool', 'search', '--onlyvisible', '--name', pattern, check=False)
            return result.stdout.splitlines()[-1] if result.returncode == 0 and result.stdout.strip() else None
        expression = re.compile(pattern, re.I)
        applications = list(pyatspi.Registry.getDesktop(0))
        pending = []
        for app in applications:
            try:
                if app.name == 'gnome-shell' if pattern == 'Authentication' else expression.search(app.name or ''):
                    pending.append(app)
            except Exception:
                continue
        if active:
            for app in pending:
                for child in app:
                    try:
                        if child.getRole() in (pyatspi.ROLE_FRAME, pyatspi.ROLE_DIALOG) and child.getState().contains(pyatspi.STATE_ACTIVE):
                            return pattern
                    except Exception:
                        continue
            return None
        count = 0
        while pending and count < 10000:
            node = pending.pop()
            count += 1
            try:
                if expression.search(node.name or ''):
                    if not active or (node.getRole() in (pyatspi.ROLE_FRAME, pyatspi.ROLE_DIALOG)
                                      and node.getState().contains(pyatspi.STATE_ACTIVE)):
                        return 'auth' if pattern == 'Authentication' else pattern
                pending.extend(node)
            except Exception:
                continue
        return None

    def focus(self, identifier):
        if identifier == 'auth':
            return  # GNOME's native polkit modal already owns keyboard focus.
        if identifier.isdigit():
            self.key('Super_L+1')
            time.sleep(1)
            expected = self.run('xdotool', 'getwindowname', identifier).stdout.strip()
            focused = self.run('xdotool', 'getwindowfocus', 'getwindowname', check=False).stdout.strip()
            assert expected and focused == expected, (expected, focused)
            return
        for count in range(8):
            active = self.window(identifier, active=True)
            if active:
                return
            # Native Alt+Tab avoids app-ID mismatches in Snap WebDriver launches.
            key = lambda code, down: {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': code}}}
            self.command('input-send-event', {'events': [key('alt', True)]})
            try:
                for _ in range(count + 1):
                    self.command('input-send-event', {'events': [key('tab', True), key('tab', False)]})
                    time.sleep(.15)
            finally:
                self.command('input-send-event', {'events': [key('alt', False)]})
            time.sleep(.5)
        raise RuntimeError(f'native window did not become active: {identifier}')

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
