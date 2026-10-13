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

    def window(self, pattern, field='--name'):
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
        count = 0
        while pending and count < 10000:
            node = pending.pop()
            count += 1
            try:
                if expression.search(node.name or ''):
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
        # Browser STATE_ACTIVE can remain set behind another Wayland window.
        self.key('Super_L')
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            pending = []
            for app in pyatspi.Registry.getDesktop(0):
                try:
                    if app.name == 'gnome-shell':
                        pending.append(app)
                except Exception:
                    continue
            count = 0
            coordinates = None
            while pending and count < 2000:
                node = pending.pop()
                count += 1
                try:
                    if (node.getRole() == pyatspi.ROLE_LABEL and
                            'localkey browser verification' in (node.name or '') and
                            re.search(identifier, node.name, re.I)):
                        preview = node.parent
                        x, y, width, height = preview.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)
                        if preview.getRole() == pyatspi.ROLE_PUSH_BUTTON and width > 100 and height > 100:
                            coordinates = (x + width // 2, y + height // 2)
                            break
                    pending.extend(node)
                except Exception:
                    continue
            if coordinates:
                self.click(*coordinates)
                time.sleep(.5)
                return
            time.sleep(.25)
        raise RuntimeError(f'native overview preview not found: {identifier}')

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
        expression = re.compile(pattern, re.I)
        pending = []
        for app in pyatspi.Registry.getDesktop(0):
            try:
                if (app.name or '').lower() == application:
                    pending.append(app)
            except Exception:
                continue
        count = 0
        while pending and count < 5000:
            node = pending.pop()
            count += 1
            try:
                if (node.getRole() == pyatspi.ROLE_PUSH_BUTTON and expression.search(node.name or '') and
                        node.getState().contains(pyatspi.STATE_SHOWING)):
                    return node
                pending.extend(node)
            except Exception:
                continue
        return None
