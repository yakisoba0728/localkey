"""Reuse the desktop checks with Ubuntu GNOME Wayland and confined Snap browsers."""
from pathlib import Path
import os
import subprocess

import desktop_flow as flow
from wayland_ui import Gui

original_run = flow.run
gui = Gui(original_run, flow.RESULTS)


def run(*arguments, **options):
    if arguments[0] == 'xdotool':
        gui.xdotool(arguments[1:])
        return subprocess.CompletedProcess(arguments, 0, '', '')
    return original_run(*arguments, **options)


def record_versions():
    packages = original_run('dpkg-query', '-W', 'ubuntu-desktop-minimal', 'systemd', 'gdm3', 'gnome-shell',
                            'snapd', 'apparmor', 'python3-fido2').stdout
    (flow.RESULTS / 'versions.txt').write_text(Path('/etc/os-release').read_text() + packages +
                                             original_run('uname', '-a').stdout)
    assert 'Type=wayland' in original_run('loginctl', 'show-session', os.environ['XDG_SESSION_ID'], '-p', 'Type').stdout
    assert original_run('aa-enabled', check=False).returncode == 0


def create_drivers():
    options = flow.webdriver.ChromeOptions()
    options.binary_location = '/snap/bin/chromium'
    for flag in ['--no-first-run', '--disable-dev-shm-usage', '--ozone-platform=wayland',
                 '--force-renderer-accessibility', '--user-data-dir=/home/lkdesktop/snap/chromium/common/test-profile']:
        options.add_argument(flag)
    chrome = flow.webdriver.Chrome(service=flow.ChromeService('/snap/bin/chromium.chromedriver',
                                   log_output=(flow.RESULTS / 'chrome.log').open('w')), options=options)
    options = flow.webdriver.FirefoxOptions()
    options.binary_location = '/snap/firefox/current/usr/lib/firefox/firefox'
    firefox = flow.webdriver.Firefox(service=flow.FirefoxService('/snap/bin/geckodriver',
                                     log_output=str(flow.RESULTS / 'gecko.log'),
                                     env={**os.environ, 'MOZ_ENABLE_WAYLAND': '1'}), options=options)
    drivers = {'chromium': chrome, 'firefox': firefox}
    profiles = {'chromium': [], 'firefox': []}
    for process in Path('/proc').glob('[0-9]*'):
        try:
            command = (process / 'cmdline').read_bytes().split(b'\0')
            if process.stat().st_uid != os.getuid() or b'--type=' in b' '.join(command) or b'-contentproc' in command:
                continue
            binary = command[0].decode()
            for browser, executable in [('chromium', 'chrome'), ('firefox', 'firefox')]:
                if binary.startswith('/snap/' + browser + '/') and Path(binary).name == executable:
                    profiles[browser].append((process / 'attr/current').read_text().strip())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    for browser, labels in profiles.items():
        assert labels and all(label.startswith('snap.' + browser + '.') and '(enforce)' in label for label in labels), profiles
    assert original_run('xdotool', 'search', '--onlyvisible', '--class', 'chromium|firefox', check=False).returncode != 0
    flow.record('both Snap browsers enforce AppArmor and use native Wayland', profiles=profiles,
                versions={browser: driver.capabilities['browserVersion'] for browser, driver in drivers.items()})
    return drivers


flow.run = run
flow.window = gui.window
flow.screenshot = gui.screenshot
flow.record_versions = record_versions
flow.create_drivers = create_drivers
flow.execute()
