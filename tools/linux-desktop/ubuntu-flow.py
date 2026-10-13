"""Reuse the desktop checks with Ubuntu GNOME Wayland and confined Snap browsers."""
from pathlib import Path
import os
import shlex
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
    device = original_run('fido2-token', '-L').stdout.strip().split(':', 1)[0]
    assert device.startswith('/dev/hidraw')
    (flow.RESULTS / 'udev-token.txt').write_text(original_run('udevadm', 'info', '--query=property', '--name=' + device).stdout)
    descriptor = '/sys/class/hidraw/' + Path(device).name + '/device/report_descriptor'
    probe = original_run('snap', 'run', '--shell', 'chromium.chromedriver',
                         input='cat /proc/self/attr/current\n' +
                               'cat ' + shlex.quote(descriptor) + ' >/dev/null && echo DESCRIPTOR_READ_OK\n' +
                               '(exec 3<>' + shlex.quote(device) + ') && echo HID_OPEN_OK\nexit\n', check=False)
    (flow.RESULTS / 'snap-hid-access.txt').write_text(probe.stdout + probe.stderr)
    options = flow.webdriver.ChromeOptions()
    options.binary_location = '/snap/chromium/current/usr/lib/chromium-browser/chrome'
    for flag in ['--no-first-run', '--disable-dev-shm-usage', '--ozone-platform=wayland',
                 '--class=chromium_chromium',
                 '--force-renderer-accessibility', '--user-data-dir=/home/lkdesktop/snap/chromium/common/test-profile']:
        options.add_argument(flag)
    chrome = flow.webdriver.Chrome(service=flow.ChromeService('/snap/bin/chromium.chromedriver',
                                   log_output=(flow.RESULTS / 'chrome.log').open('w'),
                                   service_args=['--verbose']), options=options)
    options = flow.webdriver.FirefoxOptions()
    options.binary_location = '/snap/firefox/current/usr/lib/firefox/firefox'
    firefox = flow.webdriver.Firefox(service=flow.FirefoxService('/snap/bin/geckodriver',
                                     log_output=str(flow.RESULTS / 'gecko.log'),
                                     env={**os.environ, 'MOZ_ENABLE_WAYLAND': '1',
                                          'MOZ_APP_REMOTINGNAME': 'firefox_firefox'}), options=options)
    drivers = {'chromium': chrome, 'firefox': firefox}
    profiles = {}
    for browser, capability in [('chromium', 'goog:processID'), ('firefox', 'moz:processID')]:
        process = Path('/proc') / str(drivers[browser].capabilities[capability])
        assert process.stat().st_uid == os.getuid()
        assert str((process / 'exe').readlink()).startswith('/snap/' + browser + '/')
        label = (process / 'attr/current').read_text().strip()
        assert label.startswith('snap.' + browser + '.') and '(enforce)' in label, label
        profiles[browser] = label
    assert original_run('xdotool', 'search', '--onlyvisible', '--class', 'chromium|firefox', check=False).returncode != 0
    flow.record('both Snap browsers enforce AppArmor and use native Wayland', profiles=profiles,
                versions={browser: driver.capabilities['browserVersion'] for browser, driver in drivers.items()})
    return drivers


def firefox_prompt(name, action):
    prompt = f'{name}-attestation' if action == 'register' else f'{name}-account-picker'
    pattern = r'^Allow$' if action == 'register' else r'(chromium|firefox)-pin'
    button = flow.wait(lambda: gui.button('firefox', pattern), 'Firefox native permission/account button did not appear')
    gui.screenshot(prompt)
    assert button.queryAction().doAction(0), 'Firefox native button refused activation'


flow.run = run
flow.window = gui.window
flow.screenshot = gui.screenshot
flow.record_versions = record_versions
flow.create_drivers = create_drivers
flow.firefox_prompt = firefox_prompt
flow.execute()
