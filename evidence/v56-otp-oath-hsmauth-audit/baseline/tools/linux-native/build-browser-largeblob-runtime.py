"""Install a stock browser chroot and only private guest accessibility tools."""
import hashlib
import json
import os
import shutil
import stat
import struct
from pathlib import Path


def install(root, copy_file, dependencies):
    source = Path('/opt/ske-chromium-root')
    destination = root/'opt/chromium-root'
    destination.mkdir()
    for item in source.iterdir():
        target = destination/item.name
        if item.name in {'dev','proc','sys','run','tmp'}:
            target.mkdir()
        elif item.is_symlink():
            target.symlink_to(os.readlink(item))
        elif item.is_dir():
            shutil.copytree(item,target,symlinks=True)
        else:
            assert item.is_file()
            shutil.copy2(item,target)
    binary = destination/'usr/lib/chromium/chromium'
    with binary.open('rb') as stream:
        header = stream.read(20)
        stream.seek(0)
        digest = hashlib.file_digest(stream,'sha256').hexdigest()
    assert header[:4] == b'\x7fELF' and header[5] == 1 and struct.unpack_from('<H',header,18)[0] == 183
    assert digest == '4f8459f639cd128f701fc84b04bbdc496a56202cdd78beec5db721bdda260911'
    version = (destination/'opt/ske-chromium-provenance/version.txt').read_text().strip()
    assert version == 'Chromium 154.0.8037.92'
    (destination/'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
    for directory in ['dev/pts','proc','sys','run','tmp']:
        (destination/directory).mkdir(parents=True,exist_ok=True)
    for executable in [
        '/usr/bin/Xvfb','/usr/bin/xdotool','/usr/bin/xkbcomp','/usr/bin/xprop',
        '/usr/bin/dbus-daemon','/usr/bin/dbus-uuidgen',
        '/usr/libexec/at-spi-bus-launcher','/usr/libexec/at-spi2-registryd',
        '/usr/lib/aarch64-linux-gnu/libatspi.so.0',
        '/usr/lib/aarch64-linux-gnu/libatk-1.0.so.0',
        '/usr/lib/aarch64-linux-gnu/libatk-bridge-2.0.so.0',
        '/usr/lib/aarch64-linux-gnu/libgirepository-1.0.so.1',
    ]:
        copy_file(executable)
        dependencies(executable)
    for directory in [
        '/etc/dbus-1','/usr/share/dbus-1','/usr/share/X11/xkb',
        '/usr/share/glib-2.0/schemas','/usr/share/defaults/at-spi2',
        '/usr/lib/python3/dist-packages/gi','/usr/lib/python3/dist-packages/pyatspi',
        '/usr/lib/aarch64-linux-gnu/girepository-1.0',
    ]:
        shutil.copytree(directory,root/directory.lstrip('/'),dirs_exist_ok=True)
    for library in Path('/usr/lib/python3/dist-packages/gi').glob('*.so'):
        dependencies(library)
    for name in ['verify-browser-largeblob.py','browser-largeblob-sdk.py','largeblob-guest-init.sh']:
        copy_file('/work/'+name,'/opt/verification/'+name)
    os.chmod(root/'opt/verification/largeblob-guest-init.sh',0o755)
    return {
        'name':'Chromium','version':'154.0.8037.92','architecture':'AArch64',
        'package_version':'154.0.8037.92-1~deb13u1','apt_signed_repository_verification_used':True,
        'debian_base_image_digest':'sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5',
        'binary_sha256':digest,'upstream_revision':'334b65d254ccc35df4fca82706d1753227b01039',
        'stock_binary_unmodified':True,'host_devices_or_browser_state_copied':False,
        'package_metadata_sha256':hashlib.file_digest((destination/'opt/ske-chromium-provenance/packages.tsv').open('rb'),'sha256').hexdigest(),
        'own_accessibility_runtime_resource_paths_verified':True,
        'helper_sha256':{name:hashlib.file_digest((root/'opt/verification'/name).open('rb'),'sha256').hexdigest() for name in ['verify-browser-largeblob.py','browser-largeblob-sdk.py','largeblob-guest-init.sh']},
    }
