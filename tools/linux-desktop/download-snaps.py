"""Download signed stable Snap packages and their base/content providers for the offline VM."""
import subprocess
from pathlib import Path
import yaml

directory = Path('/localkey/snaps')
directory.mkdir()
queue = ['snapd', 'firefox', 'chromium']
downloaded = set()
while queue:
    name = queue.pop(0)
    if name in downloaded:
        continue
    subprocess.run(['snap', 'download', name, '--channel=stable', '--target-directory', str(directory),
                    '--basename', name], check=True)
    metadata = yaml.safe_load(subprocess.check_output(
        ['unsquashfs', '-cat', str(directory / (name + '.snap')), 'meta/snap.yaml']))
    assert metadata['name'] == name
    downloaded.add(name)
    if metadata.get('base') not in (None, 'none'):
        queue.append(metadata['base'])
    for plug in metadata.get('plugs', {}).values():
        if isinstance(plug, dict) and plug.get('default-provider'):
            queue.append(plug['default-provider'].split(':')[0])
assert {'firefox', 'chromium', 'snapd'} <= downloaded
(directory / 'packages.txt').write_text('\n'.join(sorted(downloaded)) + '\n')
