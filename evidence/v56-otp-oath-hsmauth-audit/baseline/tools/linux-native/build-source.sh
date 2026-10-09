#!/bin/sh
# /src is the frozen emulator source mounted read-only. /artifacts is a new
# private scratch directory, never an existing user credential store.
set -eu

cmake -S /src -B /artifacts/build -G Ninja \
  -DCMAKE_CXX_COMPILER=g++-14 -DCMAKE_C_COMPILER=gcc-14 \
  -DCMAKE_BUILD_TYPE=Debug -DSWPASSKEY_LIBSECRET=OFF \
  -DSWPASSKEY_LIBNOTIFY=OFF -DSWPASSKEY_TPM=OFF \
  -DSWPASSKEY_PLATFORM_TESTS=OFF > /artifacts/linux-configure.log 2>&1
cmake --build /artifacts/build --parallel 4 > /artifacts/linux-build.log 2>&1
/artifacts/build/swpasskey_tests --reporter compact > /artifacts/linux-unit.log 2>&1

python3 - <<'PY'
import json, platform, re, subprocess
from pathlib import Path

unit=Path('/artifacts/linux-unit.log').read_text()
match=re.search(r'All tests passed \((\d+) assertions in (\d+) test cases\)',unit)
assert match,unit[-2000:]
assertions,cases=map(int,match.groups())
version=subprocess.run(['/artifacts/build/swpasskeyd','--version'],check=True,capture_output=True,text=True).stdout.strip()
result={
    'passed':True,'platform':platform.system(),'architecture':platform.machine(),
    'build_host_kernel':platform.release(),'version':version,
    'cpp_cases':cases,'cpp_assertions':assertions,
    'source_mounted_readonly':True,'hardware_key_accessed':False,
    'manufacturer_trust_reproduced':False,'real_os_keychain_tests_enabled':False,
    'native_uhid_registration_verified':False,
    'next_step':'Boot separate distro kernel with UHID/HIDRAW and verify native hidraw discovery and standard SDK on fresh own software credentials',
}
Path('/artifacts/linux-build-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
PY
