"""Validate native ARM64 pending AIO metadata and its actual submission trace."""
import re
import struct


def validate(target, entry, trace, pid, size):
    assert target['kind'] == 'native-aio'
    assert target['tgid'] == pid and target['fd'] == 10 and target['bytes'] == size
    assert target['endpoint'] == '/dev/ffs-ske/ep4' and target['wchan'] == 'read_events'
    assert target['iocb_pwrite_fd_buffer_size_verified'] is True
    words = target['syscall'].split()
    assert words[0] == '4' and int(words[1], 0) == target['context']
    assert int(words[2], 0) == int(words[3], 0) == 1
    buffer = int(target['buffer'], 0)
    assert buffer > 0 and int(target['request'], 0) > 0
    raw = bytes.fromhex(target['iocb_hex'])
    assert struct.unpack('<QIIHhIQQqQII', raw) == (0, 0, 0, 1, 0, 10, buffer, size, 0, 0, 0, 0)
    own = [line for line in trace.splitlines() if re.search(r'\bske-usbd-' + str(target['tid']) + r'\s', line)]
    assert entry in own
    assert 'ctx_id: ' + format(target['context'], 'x') + ', nr: 1' in entry
    assert 'sys_io_submit(' in entry or 'sys_enter_io_submit:' in entry
    original = own.index(entry)
    assert original + 1 < len(own)
    assert re.search(r'(?:sys_exit_io_submit:|sys_io_submit ->)\s*(?:0x1|1)\b', own[original + 1])
    assert len([line for line in own if 'sys_io_submit(' in line or 'sys_enter_io_submit:' in line]) == 1
    return own
