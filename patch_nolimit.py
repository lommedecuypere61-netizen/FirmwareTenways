"""
patch_nolimit.py — Tenways SW102 speed limiter removal

Replaces the 12-byte BL get_max_RPM + STRB block at 0x0A6DA with inline
code that stores RPM limit = 0x0001 (minimum period value = no practical cap).

No code cave, no GPREGRET, no toggle — bike runs at full motor speed.
"""

import struct
import zipfile
import json

INPUT_FILE  = 'sw102.bin'
OUTPUT_BIN  = 'sw102_nolimit.bin'
OUTPUT_DAT  = 'sw102_nolimit.dat'
OUTPUT_MAN  = 'manifest_nolimit.json'
OUTPUT_ZIP  = 'sw102_nolimit_dfu.zip'

BASE_ADDR      = 0x00018000
PATCH_FILE_OFF = 0x0A6DA   # BL get_max_RPM (4 bytes) + LSRS/MOV/STRB/STRB (8 bytes)
PATCH_LEN      = 12

# Original 12 bytes for sanity check
ORIG_BL   = bytes([0xF5, 0xF7, 0xF5, 0xFE])
ORIG_STRB = bytes([0x01, 0x0A, 0x6A, 0x46, 0x11, 0x70, 0x50, 0x70])

# Replacement: set RPM limit = 0x0001 inline, no function call needed
#   MOVS r0, #0x01      → r0 = 1  (full 16-bit limit value)
#   LSRS r1, r0, #8     → r1 = 0  (high byte)
#   MOV  r2, sp
#   STRB r1, [r2, #0]   → sp+0 = 0x00
#   STRB r0, [r2, #1]   → sp+1 = 0x01
#   NOP
NOLIMIT_PATCH = bytes([
    0x01, 0x20,  # MOVS r0, #1
    0x01, 0x0A,  # LSRS r1, r0, #8
    0x6A, 0x46,  # MOV  r2, sp
    0x11, 0x70,  # STRB r1, [r2, #0]
    0x50, 0x70,  # STRB r0, [r2, #1]
    0xBF, 0x00,  # NOP
])

assert len(NOLIMIT_PATCH) == PATCH_LEN


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def apply_patch() -> tuple[bytes, int]:
    data = bytearray(open(INPUT_FILE, 'rb').read())

    at = PATCH_FILE_OFF
    found_bl   = data[at:at+4]
    found_strb = data[at+4:at+12]

    if found_bl != ORIG_BL:
        raise ValueError(f'Unexpected BL bytes at 0x{at:05X}: {found_bl.hex().upper()} (expected {ORIG_BL.hex().upper()})')
    if found_strb != ORIG_STRB:
        raise ValueError(f'Unexpected STRB bytes at 0x{at+4:05X}: {found_strb.hex().upper()}')

    data[at:at + PATCH_LEN] = NOLIMIT_PATCH

    patched = bytes(data)
    open(OUTPUT_BIN, 'wb').write(patched)

    crc = crc16_ccitt(patched)

    # Nordic DFU v0.5 init packet
    dat = struct.pack('<HHIHH', 0xFFFF, 0xFFFF, 0xFFFFFFFF, 1, 100)
    dat += struct.pack('<H', crc)
    open(OUTPUT_DAT, 'wb').write(dat)

    manifest = {
        "manifest": {
            "application": {
                "bin_file": OUTPUT_BIN,
                "dat_file": OUTPUT_DAT,
                "init_packet_data": {
                    "application_version": 4294967295,
                    "device_revision": 65535,
                    "device_type": 65535,
                    "firmware_crc16": crc,
                    "softdevice_req": [100]
                }
            },
            "dfu_version": 0.5
        }
    }
    with open(OUTPUT_MAN, 'w') as f:
        json.dump(manifest, f, indent=2)

    with zipfile.ZipFile(OUTPUT_ZIP, 'w', zipfile.ZIP_DEFLATED) as z:
        z.write(OUTPUT_BIN)
        z.write(OUTPUT_DAT)
        z.write(OUTPUT_MAN, 'manifest.json')

    return patched, crc


def verify(data: bytes, crc: int) -> bool:
    orig = open(INPUT_FILE, 'rb').read()
    diffs = [(i, orig[i], data[i]) for i in range(len(data)) if orig[i] != data[i]]

    patch_ok = data[PATCH_FILE_OFF:PATCH_FILE_OFF + PATCH_LEN] == NOLIMIT_PATCH
    crc_ok   = crc16_ccitt(data) == crc

    dat_bytes = open(OUTPUT_DAT, 'rb').read()
    dat_crc   = struct.unpack('<H', dat_bytes[-2:])[0]
    dat_ok    = dat_crc == crc

    print('=== Verification ===')
    print(f'  Patch bytes match:   {patch_ok}')
    print(f'  CRC16-CCITT:         0x{crc:04X} = {crc}')
    print(f'  CRC consistent:      {crc_ok}')
    print(f'  .dat CRC matches:    {dat_ok}')
    print(f'  Bytes changed:       {len(diffs)}')
    for i, a, b in diffs:
        print(f'    0x{i:05X}: {a:02X} → {b:02X}')
    return patch_ok and crc_ok and dat_ok


if __name__ == '__main__':
    print(f'Patching {INPUT_FILE} → {OUTPUT_BIN}')
    data, crc = apply_patch()
    print(f'Written: {OUTPUT_BIN}, {OUTPUT_DAT}, {OUTPUT_MAN}, {OUTPUT_ZIP}')
    print()
    verify(data, crc)
