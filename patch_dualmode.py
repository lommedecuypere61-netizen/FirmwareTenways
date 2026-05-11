#!/usr/bin/env python3
"""
Tenways / SW102 Firmware Dual-Mode Speed Limiter Patch
======================================================
STREET LEGAL MODE  : 25 km/h  (RPM 799  = 0x031F)
PRIVÉ TERREIN MODE : 40 km/h  (RPM 306  = 0x0132)

TOGGLE: schrijf 0x01 naar GPREGRET (0x4000051C) voor 40 km/h,
        0x00 voor 25 km/h.  De button-handler hook staat onderaan
        als kommentaar; na Ghidra-analyse invullen op 0x07258.

Analyse gebaseerd op suffix-trie methode + ARM Thumb-2 disassemblage.
"""

import struct, sys, shutil
from pathlib import Path

# ──────────────────────────────────────────────────
# Constanten
# ──────────────────────────────────────────────────
INPUT_BIN      = Path("sw102.bin")
OUTPUT_BIN     = Path("sw102_dualmode.bin")

BASE_ADDR      = 0x00018000   # nRF52 flash load address (SoftDevice 100)
GPREGRET_ADDR  = 0x4000051C   # nRF52 POWER->GPREGRET: overleeft soft reset

RPM_25KMH      = 0x031F       # 799 RPM  → 25 km/h (wettelijk)
RPM_40KMH      = 0x0132       # 306 RPM  → 40 km/h (privé terrein)

# Speed-limiter: BL get_max_RPM + 4 STRB-instructies
SL_BL_FILE     = 0x0A6DA      # bestandsoffset van 'bl get_max_RPM'
SL_STRB_FILE   = 0x0A6DE      # bestandsoffset van lsrs/strb blok (8 bytes)

# Code cave: 177 x 0xFF bytes  (uitlijnd op 4 bytes)
CAVE_FILE      = 0x0E3C8      # bestandsoffset cave (2 bytes na cave-start)
CAVE_ADDR      = BASE_ADDR + CAVE_FILE   # = 0x000263C8

# Button-handler: CMP r6, #3  →  BEQ → 0x07258
BTN_HOOK_FILE  = 0x07258      # bestandsoffset voor optionele button hook


# ──────────────────────────────────────────────────
# Thumb-32 branch encoder
# ──────────────────────────────────────────────────
def encode_bl(from_file, to_file, kind='bl'):
    """Geeft 4-byte Thumb-32 BL of B.W van from_file naar to_file."""
    from_addr = BASE_ADDR + from_file
    to_addr   = BASE_ADDR + to_file
    offset    = to_addr - (from_addr + 4)
    assert -(1 << 24) <= offset < (1 << 24), \
        f"Branch offset {offset:#x} valt buiten ±16 MB bereik"

    S       = 1 if offset < 0 else 0
    uoff    = offset & 0x1FFFFFF        # 25-bit unsigned two's complement
    I1      = (uoff >> 23) & 1
    I2      = (uoff >> 22) & 1
    J1      = (I1 ^ S ^ 1) & 1
    J2      = (I2 ^ S ^ 1) & 1
    imm10   = (uoff >> 12) & 0x3FF
    imm11   = (uoff >>  1) & 0x7FF

    h1 = 0xF000 | (S << 10) | imm10
    # D-bit: 0xD000 = BL,  0x9000 = B.W
    link_bit = 0xD000 if kind == 'bl' else 0x9000
    h2 = link_bit | (J1 << 13) | (J2 << 11) | imm11

    return bytes([h1 & 0xFF, h1 >> 8, h2 & 0xFF, h2 >> 8])


def decode_bl_target(data, file_offset):
    """Decodeert Thumb-32 BL/B.W en geeft target bestandsoffset terug."""
    b = data[file_offset:file_offset + 4]
    h1 = b[0] | (b[1] << 8)
    h2 = b[2] | (b[3] << 8)

    S     = (h1 >> 10) & 1
    imm10 = h1 & 0x3FF
    J1    = (h2 >> 13) & 1
    J2    = (h2 >> 11) & 1
    imm11 = h2 & 0x7FF

    I1 = (J1 ^ S ^ 1) & 1
    I2 = (J2 ^ S ^ 1) & 1

    uoff = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    # Sign extend vanuit bit 24
    if S:
        uoff -= (1 << 25)

    target_addr = (BASE_ADDR + file_offset + 4) + uoff
    return target_addr - BASE_ADDR


# ──────────────────────────────────────────────────
# CAVE CODE  (36 bytes, start op CAVE_FILE = 0x0E3C8)
# ──────────────────────────────────────────────────
#
# Thumb-2 assembly (little-endian bytes):
#
#   cave+0x00:  LDR  r2, [pc, #20]    ; laad GPREGRET adres
#   cave+0x02:  LDRB r3, [r2, #0]     ; lees mode (0=25, 1=40)
#   cave+0x04:  CMP  r3, #0
#   cave+0x06:  BEQ  +2               ; als 0 → mode_25 op +0x0C
#   cave+0x08:  LDR  r0, [pc, #20]    ; mode_40: laad RPM 306
#   cave+0x0A:  B    +0               ; spring naar common op +0x0E
#   cave+0x0C:  LDR  r0, [pc, #12]    ; mode_25: laad RPM 799
#   cave+0x0E:  LSRS r1, r0, #8       ; r1 = high byte
#   cave+0x10:  MOV  r2, sp
#   cave+0x12:  STRB r1, [r2, #0]     ; sla high byte op
#   cave+0x14:  STRB r0, [r2, #1]     ; sla low byte op
#   cave+0x16:  BX   LR               ; terug naar caller
#   cave+0x18:  .word GPREGRET_ADDR   (0x4000051C)
#   cave+0x1C:  .word RPM_25KMH       (0x031F)
#   cave+0x20:  .word RPM_40KMH       (0x0132)
#
# LDR pc-relative verificatie (cave_addr = 0x263C8):
#   +0x00: Align(0x263CC, 4) = 0x263CC;  +20 = 0x263E0 = cave+0x18  ✓
#   +0x08: Align(0x263D4, 4) = 0x263D4;  +20 = 0x263E8 = cave+0x20  ✓
#   +0x0C: Align(0x263D8, 4) = 0x263D8;  +12 = 0x263E4 = cave+0x1C  ✓

SPEED_CAVE = bytes([
    0x05, 0x4A,  # LDR  r2, [pc, #20]   imm8=5
    0x13, 0x78,  # LDRB r3, [r2, #0]
    0x00, 0x2B,  # CMP  r3, #0
    0x01, 0xD0,  # BEQ  +2              imm8=1 → target=+0x0C
    0x05, 0x48,  # LDR  r0, [pc, #20]   imm8=5 → RPM_40 @ +0x20
    0x00, 0xE0,  # B    +0              imm11=0 → target=+0x0E
    0x03, 0x48,  # LDR  r0, [pc, #12]   imm8=3 → RPM_25 @ +0x1C
    0x01, 0x0A,  # LSRS r1, r0, #8
    0x6A, 0x46,  # MOV  r2, sp
    0x11, 0x70,  # STRB r1, [r2, #0]
    0x50, 0x70,  # STRB r0, [r2, #1]
    0x70, 0x47,  # BX   LR
]) + struct.pack('<III', GPREGRET_ADDR, RPM_25KMH, RPM_40KMH)

assert len(SPEED_CAVE) == 0x24, f"Cave size klopt niet: {len(SPEED_CAVE)}"


# ──────────────────────────────────────────────────
# BUTTON TOGGLE CAVE  (20 bytes, start cave+0x24)
# ──────────────────────────────────────────────────
# Optioneel: patch BTN_HOOK_FILE (0x07258) met BL naar hier.
# Na BX LR keert uitvoering terug naar 0x0725C (MOVS r0, #64).
#
#   btn_cave+0x00:  LDR  r0, [pc, #12]  ; GPREGRET adres
#   btn_cave+0x02:  LDRB r1, [r0, #0]
#   btn_cave+0x04:  MOVS r2, #1
#   btn_cave+0x06:  EORS r1, r2          ; toggle bit 0
#   btn_cave+0x08:  STRB r1, [r0, #0]
#   btn_cave+0x0A:  BX   LR
#   btn_cave+0x0C:  NOP  (2b padding)
#   btn_cave+0x0E:  NOP  (2b padding)
#   btn_cave+0x10:  .word GPREGRET_ADDR
#
# LDR verificatie (btn_cave_addr = CAVE_ADDR+0x24 = 0x263EC):
#   +0x00: Align(0x263F0, 4) = 0x263F0;  +12 = 0x263FC = btn_cave+0x10  ✓

BTN_CAVE = bytes([
    0x03, 0x48,  # LDR  r0, [pc, #12]   imm8=3 → GPREGRET @ +0x10
    0x01, 0x78,  # LDRB r1, [r0, #0]
    0x01, 0x22,  # MOVS r2, #1
    0x51, 0x40,  # EORS r1, r2
    0x01, 0x70,  # STRB r1, [r0, #0]
    0x70, 0x47,  # BX   LR
    0x00, 0xBF,  # NOP  (alignment padding)
    0x00, 0xBF,  # NOP  (alignment padding)
]) + struct.pack('<I', GPREGRET_ADDR)

assert len(BTN_CAVE) == 0x14, f"Btn cave size klopt niet: {len(BTN_CAVE)}"


# ──────────────────────────────────────────────────
# Patch uitvoeren
# ──────────────────────────────────────────────────
def apply_patch(enable_button_hook: bool = False):
    data = bytearray(INPUT_BIN.read_bytes())
    print(f"Firmware geladen: {len(data)} bytes (0x{len(data):X})")
    print(f"CRC van origineel: {sum(data) & 0xFFFF:#06X}\n")

    # 1. Verifieer dat de cave 0xFF bytes bevat
    cave_bytes = data[CAVE_FILE:CAVE_FILE + 0x38]
    if not all(b == 0xFF for b in cave_bytes):
        print(f"WAARSCHUWING: Cave bevat niet-0xFF bytes op 0x{CAVE_FILE:05X}!")
        print(f"  Huidige bytes: {cave_bytes[:16].hex(' ')}")

    # 2. Verifieer originele speed-limiter pattern
    expected_sl = bytes([0x01, 0x0A, 0x6A, 0x46, 0x11, 0x70, 0x50, 0x70])
    actual_sl   = bytes(data[SL_STRB_FILE:SL_STRB_FILE + 8])
    if actual_sl != expected_sl:
        print(f"WAARSCHUWING: Speed-limiter pattern gewijzigd!")
        print(f"  Verwacht: {expected_sl.hex(' ')}")
        print(f"  Gevonden: {actual_sl.hex(' ')}")
    else:
        print(f"✓ Speed-limiter pattern gevonden op 0x{SL_STRB_FILE:05X}")

    # 3. Schrijf speed toggle cave code
    data[CAVE_FILE:CAVE_FILE + len(SPEED_CAVE)] = SPEED_CAVE
    print(f"✓ Speed cave geschreven op 0x{CAVE_FILE:05X} ({len(SPEED_CAVE)} bytes)")

    # 4. Trampoline: vervang BL get_max_RPM door BL cave
    new_bl = encode_bl(SL_BL_FILE, CAVE_FILE)
    old_bl = bytes(data[SL_BL_FILE:SL_BL_FILE + 4])
    data[SL_BL_FILE:SL_BL_FILE + 4] = new_bl
    print(f"✓ BL trampoline: 0x{SL_BL_FILE:05X}: {old_bl.hex(' ')} → {new_bl.hex(' ')}")

    # Verifieer terug-decodering
    decoded_target = decode_bl_target(data, SL_BL_FILE)
    assert decoded_target == CAVE_FILE, \
        f"BL target decode FOUT: 0x{decoded_target:05X} ≠ 0x{CAVE_FILE:05X}"
    print(f"  ↳ Branch target geverifieerd: 0x{decoded_target:05X}")

    # 5. NOP de 4 originele instructies (lsrs/mov/strb/strb = 8 bytes)
    nop4 = bytes([0xBF, 0x00]) * 4   # 4 × NOP
    old_strb = bytes(data[SL_STRB_FILE:SL_STRB_FILE + 8])
    data[SL_STRB_FILE:SL_STRB_FILE + 8] = nop4
    print(f"✓ NOP×4 geschreven op 0x{SL_STRB_FILE:05X}: {old_strb.hex(' ')} → {nop4.hex(' ')}")

    # 6. Optioneel: button toggle hook
    if enable_button_hook:
        btn_cave_file = CAVE_FILE + len(SPEED_CAVE)   # = 0x0E3EC
        data[btn_cave_file:btn_cave_file + len(BTN_CAVE)] = BTN_CAVE
        print(f"\n✓ Button cave geschreven op 0x{btn_cave_file:05X}")

        # Vervang CMP r7, #0x54 + BEQ bij 0x07258 met BL btn_cave
        old_btn = bytes(data[BTN_HOOK_FILE:BTN_HOOK_FILE + 4])
        new_btn_bl = encode_bl(BTN_HOOK_FILE, btn_cave_file)
        data[BTN_HOOK_FILE:BTN_HOOK_FILE + 4] = new_btn_bl
        print(f"✓ Button BL: 0x{BTN_HOOK_FILE:05X}: {old_btn.hex(' ')} → {new_btn_bl.hex(' ')}")
        print(f"  ↳ Actief bij r6==3 (long press DOWN?) + terugkeer naar 0x0725C")
    else:
        print(f"\n⚠  Button hook NIET geactiveerd (enable_button_hook=False)")
        print(f"   Zet enable_button_hook=True of schrijf handmatig naar GPREGRET:")
        print(f"   - GPREGRET adres: 0x{GPREGRET_ADDR:08X}")
        print(f"   - 0x00 = STREET LEGAL (25 km/h, standaard na power-on)")
        print(f"   - 0x01 = PRIVÉ TERREIN (40 km/h)")
        print(f"   - Button toggle cave staat klaar op: 0x{CAVE_FILE + len(SPEED_CAVE):05X}")
        print(f"   - Hook locatie (BEQ r6==3): 0x{BTN_HOOK_FILE:05X}")

    # 7. Sla op
    OUTPUT_BIN.write_bytes(data)
    print(f"\n✓ Gepatchte firmware opgeslagen: {OUTPUT_BIN}")
    print(f"  CRC na patch: {sum(data) & 0xFFFF:#06X}")

    return data


# ──────────────────────────────────────────────────
# Verificatie van patch correctheid
# ──────────────────────────────────────────────────
def verify_patch(data):
    ok = True

    # Check cave inhoud
    cave_code = bytes(data[CAVE_FILE:CAVE_FILE + len(SPEED_CAVE)])
    if cave_code != SPEED_CAVE:
        print("FOUT: Cave code incorrect!")
        ok = False
    else:
        print("✓ Cave code geverifieerd")

    # Check NOP's
    nops = bytes(data[SL_STRB_FILE:SL_STRB_FILE + 8])
    if nops != bytes([0xBF, 0x00]) * 4:
        print("FOUT: NOP's niet correct!")
        ok = False
    else:
        print("✓ NOP×4 blok geverifieerd")

    # Check BL trampoline
    tgt = decode_bl_target(data, SL_BL_FILE)
    if tgt != CAVE_FILE:
        print(f"FOUT: BL target {tgt:#07x} ≠ {CAVE_FILE:#07x}")
        ok = False
    else:
        print(f"✓ BL trampoline target correct: 0x{tgt:05X}")

    # Check dat originele 0x1F 0x03 NIET meer op deze positie staat
    rpm25_bytes = bytes(data[SL_STRB_FILE:SL_STRB_FILE + 2])
    if rpm25_bytes == bytes([0x01, 0x0A]):
        print("FOUT: Origineel LSRS patroon nog aanwezig!")
        ok = False

    # Check literals in cave
    gpregret_in_cave = struct.unpack_from('<I', data, CAVE_FILE + 0x18)[0]
    rpm25_in_cave    = struct.unpack_from('<I', data, CAVE_FILE + 0x1C)[0]
    rpm40_in_cave    = struct.unpack_from('<I', data, CAVE_FILE + 0x20)[0]

    assert gpregret_in_cave == GPREGRET_ADDR, f"GPREGRET literal fout: {gpregret_in_cave:#010x}"
    assert rpm25_in_cave    == RPM_25KMH,     f"RPM_25 literal fout: {rpm25_in_cave:#06x}"
    assert rpm40_in_cave    == RPM_40KMH,     f"RPM_40 literal fout: {rpm40_in_cave:#06x}"
    print("✓ Cave literals correct (GPREGRET, RPM_25, RPM_40)")

    return ok


# ──────────────────────────────────────────────────
# Rapportage
# ──────────────────────────────────────────────────
def print_report(data):
    print("\n" + "=" * 65)
    print("TENWAYS FIRMWARE ANALYSE RAPPORT")
    print("=" * 65)

    print(f"""
GEVONDEN: Speed-limit setter
─────────────────────────────
Bestandsoffset BL get_max_RPM : 0x{SL_BL_FILE:05X}
Code-adres (flash)            : 0x{BASE_ADDR + SL_BL_FILE:08X}
Originele BL instructie bytes : {bytes([0xF5,0xF7,0xF5,0xFE]).hex(' ')}

Assembly sequence (origineel):
  0x{SL_BL_FILE:05X} (0x{BASE_ADDR+SL_BL_FILE:08X}): F5 F7 F5 FE  →  BL get_max_RPM
  0x{SL_STRB_FILE:05X} (0x{BASE_ADDR+SL_STRB_FILE:08X}): 01 0A        →  LSRS r1, r0, #8
  0x{SL_STRB_FILE+2:05X} (0x{BASE_ADDR+SL_STRB_FILE+2:08X}): 6A 46        →  MOV r2, sp
  0x{SL_STRB_FILE+4:05X} (0x{BASE_ADDR+SL_STRB_FILE+4:08X}): 11 70        →  STRB r1, [r2, #0]  ← HIGH BYTE
  0x{SL_STRB_FILE+6:05X} (0x{BASE_ADDR+SL_STRB_FILE+6:08X}): 50 70        →  STRB r0, [r2, #1]  ← LOW BYTE

Hex dump context (±16 bytes):""")

    ctx_start = SL_BL_FILE - 8
    for i in range(ctx_start, SL_BL_FILE + 16, 4):
        mark = " ←← GEPATCHT" if SL_BL_FILE <= i < SL_BL_FILE + 4 else \
               " ←← NOP×2"   if SL_STRB_FILE <= i < SL_STRB_FILE + 8 else ""
        chunk = data[i:i+4]
        print(f"  0x{i:05X}: {chunk.hex(' ')}{mark}")

    print(f"""
PATCH PLAN (TOEGEPAST):
────────────────────────
  BL trampoline   : 0x{SL_BL_FILE:05X} → {encode_bl(SL_BL_FILE, CAVE_FILE).hex(' ')}
  NOP×4           : 0x{SL_STRB_FILE:05X}–0x{SL_STRB_FILE+7:05X}

SPEED CAVE  @ 0x{CAVE_FILE:05X} (code-adres 0x{CAVE_ADDR:08X}):
────────────────────────────────────────────────────────────────
  +0x00: 05 4A  →  LDR r2, [pc, #20]    ; GPREGRET adres laden
  +0x02: 13 78  →  LDRB r3, [r2, #0]    ; mode lezen (RAM)
  +0x04: 00 2B  →  CMP r3, #0
  +0x06: 01 D0  →  BEQ → mode_25        ; 0=25 km/h
  +0x08: 05 48  →  LDR r0, [pc, #20]    ; mode_40: RPM 306
  +0x0A: 00 E0  →  B   → common
  +0x0C: 03 48  →  LDR r0, [pc, #12]    ; mode_25: RPM 799
  +0x0E: 01 0A  →  LSRS r1, r0, #8
  +0x10: 6A 46  →  MOV r2, sp
  +0x12: 11 70  →  STRB r1, [r2, #0]
  +0x14: 50 70  →  STRB r0, [r2, #1]
  +0x16: 70 47  →  BX LR
  +0x18: {struct.pack('<I', GPREGRET_ADDR).hex(' ')}  →  .word 0x{GPREGRET_ADDR:08X} (GPREGRET)
  +0x1C: {struct.pack('<I', RPM_25KMH).hex(' ')}        →  .word 0x{RPM_25KMH:04X} (RPM 799 = 25 km/h)
  +0x20: {struct.pack('<I', RPM_40KMH).hex(' ')}        →  .word 0x{RPM_40KMH:04X} (RPM 306 = 40 km/h)

MODUS DETAILS:
──────────────
  STREET LEGAL  (25 km/h) : RPM 799 = 0x031F  bytes: 1F 03
  PRIVÉ TERREIN (40 km/h) : RPM 306 = 0x0132  bytes: 32 01

RUNTIME TOGGLE (GPREGRET @ 0x{GPREGRET_ADDR:08X}):
──────────────────────────────────────────────────────
  Schrijf 0x00 → 25 km/h actief (standaard na power-on, GPREGRET=0)
  Schrijf 0x01 → 40 km/h actief

BUTTON HANDLER:
──────────────────────────────────────────────────────
  Functie start     : 0x{BASE_ADDR+0x07080:08X}  (file: 0x07080)
  CMP r6, #3        : 0x{BASE_ADDR+0x07234:08X}  (file: 0x07234)
  BEQ-target        : 0x{BASE_ADDR+0x07258:08X}  (file: {BTN_HOOK_FILE:#07x})
  Button cave klaar : 0x{CAVE_ADDR+len(SPEED_CAVE):08X}  (file: {CAVE_FILE+len(SPEED_CAVE):#07x})

  → Vervang 4 bytes op 0x{BTN_HOOK_FILE:05X} met BL naar button cave
    om mode te togellen bij r6==3 (vermoedelijk DOWN long press).
    Gebruik Ghidra op het originele binaire bestand voor bevestiging.

ALS JE VASTLOOPT:
─────────────────
  1. Ghidra: https://ghidra-sre.org/
  2. Gids:   https://suffix-trie.github.io
  3. ARM Cortex-M Little Endian, base 0x{BASE_ADDR:08X}
  4. Zoek scalar 0x1F → 0x031F voor speed limiter locaties
""")


# ──────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────
if __name__ == "__main__":
    btn_hook = "--button" in sys.argv
    print(f"Tenways SW102 Dual-Mode Patch  (button hook: {'AAN' if btn_hook else 'UIT'})\n")

    patched = apply_patch(enable_button_hook=btn_hook)
    print()
    ok = verify_patch(patched)
    print()
    print_report(patched)

    if ok:
        print("✓ PATCH SUCCESVOL – gebruik sw102_dualmode.bin voor DFU flash")
    else:
        print("✗ PATCH MISLUKT – controleer foutmeldingen hierboven")
        sys.exit(1)
