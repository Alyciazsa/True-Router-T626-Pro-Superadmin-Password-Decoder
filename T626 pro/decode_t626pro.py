#!/usr/bin/env python3
"""
True Router T626 Pro Superadmin Password Decoder
Extracts superadmin and admin credentials from encrypted romfile.cfg router backups.
"""

import argparse
import base64
import os
import re
import sys

# Scrambled Base64 alphabet extracted from libcfg_clisvc.so
CUSTOM_ALPHA = b"edcbaZYXWVUTSRQPONMLKJIHGFEDCBA+9876543210zyxwvutsrqponmlkjihgf/"
STD_ALPHA    = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
TRANS_TABLE  = bytes.maketrans(CUSTOM_ALPHA, STD_ALPHA)


def decode_romfile(file_path: str) -> str:
    """Reverses the 6-byte stride bitwise inversion and custom Base64 encoding."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        buf = bytearray(f.read())

    r1, r8, r4 = 0, 3, len(buf)
    while r1 < r4:
        if r1 % 9 == 0:
            buf[r1] = (~(buf[r1] ^ 0x75)) & 0xFF
            if r8 < r4:
                buf[r1 + 1] = (~(buf[r1 + 1] ^ 0x7B)) & 0xFF
                buf[r1 + 3] = (~(buf[r1 + 3] ^ 0x77)) & 0xFF
        elif r1 % 12 == 0:
            buf[r1] = (~(buf[r1] ^ 0x53)) & 0xFF
            if r8 < r4:
                buf[r1 + 1] = (~(buf[r1 + 1] ^ 0x77)) & 0xFF
                buf[r1 + 3] = (~(buf[r1 + 3] ^ 0x5B)) & 0xFF
        r1 += 6
        r8 += 6

    # Translate custom Base64 to standard Base64
    b64_str = bytes(buf).translate(TRANS_TABLE)
    pad = (4 - len(b64_str) % 4) % 4
    b64_str += b"=" * pad

    return base64.b64decode(b64_str).decode("latin-1", errors="replace")


def main():
    parser = argparse.ArgumentParser(
        description="Decode True Router T626 Pro romfile.cfg backup and extract superadmin password"
    )
    parser.add_argument(
        "romfile",
        nargs="?",
        default="romfile.cfg",
        help="Path to romfile.cfg (default: romfile.cfg in current directory)",
    )
    parser.add_argument(
        "-o", "--output", help="Save decrypted XML configuration to file (optional)"
    )
    args = parser.parse_args()

    print(f"[*] Reading and decoding: {args.romfile} ...")
    try:
        xml_data = decode_romfile(args.romfile)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(xml_data)
        print(f"[+] Saved full XML to: {args.output}")

    print("\n" + "=" * 50)
    print("             WEB LOGIN CREDENTIALS")
    print("=" * 50)

    pattern = r'<Entry[01]\s+[^>]*username="([^"]+)"[^>]*web_passwd="([^"]+)"'
    matches = re.findall(pattern, xml_data)

    if matches:
        for user, pwd in matches:
            tag = "SUPERADMIN" if user == "superadmin" else "USER"
            print(f"  [{tag:<10}] User: {user:<12} Pass: {pwd}")
    else:
        print("  No web login entries found in decoded file.")

    # WAN PPPoE Credentials
    pvc_m = re.search(r'<(?:PVC\d+|Entry\d+)[^>]*USERNAME="([^"]+@fiberhome)"[^>]*PASSWORD="([^"]+)"', xml_data, re.I) or \
            re.search(r'<(?:PVC\d+|Entry\d+)[^>]*PASSWORD="([^"]+)"[^>]*USERNAME="([^"]+@fiberhome)"', xml_data, re.I)
    if pvc_m:
        user = pvc_m.group(1) if "@" in pvc_m.group(1) else pvc_m.group(2)
        pwd = pvc_m.group(2) if "@" in pvc_m.group(1) else pvc_m.group(1)
        print("\n  [WAN PPPoE Credentials]")
        print(f"    Username: {user}")
        print(f"    Password: {pwd}")
    else:
        tr_m = re.search(r'<Entry\d+[^>]*Username="([^"]+@fiberhome)"[^>]*Password="([^"]+)"', xml_data, re.I)
        if tr_m:
            print("\n  [WAN PPPoE Credentials]")
            print(f"    Username: {tr_m.group(1)}")
            print(f"    Password: {tr_m.group(2)}")

    # Device Info
    sn = re.search(r'SerialNumber="([^"]+)"', xml_data, re.I)
    sw = re.search(r'SoftwareVersion="([^"]+)"', xml_data, re.I)
    hw = re.search(r'HardwareVersion="([^"]+)"', xml_data, re.I)
    if sn or sw or hw:
        print("\n  [Device Info]")
        if sn: print(f"    SerialNumber    : {sn.group(1)}")
        if sw: print(f"    SoftwareVersion : {sw.group(1)}")
        if hw: print(f"    HardwareVersion : {hw.group(1)}")

    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
