#!/usr/bin/env python3
"""
True Router T625 Pro bfwcfg.dt Decoder & Superadmin Enabler
Reverse-engineered from T3 Technology T625 Pro firmware (/ptrom/bin/cfgutil).

Algorithm:
- 40-byte header: "37249126" + MD5(tar.gz payload) XORed with 0x68
- Payload: tar.gz archive of UCI configuration files XORed with 0x68
"""

import argparse
import base64
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile

MAGIC_PREFIX = "37249126"
XOR_KEY = 0x68

def xor_bytes(data: bytes, key: int = XOR_KEY) -> bytes:
    return bytes(b ^ key for b in data)

def decode_bfwcfg(file_path: str, extract_dir: str = None) -> dict:
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        raw_data = f.read()

    if len(raw_data) < 40:
        raise ValueError("File is too short to be a valid bfwcfg.dt (minimum 40 bytes)")

    # 1. Decode header
    hdr_raw = raw_data[:40]
    hdr_dec = xor_bytes(hdr_raw).decode("ascii", errors="replace")

    prefix = hdr_dec[:8]
    expected_md5 = hdr_dec[8:40]

    if prefix != MAGIC_PREFIX:
        raise ValueError(f"Invalid magic prefix '{prefix}' (expected '{MAGIC_PREFIX}'). Is this a valid T625 bfwcfg.dt?")

    # 2. Decode payload (tar.gz)
    payload_enc = raw_data[40:]
    payload_targz = xor_bytes(payload_enc)

    # 3. Verify MD5
    calc_md5 = hashlib.md5(payload_targz).hexdigest()
    if calc_md5.lower() != expected_md5.lower():
        raise ValueError(f"MD5 checksum mismatch! Expected: {expected_md5}, Calculated: {calc_md5}")

    # 4. Decompress gzip and inspect tarball
    decompressed_tar = gzip.decompress(payload_targz)
    tar = tarfile.open(fileobj=io.BytesIO(decompressed_tar))

    extracted_files = {}
    for member in tar.getmembers():
        f = tar.extractfile(member)
        if f:
            extracted_files[member.name] = f.read()

    if extract_dir:
        os.makedirs(extract_dir, exist_ok=True)
        for name, data in extracted_files.items():
            out_file = os.path.join(extract_dir, name)
            with open(out_file, "wb") as out_f:
                out_f.write(data)

    # 5. Parse configuration details from usrconfig_conf and sysinfo_conf
    info = parse_config(extracted_files)
    info["md5"] = calc_md5
    info["files"] = extracted_files
    info["raw_targz"] = payload_targz
    return info

def parse_config(files: dict) -> dict:
    res = {
        "accounts": [],
        "wifi": [],
        "wan": {},
        "sysinfo": {}
    }

    # Parse sysinfo_conf
    if "sysinfo_conf" in files:
        sys_text = files["sysinfo_conf"].decode("utf-8", errors="replace")
        for m in re.finditer(r"config key '([^']+)'\s+option value '([^']+)'", sys_text):
            res["sysinfo"][m.group(1)] = m.group(2)

    # Parse usrconfig_conf
    if "usrconfig_conf" in files:
        usr_text = files["usrconfig_conf"].decode("utf-8", errors="replace")

        # Extract UserList 1 (superadmin)
        # config interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__'
        m_ul1 = re.search(
            r"config interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__'(.*?)(?=config interface|\Z)",
            usr_text, re.DOTALL
        )
        if m_ul1:
            block = m_ul1.group(1)
            pwd_m = re.search(r"option Password '([^']+)'", block)
            usr_m = re.search(r"option Username '([^']+)'", block)
            pwd_raw = pwd_m.group(1) if pwd_m else ""
            pwd_clear = b64_decode_safe(pwd_raw)
            user = b64_decode_safe(usr_m.group(1)) if usr_m else "superadmin"
            res["accounts"].append({
                "role": "SUPERADMIN (UserList 1)",
                "username": user or "superadmin",
                "password": pwd_clear or pwd_raw,
                "password_b64": pwd_raw
            })

        # Extract UserList 2 (admin)
        m_ul2 = re.search(
            r"config interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__2__'(.*?)(?=config interface|\Z)",
            usr_text, re.DOTALL
        )
        if m_ul2:
            block = m_ul2.group(1)
            pwd_m = re.search(r"option Password '([^']+)'", block)
            usr_m = re.search(r"option Username '([^']+)'", block)
            pwd_raw = pwd_m.group(1) if pwd_m else ""
            pwd_clear = b64_decode_safe(pwd_raw)
            user = b64_decode_safe(usr_m.group(1)) if usr_m else "admin"
            res["accounts"].append({
                "role": "USER (UserList 2)",
                "username": user or "admin",
                "password": pwd_clear or pwd_raw,
                "password_b64": pwd_raw
            })
        else:
            res["accounts"].append({
                "role": "USER (UserList 2)",
                "username": "admin",
                "password": "(Printed on bottom router sticker - Factory Default)",
                "password_b64": ""
            })

        # Check TeleComAccount
        m_telecom = re.search(
            r"config interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_TeleComAccount__'(.*?)(?=config interface|\Z)",
            usr_text, re.DOTALL
        )
        if m_telecom:
            block = m_telecom.group(1)
            en_m = re.search(r"option Enable '([^']+)'", block)
            pwd_m = re.search(r"option Password '([^']+)'", block)
            name_m = re.search(r"option Name '([^']+)'", block)
            res["telecom_account"] = {
                "enabled": en_m.group(1) if en_m else "0",
                "username": name_m.group(1) if name_m else "superadmin",
                "password": pwd_m.group(1) if pwd_m else ""
            }

        # Check TelnetEnable
        m_service = re.search(
            r"config interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_ServiceManage__'(.*?)(?=config interface|\Z)",
            usr_text, re.DOTALL
        )
        if m_service:
            block = m_service.group(1)
            telnet_m = re.search(r"option TelnetEnable '([^']+)'", block)
            res["telnet_enabled"] = telnet_m.group(1) if telnet_m else "0"

        # WAN PPPoE credentials
        m_wan = re.search(
            r"config interface 'InternetGatewayDevice__WANDevice__1__WANConnectionDevice__1__WANPPPConnection__1__'(.*?)(?=config interface|\Z)",
            usr_text, re.DOTALL
        )
        if m_wan:
            block = m_wan.group(1)
            usr_m = re.search(r"option Username '([^']+)'", block)
            pwd_m = re.search(r"option Password '([^']+)'", block)
            if usr_m:
                res["wan"]["username"] = b64_decode_safe(usr_m.group(1))
            if pwd_m:
                res["wan"]["password"] = b64_decode_safe(pwd_m.group(1))

        # Wi-Fi SSIDs & Passwords
        wifi_blocks = re.findall(
            r"config interface '(InternetGatewayDevice__LANDevice__1__WLANConfiguration__\d+__)'(.*?)(?=config interface|\Z)",
            usr_text, re.DOTALL
        )
        for iface, block in wifi_blocks:
            ssid_m = re.search(r"option SSID '([^']+)'", block)
            pwd_m = re.search(r"option (?:PreSharedKey|KeyPassphrase|X_PT_PWD) '([^']+)'", block)
            if ssid_m:
                res["wifi"].append({
                    "interface": iface,
                    "ssid": ssid_m.group(1),
                    "password": pwd_m.group(1) if pwd_m else ""
                })

    return res

def b64_decode_safe(val: str) -> str:
    if not val or val == "UCI_NULL":
        return ""
    try:
        pad = (4 - (len(val) % 4)) % 4
        padded = val + "=" * pad
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        return decoded
    except Exception:
        return val

def unlock_bfwcfg(file_path: str, output_path: str, new_super_pass: str = None) -> str:
    """Decodes bfwcfg.dt, ensures superadmin and telnet are enabled, and re-packages into a valid encrypted bfwcfg.dt."""
    info = decode_bfwcfg(file_path)
    files = info["files"]

    if "usrconfig_conf" not in files:
        raise ValueError("usrconfig_conf not found in backup archive!")

    usr_text = files["usrconfig_conf"].decode("utf-8", errors="replace")

    # 1. Determine superadmin password
    super_pass = new_super_pass
    if not super_pass:
        # Check if existing password in UserList 1
        for acc in info["accounts"]:
            if "superadmin" in acc["role"].lower() and acc["password"]:
                super_pass = acc["password"]
                break
    if not super_pass:
        super_pass = "t4246#5753S@dM1n"  # Firmware factory default

    super_pass_b64 = base64.b64encode(super_pass.encode("utf-8")).decode("ascii")

    # 2. Ensure UserList 1 exists, has username superadmin and password
    userlist_block = (
        "\nconfig interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__'\n"
        "\toption Username 'c3VwZXJhZG1pbg=='\n"
        f"\toption Password '{super_pass_b64}'\n"
    )
    if "InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__" in usr_text:
        usr_text = re.sub(
            r"config interface 'InternetGatewayDevice__X_TRUE_UserInfo__UserList__1__'.*?(?=config interface|\Z)",
            userlist_block.strip() + "\n\n",
            usr_text,
            flags=re.DOTALL
        )
    else:
        usr_text += userlist_block

    # 3. Ensure TeleComAccount is Enabled (both X_CT111COM and X_CT_COM mappings)
    telecom_block = (
        "\nconfig interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_TeleComAccount__'\n"
        "\toption Enable '1'\n"
        "\toption Name 'superadmin'\n"
        f"\toption Password '{super_pass}'\n"
        "\toption X_PT_LoginInterval '180'\n\n"
        "config interface 'InternetGatewayDevice__DeviceInfo__X_CT_COM_TeleComAccount__'\n"
        "\toption Enable '1'\n"
        "\toption Name 'superadmin'\n"
        f"\toption Password '{super_pass}'\n"
    )
    if "InternetGatewayDevice__DeviceInfo__X_CT111COM_TeleComAccount__" in usr_text:
        usr_text = re.sub(
            r"config interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_TeleComAccount__'.*?(?=config interface|\Z)",
            telecom_block.strip() + "\n\n",
            usr_text,
            flags=re.DOTALL
        )
    else:
        usr_text += telecom_block

    # 4. Ensure TelnetEnable is '1' and SuperUser Telnet is '1'
    servicemanage_block = (
        "\nconfig interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_ServiceManage__'\n"
        "\toption TelnetEnable '1'\n"
        "\toption X_PT_SuperUser_TelnetEnable '1'\n"
        "\toption FtpEnable '0'\n"
    )
    if "InternetGatewayDevice__DeviceInfo__X_CT111COM_ServiceManage__" in usr_text:
        usr_text = re.sub(
            r"config interface 'InternetGatewayDevice__DeviceInfo__X_CT111COM_ServiceManage__'.*?(?=config interface|\Z)",
            servicemanage_block.strip() + "\n\n",
            usr_text,
            flags=re.DOTALL
        )
    else:
        usr_text += servicemanage_block

    # Update usrconfig_conf in memory
    files["usrconfig_conf"] = usr_text.encode("utf-8")

    # 5. Build tar archive in memory
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        for name in ["usrconfig_conf", "attrconfig_conf", "sysinfo_conf", "tr069_control_conf", "voice_digitmap_conf"]:
            if name in files:
                data = files[name]
                ti = tarfile.TarInfo(name=name)
                ti.size = len(data)
                ti.mtime = 0
                ti.mode = 0o644
                tar.addfile(ti, io.BytesIO(data))

    tar_bytes = tar_buf.getvalue()

    # 6. Compress with gzip (mtime=0 for deterministic reproducibility)
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    gz_payload = gz_buf.getvalue()

    # 7. Compute MD5 checksum of tar.gz
    calc_md5 = hashlib.md5(gz_payload).hexdigest()

    # 8. Construct 40-byte header: "37249126" + MD5
    header_str = MAGIC_PREFIX + calc_md5
    header_bytes = header_str.encode("ascii")

    # 9. Encrypt header and payload with XOR 0x68
    enc_header = xor_bytes(header_bytes)
    enc_payload = xor_bytes(gz_payload)

    final_dt = enc_header + enc_payload

    with open(output_path, "wb") as out_f:
        out_f.write(final_dt)

    return super_pass

def main():
    parser = argparse.ArgumentParser(
        description="True Router T625 Pro bfwcfg.dt Decoder & Superadmin Enabler"
    )
    parser.add_argument("file", nargs="?", default="bfwcfg.dt", help="Path to bfwcfg.dt (default: bfwcfg.dt)")
    parser.add_argument("-e", "--extract", metavar="DIR", help="Extract raw configuration files to directory")
    parser.add_argument("-u", "--unlock", metavar="OUT_FILE", nargs="?", const="unlocked_bfwcfg.dt",
                        help="Generate unlocked bfwcfg.dt ready for router restore (default: unlocked_bfwcfg.dt)")
    parser.add_argument("-p", "--password", help="Set custom superadmin password when generating unlocked file")

    args = parser.parse_args()

    print(f"[*] Reading and decoding: {args.file} ...")
    try:
        info = decode_bfwcfg(args.file, extract_dir=args.extract)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "=" * 55)
    print("        TRUE ROUTER T625 PRO WEB CREDENTIALS")
    print("=" * 55)

    if info["accounts"]:
        for acc in info["accounts"]:
            print(f"  [{acc['role']:<24}] User: {acc['username']:<12} Pass: {acc['password']}")
    else:
        print("  No custom user accounts found (using firmware defaults).")

    if info["wan"]:
        print("\n  [WAN PPPoE Credentials]")
        print(f"    Username: {info['wan'].get('username', 'N/A')}")
        print(f"    Password: {info['wan'].get('password', 'N/A')}")

    if info["wifi"]:
        print("\n  [Wi-Fi Configurations]")
        for w in info["wifi"]:
            print(f"    SSID: {w['ssid']:<24} Key: {w['password']}")

    if info["sysinfo"]:
        print("\n  [Device Info]")
        for k, v in info["sysinfo"].items():
            print(f"    {k:<24}: {v}")

    print("=" * 55)

    if args.extract:
        print(f"[+] Extracted config files to: {os.path.abspath(args.extract)}")

    # Handle unlock output
    unlock_out = args.unlock
    if not unlock_out:
        # Default behavior: generate unlocked file in same directory as input
        input_dir = os.path.dirname(os.path.abspath(args.file))
        base_name = os.path.basename(args.file)
        if base_name.startswith("unlocked_"):
            unlock_out = None
        else:
            unlock_out = os.path.join(input_dir, f"unlocked_{base_name}")

    if unlock_out:
        print(f"\n[*] Generating unlocked router restore file: {unlock_out} ...")
        try:
            active_pass = unlock_bfwcfg(args.file, unlock_out, new_super_pass=args.password)
            print(f"[+] SUCCESS! Unlocked file created: {unlock_out}")
            print(f"    - Superadmin Account: superadmin")
            print(f"    - Superadmin Password: {active_pass}")
            print(f"    - Telnet Service: ENABLED (Port 23)")
            print(f"    - TeleComAccount: ENABLED")
            print("\n[+] How to restore on router:")
            print("    1. Open router Web GUI (http://192.168.1.1)")
            print("    2. Navigate to Admin -> Backup / Restore")
            print(f"    3. Choose File -> Select '{os.path.basename(unlock_out)}' -> Click Restore")
            print("    4. Router will reboot with full superadmin privileges active!")
        except Exception as e:
            print(f"[-] Error generating unlocked file: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
