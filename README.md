# T626 Pro & T625 Pro Superadmin Password Decoder & Unlocker

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://www.python.org/)
[![PowerShell 5.1/7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Web Tool](https://img.shields.io/badge/Web%20App-t3unlock.alyciax.top-orange.svg)](https://t3unlock.alyciax.top)
[![100% Offline](https://img.shields.io/badge/Security-100%25%20Offline-success.svg)](SECURITY.md)

Offline decoder, credential extractor, and privilege unlocker for Wi-Fi 6 GPON ONT routers:
- **T626 Pro & T626 Pro V2** (`romfile.cfg`)
- **T625 Pro** (`bfwcfg.dt`)

Extracts the router's dynamic **`superadmin`** password, standard **`admin`** password, **WAN PPPoE credentials**, and **Wi-Fi keys** without requiring UART serial soldering, root exploits, or sending sensitive backup files to third parties. For the T625 Pro, it also generates an **unlocked restore configuration** to permanently enable `superadmin` and Telnet access.

> 🌐 **No Installation Web Version:** You can also decode and unlock directly in your web browser with zero installation at **[t3unlock.alyciax.top](https://t3unlock.alyciax.top)** (100% client-side via Web Crypto API — your files never leave your machine).

<p align="center">
  <img src="Router%20FW.png" alt="Router Device & Firmware Information" width="550"/>
</p>

---

## 📋 Supported Hardware & Capabilities

| Feature / Model | **T626 Pro / V2** | **T625 Pro** |
| :--- | :--- | :--- |
| **Target Hardware** | T626 Pro & T626 Pro V2 (Wi-Fi 6 AX3000 GPON ONT) | T625 Pro (Wi-Fi 6 AX3000 GPON ONT) |
| **Firmware Base** | ARM Linux (`/lib/libcfg_clisvc.so`) | OpenWrt Embedded Linux (`/ptrom/bin/cfgutil`) |
| **Configuration Backup File** | `romfile.cfg` | `bfwcfg.dt` |
| **Encryption Algorithm** | 6-Byte Stride Inversion & Modulo XOR + Scrambled Base64 | Stream XOR `0x68` + 40-Byte Header (Magic `37249126` + MD5) |
| **Decrypted Format** | XML (`<ROMFILE> ... </ROMFILE>`) | `.tar.gz` archive containing 5 UCI config files |
| **Extracted Credentials** | `superadmin`, `admin`, WAN PPPoE (`@fiberhome`), Device S/N | `superadmin`, `admin`, WAN PPPoE, Wi-Fi SSIDs & PSKs, S/N |
| **Permanent Privilege Unlock** | Read-only credential extraction | ✅ Generates `unlocked_bfwcfg.dt` (Enables Telnet & Superadmin) |
| **Web Browser Support** | Supported on [t3unlock.alyciax.top](https://t3unlock.alyciax.top) | Supported on [t3unlock.alyciax.top](https://t3unlock.alyciax.top) |

---

## 📌 Why This Tool Is Needed

ISP routers are provisioned with a dynamic, randomized `superadmin` password during initial TR-069 registration. The standard `admin` account printed on the router label is strictly restricted from critical administrative capabilities:

- **Bridge Mode Configuration:** Switching the ONT into transparent Layer 2 bridge mode so you can use your own high-performance gateway (e.g. OpenWrt, Flint 3, pfSense, OPNsense).
- **VLAN Binding & Port Mapping:** Mapping GPON WAN VLANs (`VLAN 100` / `VLAN 101`) directly to specific LAN Ethernet ports.
- **TR-069 ACS Settings:** Inspecting or modifying remote management and provisioning endpoints.
- **SIP / VoIP Line Configuration:** Extracting or adjusting voice/telephony profiles.
- **Telnet / Local Shell Access:** Gaining local maintenance and diagnostic access.

When you download your backup file via the web interface (`Admin -> Backup/Restore`), the router produces an obfuscated binary file (`romfile.cfg` or `bfwcfg.dt`). This repository reverses that obfuscation completely offline in milliseconds.

<p align="center">
  <img src="routerpageexample.png" alt="Router Web Interface Backup Page" width="550"/>
</p>

---

## 📁 Repository Structure

```text
├── T625 pro/
│   ├── Superadmin.bat          # 1-Click Drag & Drop decoder and unlock builder
│   ├── decode_t625pro.ps1      # Native PowerShell decoder & unlock builder
│   └── decode_t625pro.py       # Cross-platform Python 3 decoder & unlock builder
├── T626 pro/
│   ├── Superadmin.bat          # 1-Click Drag & Drop credential extractor
│   ├── decode_t626pro.ps1      # Native PowerShell credential extractor
│   └── decode_t626pro.py       # Cross-platform Python 3 credential extractor
├── Router FW.png               # Hardware info reference image
├── routerpageexample.png       # Web GUI backup tab reference image
├── example.png                 # CLI output reference image
├── SECURITY.md                 # Security & offline privacy policy
└── LICENSE                     # MIT License
```

---

## 🚀 Step-by-Step Guide

### Step 1: Download Configuration Backup from Your Router

1. Connect your computer to the router via Ethernet cable or Wi-Fi.
2. Open your browser and navigate to `http://192.168.1.1` (or your router's default IP).
3. Log in with the standard `admin` credentials printed on the router sticker.
4. Go to **Admin** -> **Backup / Restore** (or **Maintenance** -> **Backup Configuration**).
5. Click **Backup Configuration** to download your encrypted backup file:
   - For **T626 Pro / V2**: Saves as `romfile.cfg`.
   - For **T625 Pro**: Saves as `bfwcfg.dt`.

---

### Step 2: Decode & Extract Credentials

#### Method 1: Windows 1-Click Drag & Drop (Easiest)

https://github.com/user-attachments/assets/70e3203a-9aaf-4dee-a6a2-ae90b473c59c

- **For T626 Pro:**
  1. Open the [`T626 pro`](T626%20pro/) folder.
  2. Drag and drop your `romfile.cfg` file directly onto [`Superadmin.bat`](T626%20pro/Superadmin.bat).
  3. The console immediately prints your `superadmin` and `admin` passwords.
- **For T625 Pro:**
  1. Open the [`T625 pro`](T625%20pro/) folder.
  2. Drag and drop your `bfwcfg.dt` file directly onto [`Superadmin.bat`](T625%20pro/Superadmin.bat).
  3. The console prints all credentials and automatically generates `unlocked_bfwcfg.dt` in the same directory.

---

#### Method 2: Native PowerShell (No Installation Required)

Open PowerShell inside the repository folder:

* **T626 Pro (`romfile.cfg`):**
  ```powershell
  cd "T626 pro"
  .\decode_t626pro.ps1 -Path "C:\path\to\romfile.cfg"
  
  # Optional: Export the cleartext decrypted XML
  .\decode_t626pro.ps1 -Path "romfile.cfg" -OutputXml "decoded_config.xml"
  ```

* **T625 Pro (`bfwcfg.dt`):**
  ```powershell
  cd "T625 pro"
  .\decode_t625pro.ps1 -Path "C:\path\to\bfwcfg.dt"
  
  # Optional: Specify a custom superadmin password for the unlocked restore file
  .\decode_t625pro.ps1 -Path "bfwcfg.dt" -CustomPassword "xxxxxxxxxx"
  ```

---

#### Method 3: Cross-Platform Python 3 (Windows, macOS, Linux)

Requires standard Python 3.8+ with no external pip dependencies:

* **T626 Pro:**
  ```bash
  python "T626 pro/decode_t626pro.py" romfile.cfg

  # Optional: Save decrypted XML
  python "T626 pro/decode_t626pro.py" romfile.cfg -o romfile_decrypted.xml
  ```

* **T625 Pro:**
  ```bash
  python "T625 pro/decode_t625pro.py" bfwcfg.dt

  # Optional: Extract raw UCI config files and specify custom superadmin password
  python "T625 pro/decode_t625pro.py" bfwcfg.dt --extract ./uci_configs --password "xxxxxxxxxx"
  ```

---

#### Method 4: Browser Web Application (Zero Installation)

Visit **[https://t3unlock.alyciax.top](https://t3unlock.alyciax.top)** in any modern browser. Drop either `romfile.cfg` or `bfwcfg.dt`. The Web Crypto engine instantly decodes your credentials locally on your device.

---

## 🔓 How to Permanently Unlock T625 Pro (Superadmin & Telnet)

The T625 Pro decoder scripts (`decode_t625pro.py` / `decode_t625pro.ps1`) automatically generate a modified restore file named `unlocked_bfwcfg.dt`. This unlocks root-level functionality through the router's own restore mechanism:

1. Log into your router's Web GUI at `http://192.168.1.1` with the standard `admin` account.
2. Navigate to **Admin** -> **Backup / Restore**.
3. Under **Restore Configuration**, click **Choose File** and select `unlocked_bfwcfg.dt`.
4. Click **Restore Configuration**.
5. The router verifies the MD5 header, unpacks the modified UCI configurations, and automatically reboots.
6. Once rebooted:
   - **Web Superadmin:** Username `superadmin` with the password shown during decode (or your custom password).
   - **Telnet Service:** Port 23 is permanently enabled. Connect via `telnet 192.168.1.1`.
   - **TeleComAccount:** Full administrative menu options are permanently unlocked in the web interface.

---

## 🖥️ Example Console Outputs

### T626 Pro Output Example
<p align="center">
  <img src="example.png" alt="T626 Pro Output Example" width="550"/>
</p>

```text
[*] Reading and decoding: romfile.cfg ...

==================================================
             WEB LOGIN CREDENTIALS
==================================================
  [SUPERADMIN] User: superadmin   Pass: xxxxxxxxxx
  [USER      ] User: admin        Pass: yyyyyyyyyy

  [WAN PPPoE Credentials]
    Username: xxxxxxxxx@fiberhome
    Password: ••••••••••••

  [Device Info]
    SerialNumber    : xxxxxxxxxxxxxx
    SoftwareVersion : V1.0.0.5
    HardwareVersion : V1.0
==================================================
```

### T625 Pro Output Example
```text
[*] Decoding: bfwcfg.dt ...
[+] Magic prefix '37249126' verified.
[+] MD5 checksum verified: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[+] Successfully extracted configuration archive (5 files).

=======================================================
            T625 PRO WEB CREDENTIALS
=======================================================
  [TeleComAccount         ] User: superadmin   Pass: xxxxxxxxxx
  [NormalAccount          ] User: admin        Pass: yyyyyyyyyy

  [WAN PPPoE Credentials]
    Username: xxxxxxxxx@fiberhome
    Password: ••••••••••••

  [Wi-Fi Configurations]
    SSID: Wi-Fi_2.4G               Key: xxxxxxxxxx
    SSID: Wi-Fi_5G                 Key: xxxxxxxxxx

  [Device Info]
    Hardware Version        : V1.0.0
    Software Version        : V1.0.12
=======================================================

[*] Generating unlocked router restore file: unlocked_bfwcfg.dt ...
[+] SUCCESS! Unlocked file created: unlocked_bfwcfg.dt
    - Superadmin Account: superadmin (Active)
    - Telnet Service    : ENABLED (Port 23)
    - TeleComAccount    : ENABLED
```

---

## 🔬 Reverse Engineering & Cryptographic Analysis

<details>
<summary><b>▶ Click to expand: T626 Pro Cryptographic Analysis & Deobfuscation Logic (romfile.cfg)</b></summary>

<br>

Disassembly of `/lib/libcfg_clisvc.so` (offsets `0x5af20` – `0x5b0c0`) and `/usr/bin/backuprestorecmd` reveals a two-stage obfuscation pipeline:

```
[romfile.cfg] ──► (1. 6-Byte Stride XOR & Inversion) ──► (2. Scrambled Base64 Translation) ──► (3. Base64 Decode) ──► [XML Configuration]
```

<details>
<summary><b>1. 6-Byte Stride Inversion & Modulo XOR Algorithm (Click to expand)</b></summary>

The file is traversed in 6-byte blocks (`r1 += 6`). Modulo conditions apply bitwise XOR and complement inversions (`~`):

```python
while r1 < len(buf):
    if r1 % 9 == 0:
        buf[r1]     = (~(buf[r1]     ^ 0x75)) & 0xFF
        buf[r1 + 1] = (~(buf[r1 + 1] ^ 0x7B)) & 0xFF
        buf[r1 + 3] = (~(buf[r1 + 3] ^ 0x77)) & 0xFF
    elif r1 % 12 == 0:
        buf[r1]     = (~(buf[r1]     ^ 0x53)) & 0xFF
        buf[r1 + 1] = (~(buf[r1 + 1] ^ 0x77)) & 0xFF
        buf[r1 + 3] = (~(buf[r1 + 3] ^ 0x5B)) & 0xFF
    r1 += 6
```
</details>

<details>
<summary><b>2. Proprietary Base64 Substitution Cipher Table (Click to expand)</b></summary>

The inverted stream represents ASCII characters mapped from a non-standard 64-character alphabet:

| Alphabet | Character Sequence |
| :--- | :--- |
| **Firmware Custom Table** | `edcbaZYXWVUTSRQPONMLKJIHGFEDCBA+9876543210zyxwvutsrqponmlkjihgf/` |
| **Standard RFC 4648** | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` |

Translating each custom character to RFC 4648 and performing standard Base64 decoding produces the cleartext XML configuration (`<ROMFILE> ... </ROMFILE>`).
</details>

<details>
<summary><b>3. XML Credential Nodes (Click to expand)</b></summary>

Web login credentials reside inside the `<Account>` XML node:
```xml
<Account>
    <Entry0 username="superadmin" web_passwd="..." ... />
    <Entry1 username="admin" web_passwd="..." ... />
</Account>
```
</details>

</details>

---

<details>
<summary><b>▶ Click to expand: T625 Pro Cryptographic Analysis & Deobfuscation Logic (bfwcfg.dt)</b></summary>

<br>

Reverse-engineering `/ptrom/bin/cfgutil` and `/usr/bin/backuprestorecmd` from the firmware reveals the file format:

```
[40-Byte Header (XOR 0x68)] + [.tar.gz Archive Payload (XOR 0x68)]
```

<details>
<summary><b>1. 40-Byte Header & Integrity Check (Click to expand)</b></summary>

- **Bytes `0..7`:** Magic string `37249126` XORed with `0x68`.
- **Bytes `8..39`:** 32-character lowercase hex MD5 checksum of the unencrypted `.tar.gz` archive, XORed with `0x68`.
</details>

<details>
<summary><b>2. XOR Stream Decryption & Tarball Extraction (Click to expand)</b></summary>

- Every byte of the payload is XORed with static byte `0x68` (ASCII `'h'`).
- Decrypting yields a valid Gzip compressed Tar archive containing 5 OpenWrt UCI configuration files:
  - `usrconfig_conf`: User credentials and privilege level flags (`normal_user`, `telecom_user`).
  - `attrconfig_conf`: Feature toggles, Telnet enable/disable (`telnetd.enable='1'`), firewall rules.
  - `sysinfo_conf`: Device model, serial number, and firmware version.
  - `tr069_control_conf`: Remote ACS endpoints and credentials.
  - `voice_digitmap_conf`: VoIP and SIP configurations.
</details>

<details>
<summary><b>3. Re-Packaging & Checksum Builder for Permanent Unlock (Click to expand)</b></summary>

To produce `unlocked_bfwcfg.dt`, the unlock engine modifies `usrconfig_conf` and `attrconfig_conf`, recalculates the gzip archive, hashes the payload with MD5, builds the 40-byte header, and re-encrypts the entire file with XOR `0x68`:

```python
# Unpack -> Modify UCI files -> Re-gzip -> Compute MD5 -> Prepend Header -> XOR 0x68
payload_tar = create_tar_gz(modified_files)
payload_md5 = hashlib.md5(payload_tar).hexdigest().lower().encode('ascii')
header = xor_bytes(b"37249126" + payload_md5, 0x68)
encrypted_payload = xor_bytes(payload_tar, 0x68)
unlocked_data = header + encrypted_payload
```
</details>

</details>

---

## 📚 Credits & Acknowledgements

1. **[Blinko1987](https://github.com/Blinko1987)**
   - Author of [True-Fiber-T626Pro-V1.0.0.5-Firmware](https://github.com/Blinko1987/True-Fiber-T626Pro-V1.0.0.5-Firmware). Provided the initial firmware dump, documented UART pinouts, and factory credentials.
2. **[UBNT Thailand Community](https://www.facebook.com/ubntthailand)**
   - Router configuration research and test files across various router revisions.
3. **Community Contributors**
   - Everyone testing and reporting hardware revisions.

---

## ⚖️ License & Disclaimer

Distributed under the [MIT License](LICENSE). 

*This tool is intended for personal homelab administration, network optimization (enabling Bridge Mode), and educational research only. Please maintain backups of your original configuration files before performing any restore operations.*
