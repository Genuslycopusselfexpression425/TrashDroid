# Android DAST - Automated VAPT Framework

A terminal-based automation framework for performing Dynamic Application Security Testing (DAST) against Android applications. It orchestrates `adb`, `drozer`, `scrcpy`, `apktool`, and `sqlite3` to execute a full 9-phase security assessment, capture screenshots after every test, and produce an AI-ready Markdown report.

---

## Table of Contents

- [Android DAST - Automated VAPT Framework](#android-dast---automated-vapt-framework)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Architecture](#architecture)
  - [Prerequisites](#prerequisites)
    - [Host machine](#host-machine)
    - [Target device](#target-device)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Interactive Mode](#interactive-mode)
    - [Non-Interactive / Auto Mode](#non-interactive--auto-mode)
    - [Selective Phases](#selective-phases)
    - [All CLI Arguments](#all-cli-arguments)
  - [Test Phases](#test-phases)
  - [Output Structure](#output-structure)
  - [Report Format](#report-format)
  - [Troubleshooting](#troubleshooting)
  - [Disclaimer](#disclaimer)

---

## Features

- **Pre-flight validation** of all required tools and device connectivity.
- **Drozer component testing** -- exported activities, services, broadcast receivers, content providers, SQL injection scans, path traversal scans, and intent sniffing.
- **Automatic screenshots** via `adb screencap` after every Drozer command and post-logout test, with optional live mirroring through `scrcpy`.
- **Local file system analysis** -- pulls shared preferences, SQLite databases, Realm/NoSQL files, cache, WebView storage, and external storage; runs regex scans for passwords, tokens, API keys, and PII.
- **Deep dump verification** -- parses XML shared prefs for boolean feature flags, queries every SQLite table row-by-row, extracts strings from binary files, and inspects WebView local storage.
- **Logcat monitoring** -- captures logs in real time while the user interacts with the app, then scans for sensitive data, cleartext HTTP, SQL queries, and stack traces.
- **Memory analysis** -- heap dump via `am dumpheap`, `/proc/pid/maps` and `/proc/pid/smaps` extraction, string scanning, open file descriptor listing, and network connection enumeration.
- **ADB backup analysis** -- creates a full backup, extracts the `.ab` archive, and greps the unpacked contents.
- **Manifest analysis** -- decompiles with `apktool` and checks `debuggable`, `allowBackup`, `usesCleartextTraffic`, exported components without permissions, overly broad intent filters, dangerous permissions, and network security config.
- **Post-logout access control testing** -- clears app data or waits for manual logout, then re-launches every exported activity and attempts direct access with privilege-escalation intent extras.
- **Markdown report** with executive summary, per-phase findings, risk summary table, inline screenshot references, full command log, and an AI prompt header for feeding into GPT-4 / Claude.

---

## Architecture

```
android_automation/
|-- main.py                     Entry point and phase orchestrator
|-- requirements.txt            Python dependencies
|-- core/
|   |-- config.py               Global state, sensitive-data patterns, manifest flags
|   |-- adb.py                  ADB command wrapper
|   |-- drozer.py               Non-interactive drozer wrapper (drozer console connect -c)
|   |-- screenshot.py           Screenshot capture + scrcpy live view
|   |-- report.py               Markdown report generator
|-- phases/
|   |-- preflight.py            Tool availability and device checks
|   |-- setup.py                Device selection, APK install, permission/login prompts
|   |-- drozer_testing.py       Phase I  -- Drozer component testing
|   |-- filesystem.py           Phase III -- Local file system analysis
|   |-- dump_verify.py          Phase IV  -- Deep dump file verification
|   |-- logcat.py               Phase V   -- Logcat monitoring
|   |-- memory.py               Phase VI  -- Memory analysis
|   |-- backup.py               Phase VII -- ADB backup analysis
|   |-- manifest.py             Phase VIII-- Manifest analysis
|   |-- post_logout.py          Phase IX  -- Post-logout access control
|-- output/                     Generated per-package output (created at runtime)
```

---

## Prerequisites

### Host machine

| Tool       | Purpose                        | Required |
|------------|--------------------------------|----------|
| `adb`      | Device communication           | Yes      |
| `drozer`   | Android component exploitation | Yes      |
| `scrcpy`   | Live device mirroring          | Yes      |
| `apktool`  | APK decompilation              | Yes      |
| `sqlite3`  | Database analysis              | Optional |
| `strings`  | Binary string extraction       | Optional |
| `aapt2`    | Package name auto-detection    | Optional |
| Python 3.10+ | Runtime                      | Yes      |

### Target device

- Rooted Android device (Magisk or similar).
- USB debugging enabled.
- Drozer agent APK installed (`com.withsecure.dz`). Download from [WithSecure releases](https://github.com/WithSecureLabs/drozer-agent/releases).
- Drozer embedded server turned ON in the agent app before running Phase I.

---

## Installation

```bash
# Clone or navigate to the project
cd /path/to/android_automation

# Install Python dependency
pip install -r requirements.txt

# Install drozer (if not already present)
pip install drozer

# Install apktool (Arch Linux example -- adjust for your distro)
# See https://ibotpeaches.github.io/Apktool/install/ for other platforms
curl -sLO "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"
curl -sLO "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar"
chmod +x apktool
sudo mv apktool /usr/local/bin/apktool
sudo mv apktool_2.10.0.jar /usr/local/bin/apktool.jar

# Install drozer agent on device
adb install drozer-agent.apk
```

---

## Usage

### Interactive Mode

Prompts for device selection, APK path, permission grants, login state, and per-phase options:

```bash
python main.py
```

### Non-Interactive / Auto Mode

Runs all phases with sensible defaults -- no user prompts. Useful for CI or batch testing:

```bash
python main.py \
  --auto \
  --device <DEVICE_SERIAL> \
  --package <PACKAGE_NAME> \
  --apk /path/to/app.apk
```

### Selective Phases

Run only specific phases (comma-separated numbers):

```bash
# Only Drozer + Manifest + Post-logout
python main.py --phases 1,8,9

# Only file system and logcat analysis
python main.py --phases 3,5 --package com.example.app --device SERIAL --auto
```

### All CLI Arguments

| Argument            | Description                                          |
|---------------------|------------------------------------------------------|
| `--auto`            | Non-interactive mode with default answers             |
| `--device SERIAL`   | Device serial from `adb devices`                     |
| `--package PKG`     | Target package name                                  |
| `--apk PATH`        | Path to APK file (omit if pre-installed)             |
| `--phases 1,3,5`    | Comma-separated phase numbers to run                 |
| `--skip-preflight`  | Skip tool availability checks                        |

---

## Test Phases

| # | Phase                              | What it does                                                                 |
|---|------------------------------------|------------------------------------------------------------------------------|
| 1 | Drozer Component Testing           | Tests all exported activities, services, receivers, content providers; SQL injection and path traversal scans |
| 3 | Local File System Analysis         | Pulls app data directory; greps for sensitive data; analyzes SQLite, shared prefs, NoSQL, file permissions |
| 4 | Dump File Verification             | Deep re-analysis of pulled files: per-table SQLite queries, XML parsing, binary string extraction, WebView storage |
| 5 | Logcat Monitoring                  | Real-time logcat capture during user interaction; scans for leaked credentials, HTTP URLs, SQL, exceptions |
| 6 | Memory Analysis                    | Heap dump, /proc/pid/maps, string extraction, open FDs, active network connections |
| 7 | ADB Backup Analysis                | Creates and extracts ADB backup; scans unpacked contents for sensitive data |
| 8 | Manifest Analysis                  | Decompiles APK; checks debuggable, allowBackup, cleartext traffic, exported components, permissions, network security config |
| 9 | Post-Logout Access Control         | Clears app data; re-launches activities via Drozer and ADB intents with privilege-escalation extras |

Phase 2 (screenshot capture) is integrated into Phases 1 and 9 automatically.

---

## Output Structure

All output is written to `./output/<package_name>/`:

```
output/<package_name>/
|-- DAST_Report_<pkg>_<timestamp>.md    Final Markdown report
|-- screenshots/                        PNG screenshots from every test
|-- filesystem/
|   |-- shared_prefs/                   Pulled XML preference files
|   |-- databases/                      Pulled SQLite databases
|   |-- files/                          Pulled internal files
|   |-- cache/                          Pulled cache
|   |-- app_webview/                    Pulled WebView storage
|   |-- external/                       Pulled external storage
|   |-- full_data/                      Full /data/data/<pkg>/ pull
|-- grep_results.txt                    Sensitive data regex matches
|-- logcat_dump.txt                     Full logcat capture
|-- logcat_app_filtered.txt             App-specific log lines
|-- heap_dump.hprof                     Java heap dump
|-- proc_maps.txt                       /proc/pid/maps
|-- proc_smaps.txt                      /proc/pid/smaps
|-- open_fds.txt                        Open file descriptors
|-- network_connections.txt             TCP/UDP connection state
|-- backup.ab                           Raw ADB backup
|-- backup.tar                          Extracted backup archive
|-- backup_unpacked/                    Unpacked backup contents
|-- apktool_out/                        Decompiled APK (AndroidManifest.xml, resources, smali)
|-- db_dump_*.sql                       Full SQLite table dumps
|-- backup_grep_results.txt             Sensitive matches in backup
```

---

## Report Format

The generated `.md` report contains:

1. **AI prompt header** -- a pre-written prompt for feeding the report into GPT-4 or Claude for risk rating, executive summary, and Jira ticket generation.
2. **Executive summary** -- package name, device info, date, severity breakdown table.
3. **Detailed findings** -- one section per phase, each finding with severity, status, and full detail block.
4. **Screenshots** -- inline Markdown image references to captured PNGs.
5. **Command log** -- collapsible section with every command executed and its output.
6. **Risk summary table** -- flat table of all findings with phase, severity, and status.

---

## Troubleshooting

**"No Android device detected via ADB"**
- Check that USB debugging is enabled on the device.
- Run `adb devices` manually and confirm the device shows as `device` (not `unauthorized`).

**Drozer phases return empty results**
- Open the Drozer Agent app on the device and enable the embedded server.
- Verify the connection: `adb forward tcp:31415 tcp:31415 && drozer console connect -c "list"`.

**ADB backup times out**
- ADB backup requires physical confirmation on the device. Tap "Back up my data" when prompted.
- In `--auto` mode this phase may fail if no one taps the device; this is expected and logged as Info.

**"apktool not found"**
- Install apktool following the instructions in the Installation section.
- Verify with `apktool --version`.

**File system pull returns empty**
- The device must be rooted. Verify with `adb shell su -c id` (should show `uid=0`).
- Some apps on Android 13+ use per-app SELinux contexts that block even root pulls.

**Heap dump is empty (0 bytes)**
- The app must be running when the heap dump is taken. Ensure the app is in the foreground.
- On some devices `am dumpheap` requires the app to be debuggable; non-debuggable apps will produce an empty file.

---

## Disclaimer

This tool is intended for authorized security testing only. Use it exclusively against applications for which you have explicit written permission. Unauthorized testing of applications you do not own or have permission to test is illegal and unethical.
