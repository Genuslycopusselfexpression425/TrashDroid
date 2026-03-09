# Android DAST — Automated Security Testing Framework

> **Purpose:** This document describes the full Android Dynamic Application Security Testing (DAST) automation script. It is intended as a technical runbook for building the script in Cursor or any IDE.

---

## Table of Contents

- [Android DAST — Automated Security Testing Framework](#android-dast--automated-security-testing-framework)
  - [Table of Contents](#table-of-contents)
  - [1. Overview](#1-overview)
  - [2. Prerequisites \& Setup](#2-prerequisites--setup)
    - [2.1 Pre-flight Checks (automated at script start)](#21-pre-flight-checks-automated-at-script-start)
    - [2.2 Target Device Requirements](#22-target-device-requirements)
  - [3. Execution Flow](#3-execution-flow)
  - [4. Test Phases](#4-test-phases)
    - [4.1 Phase I — Drozer Component Testing](#41-phase-i--drozer-component-testing)
    - [4.2 Phase II — Screenshot Capture via Scrcpy](#42-phase-ii--screenshot-capture-via-scrcpy)
    - [4.3 Phase III — Local File System Analysis](#43-phase-iii--local-file-system-analysis)
    - [4.4 Phase IV — Dump File Verification (Optional)](#44-phase-iv--dump-file-verification-optional)
    - [4.5 Phase V — Logcat Monitoring](#45-phase-v--logcat-monitoring)
    - [4.6 Phase VI — Memory Analysis](#46-phase-vi--memory-analysis)
    - [4.7 Phase VII — ADB Backup Analysis](#47-phase-vii--adb-backup-analysis)
    - [4.8 Phase VIII — Manifest Analysis (Runtime)](#48-phase-viii--manifest-analysis-runtime)
    - [4.9 Phase IX — Post-Logout Access Control Testing](#49-phase-ix--post-logout-access-control-testing)
  - [5. Post-Runtime Reporting](#5-post-runtime-reporting)
    - [5.1 Generate Markdown Report](#51-generate-markdown-report)
    - [5.2 AI-Ready Format](#52-ai-ready-format)
  - [6. Quick Command Reference](#6-quick-command-reference)

---

## 1. Overview

The script starts with an APK file and performs a full DAST assessment against a rooted Android device. It automates tool invocation, user interaction prompts, screenshot capture, file dumping, and report generation.

**Stack used:**
- `adb` — device communication
- `drozer` — Android component exploitation
- `scrcpy` — screenshot automation
- `memdump` — memory extraction
- `apktool` — manifest decompilation

---

## 2. Prerequisites & Setup

### 2.1 Pre-flight Checks (automated at script start)

The script must verify the following before proceeding:

- [ ] `drozer` is installed on the host
- [ ] `adb` is installed on the host
- [ ] USB cable is connected
- [ ] At least one device is visible via `adb devices`
- [ ] `scrcpy` is installed on the host
- [ ] `apktool` is installed on the host
- [ ] Device is rooted 

If any check fails → print a clear error message and exit.

### 2.2 Target Device Requirements

- Rooted Android device
- USB Debugging enabled
- Drozer agent APK installed on the device if not drozer can install via it's own

---

## 3. Execution Flow

The script runs the following steps in order:

1. **Device Selection** — Run `adb devices`, list all connected devices, prompt user to select one.
2. **APK Input** — Ask user for the path to the `.apk` file to test. Or if the app is preinstalled ask for its module name.
   
3. IF not PRE-INSTALLED **APK Install** — Install the APK to the selected device:
   ```bash
   adb -s <device_id> install -r -d <path/to/app.apk>
   ```
4. **Permission Prompt** — Pause the script. Tell the user:
   > "Please open the app, grant ALL permissions, then press Enter to continue."
5. **Login State** — Ask the user:
   > "Do you want to run tests logged in or logged out? (y = logged in / n = logged out)" If user press Y then pause the script and let the user login. 
6. **Resume** — User presses Enter to resume. Script proceeds to test phases.

---

## 4. Test Phases

### 4.1 Phase I — Drozer Component Testing

**Tool:** `drozer`

Connect Drozer:
```bash
adb -s <device_id> forward tcp:31415 tcp:31415
drozer console connect
```
Ask the user which component types to test (multi-select Y/N for each):

| Option | Drozer Test |
|--------|-------------|
| Exported Activities | `run app.activity.start --component <pkg> <activity>` |
| Exported Broadcast Receivers | `run app.broadcast.send --component <pkg> <receiver>` |
| Exported Services | `run app.service.start --component <pkg> <service>` |
| Content Provider Testing | `run app.provider.query content://<uri>` |
| Intent Sniffing & Interception | `run scanner.activity.browsable -a <pkg>` |

> After **each** Drozer command executes → automatically take a screenshot via Scrcpy (see Phase II).

---

### 4.2 Phase II — Screenshot Capture via Scrcpy

**Tool:** `scrcpy`

- Fire up `scrcpy` in the background at the start of Phase I.
- After each Drozer command completes, capture a screenshot (there should be some delay in the screenshot to let the drozer do the work):
  ```bash
  scrcpy --screenshot-file <output_dir>/<phase>_<command_name>_<timestamp>.png
  ```
- Store all screenshots in an `/output/<package_name>/screenshots/` folder.
- Embed screenshot paths in the final `.md` report.

---

### 4.3 Phase III — Local File System Analysis

**Goal:** Dump the app's local storage to the host for analysis.

Pull the following paths from the device (requires root):

| ADB Path | Contents |
|----------|----------|
| `/data/data/<pkg>/shared_prefs/` | XML preferences — tokens, flags |
| `/data/data/<pkg>/databases/` | SQLite databases |
| `/data/data/<pkg>/files/` | Internal files |
| `/data/data/<pkg>/cache/` | Cache files |
| `/data/data/<pkg>/app_webview/` | WebView storage, cookies |
| `/sdcard/Android/data/<pkg>/` | External storage |

**Pull command:**
```bash
adb -s <device_id> pull /data/data/<package_name>/ ./output/<package_name>/filesystem/
```

**Post-pull grep scan** — run pre-set grep patterns against all pulled files to find:
- Passwords, tokens, API keys
- PII (email, phone, SSN patterns)
- Hardcoded credentials
- Private keys / certificates

```bash
grep -rniE "(password|token|api_key|secret|bearer|private_key|email|ssn)" ./output/<package_name>/filesystem/
```

Save grep results to `./output/<package_name>/grep_results.txt`.

---

### 4.4 Phase IV — Dump File Verification (Optional)

**Prompt the user (Y/N):**
> "Do you want the script to attempt verification of the dumped files? (y/n)"

If `y`:
- For each file found in the dump (shared_prefs, databases, files — steps 3.3, 3.4, 3.5 get these from the @kimi_response.txt):
  - Re-execute the relevant test cases that were unable to dump automatically.
  - Run the commands against the dumped file path directly.
  - Log results to the report.

If `n`: skip and move to Phase V.

---

### 4.5 Phase V — Logcat Monitoring

**Goal:** Capture app log output to detect sensitive data leakage.

1. Fire up the application:
   ```bash
   adb -s <device_id> shell monkey -p <package_name> 1
   ```
2. Ask the user:
   > "Please use the app and enter sensitive data (login, PII, etc.). Press 'S' when done (max 15 seconds)."
3. Start logcat capture in the background (max 15 seconds):
   ```bash
   adb -s <device_id> logcat -d > ./output/<package_name>/logcat_dump.txt
   ```
   Stop capture when user presses `S` or after 15 seconds — whichever comes first.
4. Dump logs to host.
5. Grep for sensitive/cleartext data:
   ```bash
   grep -iE "(password|token|secret|credit|card|otp|pin|bearer)" ./output/<package_name>/logcat_dump.txt
   ```
6. Save results to the report.

---

### 4.6 Phase VI — Memory Analysis

**Tool:** `memdump`

1. Ask the user:
   > "Is the app currently logged in? If not, please log in now and press 'F' to continue."
2. Wait for user to press `F`.
3. Dump full device memory and app process memory:
   ```bash
   # Dump app-specific memory
   adb -s <device_id> shell "memdump <pid_of_app>" > ./output/<package_name>/memory_dump.bin
   ```
4. Analyse the dump for sensitive strings:
   ```bash
   strings ./output/<package_name>/memory_dump.bin | grep -iE "(password|token|secret|credit|ssn|bearer)"
   ```
5. Store the raw dump and analysis results on the host.

---

### 4.7 Phase VII — ADB Backup Analysis

1. Ask the user:
   > "Is the app currently logged in? (y/n)"
2. Wait for user input.
3. Run ADB backup:
   ```bash
   adb -s <device_id> backup -apk -shared -all -f ./output/<package_name>/backup.ab <package_name>
   ```
4. Unpack the backup:
   ```bash
   dd if=./output/<package_name>/backup.ab bs=24 skip=1 | python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > ./output/<package_name>/backup.tar
   tar xf ./output/<package_name>/backup.tar -C ./output/<package_name>/backup_unpacked/
   ```
5. Analyse unpacked contents for sensitive data (same grep patterns as Phase III).

---

### 4.8 Phase VIII — Manifest Analysis (Runtime)

**Tool:** `apktool`

1. Decompile the APK:
   ```bash
   apktool d <path/to/app.apk> -o ./output/<package_name>/apktool_out/
   ```
2. Parse `./output/<package_name>/apktool_out/AndroidManifest.xml` and check for:

| Flag | Check | Risk |
|------|-------|------|
| `android:debuggable="true"` | Should be `false` in production | High |
| `android:allowBackup="true"` | Enables full ADB backup extraction | Medium |
| `android:exported="true"` without permissions | Unprotected component | High |
| Overly broad intent filters | Unintended component exposure | Medium |
| `android:usesCleartextTraffic="true"` | Allows HTTP traffic | Medium |

3. Log all findings to the report.

---

### 4.9 Phase IX — Post-Logout Access Control Testing

1. Ask the user to log out of the app:
   > "Please log out of the application and press Enter to continue."
   
   **OR** optionally clear all app data:
   ```bash
   adb -s <device_id> shell pm clear <package_name>
   ```

2. Re-run Drozer exported activity tests (same as Phase I — Activities only).

3. Test for broken access control via intent flags:

```bash
# Direct access to profile page without login
adb shell am start -n <pkg>/<ProfileActivity>

# Access admin panel by flipping boolean flag
adb shell am start -n <pkg>/<AdminActivity> --ez is_admin true

# Access payment screen directly
adb shell am start -n <pkg>/<PaymentActivity>

# Access any sensitive screen requiring auth
adb shell am start -n <pkg>/<SensitiveActivity>
```

4. Screenshot each result via Scrcpy.
5. Log findings — note which screens were accessible without authentication.

---

## 5. Post-Runtime Reporting

### 5.1 Generate Markdown Report

After all phases complete, the script must auto-generate a `.md` report file at:
```
./output/<package_name>/DAST_Report_<package_name>_<timestamp>.md
```

The report must include:

- **Executive Summary** — package name, date, device, test scope
- **Per-phase findings** — each phase gets its own section
- **Commands executed** — exact commands with full output
- **Screenshots** — inline image references `![screenshot](./screenshots/xxx.png)`
- **Grep results** — sensitive data found
- **Risk summary table** — finding name, phase, severity, status

### 5.2 AI-Ready Format

The `.md` file is intentionally designed to be fed into an AI model (e.g., GPT-4, Claude) for:

- Summarising findings into a pentest executive summary
- Assigning CVSS-style risk ratings (Critical / High / Medium / Low / Info)
- Auto-generating **Jira tickets** for each finding
- Providing remediation recommendations per finding

**Suggested AI prompt to include at the top of the report:**
```
You are a senior mobile security engineer. Review the following Android DAST findings,
assign a risk rating to each, write an executive summary, and generate a Jira ticket
description for each High and Critical finding.
```

---

## 6. Quick Command Reference

```bash
# List ADB devices
adb devices

# Install APK (force + downgrade)
adb -s <device_id> install -r -d <app.apk>

# Forward Drozer port
adb -s <device_id> forward tcp:31415 tcp:31415

# Connect Drozer
drozer console connect

# Pull app data directory
adb -s <device_id> pull /data/data/<package>/ ./output/

# Dump logcat
adb -s <device_id> logcat -d > logcat.txt

# ADB backup
adb -s <device_id> backup -apk -shared -f backup.ab <package>

# Clear app data
adb -s <device_id> shell pm clear <package>

# Decompile APK
apktool d app.apk -o ./apktool_out/

# Start app via intent
adb shell monkey -p <package> 1

# Launch specific activity
adb shell am start -n <package>/<ActivityName>
```

---

> **Note:** All output files are saved under `./output/<package_name>/`. Ensure this directory is created at the start of the script.
> 
> **Security:** This tool must only be used against applications for which explicit written authorisation has been obtained.
