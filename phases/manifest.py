"""
Phase VIII — Manifest Analysis (Runtime).

Decompiles the APK with apktool and inspects AndroidManifest.xml
for security-relevant flags and misconfigurations.
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from rich.console import Console
from rich.table import Table

from core.config import Config, MANIFEST_SECURITY_FLAGS
from core.adb import ADB

console = Console()
PHASE = "Phase VIII — Manifest Analysis"


def run_manifest_analysis(config: Config, adb: ADB) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name
    apktool_dir = config.output_dir / "apktool_out"
    apk_path = config.apk_path

    # If no local APK, pull from device
    if not apk_path or not Path(apk_path).exists():
        console.print("[cyan]Pulling APK from device...[/cyan]")
        pm_result = adb.shell(f"pm path {pkg}")
        apk_device_path = pm_result.stdout.strip().replace("package:", "")
        if apk_device_path:
            local_apk = str(config.output_dir / "pulled_app.apk")
            adb.pull(apk_device_path, local_apk)
            apk_path = local_apk
            config.log_command(PHASE, f"adb pull {apk_device_path}", f"Pulled to {local_apk}")
        else:
            console.print("[red]Could not locate APK on device. Skipping manifest analysis.[/red]")
            return

    # ── Decompile with apktool ──
    console.print(f"[cyan]Decompiling APK with apktool...[/cyan]")
    try:
        result = subprocess.run(
            ["apktool", "d", apk_path, "-o", str(apktool_dir), "-f"],
            capture_output=True, text=True, timeout=120,
        )
        config.log_command(PHASE, f"apktool d {apk_path} -o {apktool_dir}", result.stdout, result.stderr)
    except FileNotFoundError:
        console.print("[red]apktool not found. Skipping manifest analysis.[/red]")
        return
    except subprocess.TimeoutExpired:
        console.print("[red]apktool timed out. Skipping manifest analysis.[/red]")
        return

    manifest_path = apktool_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        console.print("[red]AndroidManifest.xml not found in decompiled output.[/red]")
        return

    manifest_content = manifest_path.read_text(encoding="utf-8")
    config.log_command(PHASE, f"cat AndroidManifest.xml", manifest_content[:5000])

    # ── Check security flags ──
    console.print("\n[cyan]Checking security flags...[/cyan]\n")

    table = Table(title="Manifest Security Flags")
    table.add_column("Flag", style="bold")
    table.add_column("Present?")
    table.add_column("Risk")
    table.add_column("Description")

    for flag, info in MANIFEST_SECURITY_FLAGS.items():
        present = flag in manifest_content
        status = "[red]YES[/red]" if present else "[green]NO[/green]"
        table.add_row(flag, status, info["risk"], info["desc"])

        if present:
            config.add_finding(
                PHASE,
                f"Insecure manifest flag: {flag}",
                info["risk"],
                info["desc"],
            )

    console.print(table)

    # ── Check exported components without permissions ──
    _check_exported_without_permissions(config, manifest_content)

    # ── Check overly broad intent filters ──
    _check_intent_filters(config, manifest_content)

    # ── Check permissions declared ──
    _check_permissions(config, manifest_content)

    # ── Check network security config reference ──
    _check_network_security_config(config, manifest_content, apktool_dir)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _check_exported_without_permissions(config: Config, manifest: str) -> None:
    console.print("[cyan]Checking for exported components without permissions...[/cyan]")

    exported_no_perm = []
    # Simple regex-based check — works for the common cases
    component_pattern = re.compile(
        r'<(activity|service|receiver|provider)[^>]*'
        r'android:exported="true"[^>]*'
        r'(?!.*android:permission)',
        re.DOTALL,
    )

    for match in component_pattern.finditer(manifest):
        block = match.group(0)
        name_match = re.search(r'android:name="([^"]+)"', block)
        comp_type = match.group(1)
        name = name_match.group(1) if name_match else "unknown"
        exported_no_perm.append(f"  {comp_type}: {name}")

    if exported_no_perm:
        detail = "\n".join(exported_no_perm)
        config.add_finding(
            PHASE,
            f"Exported components without permission ({len(exported_no_perm)})",
            "High",
            f"The following components are exported without explicit permission guards:\n{detail}",
        )
        console.print(f"  [red]Found {len(exported_no_perm)} exported component(s) without permissions[/red]")
    else:
        console.print("  [green]All exported components have permission guards.[/green]")


def _check_intent_filters(config: Config, manifest: str) -> None:
    console.print("[cyan]Checking for overly broad intent filters...[/cyan]")

    broad_filters = []
    # Look for intent-filters with very generic actions
    generic_actions = [
        "android.intent.action.VIEW",
        "android.intent.action.SEND",
        "android.intent.action.SENDTO",
    ]

    for action in generic_actions:
        if action in manifest:
            # Check if combined with broad data schemes
            if 'android:scheme="http"' in manifest or 'android:scheme="https"' in manifest:
                broad_filters.append(f"{action} with http/https scheme")
            if 'android:scheme="*"' in manifest or 'android:mimeType="*/*"' in manifest:
                broad_filters.append(f"{action} with wildcard scheme/mimeType")

    if broad_filters:
        config.add_finding(
            PHASE,
            "Overly broad intent filters",
            "Medium",
            "The following broad intent filter configurations were found:\n"
            + "\n".join(f"  - {f}" for f in broad_filters),
        )


def _check_permissions(config: Config, manifest: str) -> None:
    console.print("[cyan]Listing declared permissions...[/cyan]")

    dangerous_perms = [
        "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
        "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_SMS", "SEND_SMS",
        "READ_PHONE_STATE", "CALL_PHONE", "READ_CALENDAR", "WRITE_CALENDAR",
        "ACCESS_BACKGROUND_LOCATION",
    ]

    found_dangerous = []
    for perm in dangerous_perms:
        if perm in manifest:
            found_dangerous.append(perm)

    if found_dangerous:
        config.add_finding(
            PHASE,
            f"Dangerous permissions declared ({len(found_dangerous)})",
            "Info",
            "The app declares the following dangerous permissions:\n"
            + "\n".join(f"  - android.permission.{p}" for p in found_dangerous),
        )
        config.log_command(PHASE, "Dangerous permissions check", "\n".join(found_dangerous))


def _check_network_security_config(config: Config, manifest: str, apktool_dir: Path) -> None:
    console.print("[cyan]Checking network security configuration...[/cyan]")

    nsc_match = re.search(r'android:networkSecurityConfig="@xml/([^"]+)"', manifest)
    if not nsc_match:
        config.add_finding(
            PHASE,
            "No custom network security config",
            "Info",
            "The app does not define a custom networkSecurityConfig. "
            "Default platform behavior applies.",
        )
        return

    nsc_name = nsc_match.group(1)
    nsc_path = apktool_dir / "res" / "xml" / f"{nsc_name}.xml"
    if not nsc_path.exists():
        return

    nsc_content = nsc_path.read_text(encoding="utf-8")
    config.log_command(PHASE, f"cat res/xml/{nsc_name}.xml", nsc_content[:3000])

    if "cleartextTrafficPermitted" in nsc_content and '"true"' in nsc_content:
        config.add_finding(
            PHASE,
            "Network security config permits cleartext traffic",
            "Medium",
            f"network_security_config.xml:\n{nsc_content[:2000]}",
        )

    if "<trust-anchors>" in nsc_content and "user" in nsc_content:
        config.add_finding(
            PHASE,
            "Network security config trusts user-installed certificates",
            "Medium",
            f"The app trusts user-installed CA certificates:\n{nsc_content[:2000]}",
        )
