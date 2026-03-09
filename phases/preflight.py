"""
Pre-flight checks — verifies all required tools, device connectivity, and root status.
"""

from __future__ import annotations

import shutil
import subprocess

from rich.console import Console
from rich.table import Table

from core.config import REQUIRED_TOOLS

console = Console()


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def check_tool_version(name: str) -> str:
    for flag in ["--version", "version", "-v"]:
        try:
            result = subprocess.run(
                [name, flag], capture_output=True, text=True, timeout=10,
            )
            output = (result.stdout or result.stderr).strip()
            if output and "unknown command" not in output.lower():
                return output.splitlines()[0][:80]
        except Exception:
            continue
    return "installed"


def run_preflight() -> bool:
    """
    Verify all prerequisites. Returns True if all critical checks pass.
    """
    console.print("\n[bold cyan]═══ Pre-flight Checks ═══[/bold cyan]\n")

    table = Table(title="Tool Availability")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Version")

    all_ok = True
    for tool in REQUIRED_TOOLS:
        found = check_tool(tool)
        version = check_tool_version(tool) if found else "—"
        status = "[green]✓ Found[/green]" if found else "[red]✗ Missing[/red]"
        table.add_row(tool, status, version)
        if not found:
            all_ok = False

    for extra in ["sqlite3", "strings", "aapt2"]:
        found = check_tool(extra)
        version = check_tool_version(extra) if found else "—"
        status = "[green]✓ Found[/green]" if found else "[yellow]~ Optional[/yellow]"
        table.add_row(extra, status, version)

    console.print(table)

    if not all_ok:
        console.print("\n[red bold]✗ Critical tools are missing. Install them before proceeding.[/red bold]")
        return False

    from core.adb import ADB
    devices = ADB.get_devices()
    if not devices:
        console.print("\n[red bold]✗ No Android device detected via ADB.[/red bold]")
        console.print("  Ensure USB debugging is enabled and the device is connected.")
        return False

    console.print(f"\n[green]✓ {len(devices)} device(s) connected via ADB.[/green]")
    return True
