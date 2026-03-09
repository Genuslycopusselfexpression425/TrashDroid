"""
Setup phase — device selection, APK input, installation, permission grant, login state.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from core.adb import ADB
from core.config import Config

console = Console()


def select_device() -> str:
    devices = ADB.get_devices()
    if not devices:
        console.print("[red]No connected devices found via adb.[/red]")
        return ""
    if len(devices) == 1:
        console.print(f"[green]Auto-selected device:[/green] {devices[0]}")
        return devices[0]

    console.print("\n[bold cyan]Connected devices:[/bold cyan]")
    for i, dev in enumerate(devices, 1):
        console.print(f"  [{i}] {dev}")

    while True:
        choice = Prompt.ask("Select device number", default="1")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                return devices[idx]
        except ValueError:
            pass
        console.print("[red]Invalid selection, try again.[/red]")


def get_apk_input(adb: ADB) -> tuple[str | None, str, bool]:
    """
    Returns (apk_path or None, package_name, is_preinstalled).
    """
    console.print("\n[bold cyan]═══ Target Application ═══[/bold cyan]\n")
    preinstalled = Confirm.ask("Is the app already installed on the device?", default=False)

    if preinstalled:
        pkg = Prompt.ask("Enter the package name (adb shell pm list packages)")
        return None, pkg.strip(), True

    apk_path = Prompt.ask("Enter the full path to the APK file")
    apk_path = apk_path.strip().strip("'\"")

    pkg = adb.get_package_name_from_apk(apk_path)
    if not pkg:
        pkg = Prompt.ask("Could not auto-detect package name. Enter it manually")
        pkg = pkg.strip()

    return apk_path, pkg, False


def install_and_prepare(adb: ADB, config: Config) -> None:
    """Install APK, prompt for permissions and login."""
    if not config.is_preinstalled and config.apk_path:
        console.print(f"\n[cyan]Installing APK: {config.apk_path}[/cyan]")
        result = adb.install_apk(config.apk_path)
        console.print(f"  {result}")
        config.log_command("Setup", f"adb install -r -d {config.apk_path}", result)

    if config.auto_mode:
        console.print("[yellow]Auto-mode: skipping permission/login prompts.[/yellow]")
        config.logged_in = False
    else:
        console.print(Panel(
            "Please open the app, grant ALL permissions,\nthen press Enter to continue.",
            style="bold yellow",
        ))
        input()

        want_login = Confirm.ask("Do you want to run tests in a logged-in state?", default=True)
        if want_login:
            console.print("\n[yellow]Please log in to the application now. Press Enter when ready.[/yellow]")
            input()
            config.logged_in = True
        else:
            config.logged_in = False

    console.print(f"\n[green]✓ Setup complete — testing '{config.package_name}' "
                  f"({'logged in' if config.logged_in else 'logged out'})[/green]")
