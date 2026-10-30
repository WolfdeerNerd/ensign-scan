"""Desktop notification for scan completion, via notify-send.

Best-effort only: if there's no notification daemon (headless server,
SSH session, minimal install), this silently does nothing rather than
error out the whole run over a cosmetic feature.

The infected-files alert is critical urgency so it can't be missed, which
also makes it sticky: it stays until dismissed. `notify-send -t` can't fix
that -- KDE Plasma ignores the expire time on critical notifications -- so
send() can instead close the notification itself after a delay, over D-Bus.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
from pathlib import Path

_MAX_NAMES_SHOWN = 3


def available() -> bool:
    return shutil.which("notify-send") is not None


def build_message(summary: dict, infected: list[dict]) -> tuple[str, str, str]:
    """Build (title, body, urgency) for a scan-completion notification.

    Pure function, no subprocess -- kept separate from send() so the
    message logic can be tested without notify-send installed.
    """
    infected_count = summary.get("infected", 0)
    error_count = summary.get("error", 0) or summary.get("errors", 0)

    if infected_count:
        title = f"! Ensign: {infected_count} infected file" + ("s" if infected_count != 1 else "")
        urgency = "critical"
    elif error_count:
        title = f"Ensign scan complete — {error_count} error" + ("s" if error_count != 1 else "")
        urgency = "normal"
    else:
        title = "Ensign scan complete"
        urgency = "normal"

    body_lines = [
        f"Total: {summary.get('total', 0)}  ·  "
        f"Clean: {summary.get('clean', 0)}  ·  "
        f"Infected: {infected_count}  ·  "
        f"Errors: {error_count}"
    ]
    if infected:
        names = [i["filepath"].split("/")[-1] for i in infected[:_MAX_NAMES_SHOWN]]
        line = "Infected: " + ", ".join(names)
        if len(infected) > _MAX_NAMES_SHOWN:
            line += f" (+{len(infected) - _MAX_NAMES_SHOWN} more)"
        body_lines.append(line)

    return title, "\n".join(body_lines), urgency


def game_running() -> bool:
    """True if Steam has a game running right now.

    Steam starts every game it launches (native or Proton) under a helper
    process whose command line begins `reaper SteamLaunch AppId=<id>`, so
    this looks for that with `pgrep -f`. The client sitting open and idle
    does not match. The pattern is deliberately not just "reaper": that is
    also the name of an audio workstation. If pgrep is missing or fails,
    answers False: no game detected means the alert stays until dismissed.
    """
    if shutil.which("pgrep") is None:
        return False
    try:
        result = subprocess.run(["pgrep", "-f", "reaper SteamLaunch AppId="],
                                capture_output=True, timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _boot_id() -> str:
    """Identifies this boot. Notification ids restart when the notification
    daemon does (every login), so a saved id is only trusted within a boot."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def _load_state(path: Path | str) -> dict:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(path: Path | str, state: dict) -> None:
    try:
        Path(path).write_text(json.dumps(state))
    except OSError:
        pass  # best-effort, like everything in this module


def _kill_close_helper(pid: object) -> None:
    """Stop a still-pending close timer started by an earlier run.

    Replacing an alert keeps its notification id, so the old timer would
    otherwise close the NEW alert early. Only a process that still looks
    like our helper (its command line carries "ensign-close") is touched:
    once the timer fires the process becomes gdbus, and a recycled pid is
    someone else's.
    """
    if not isinstance(pid, int) or pid <= 0:
        return
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return
    if b"ensign-close" not in cmdline:
        return
    try:
        os.killpg(pid, signal.SIGTERM)  # helper is its own session: pgid == pid
    except OSError:
        pass


def _effective_timeout(urgency: str, timeout_s: int, interactive: bool,
                       only_when_gaming: bool) -> int:
    """Seconds after which the alert closes itself; 0 = stays until dismissed.

    Only the critical (infected) alert is ever timed. A run with no terminal
    (a service or cron job) is always timed, so scheduled runs can't pile up
    sticky alerts. A run you started in a terminal is timed only if
    only_when_gaming is off, or a Steam game is running right now.
    """
    if urgency != "critical" or timeout_s <= 0:
        return 0
    if interactive and only_when_gaming and not game_running():
        return 0
    return timeout_s


def _schedule_close(notification_id: int, delay_s: int) -> int | None:
    """Close a notification after `delay_s` seconds, from a detached process.

    Ensign exits when the scan is done, so the wait can't live in this
    process. The helper outlives it (own session: survives the terminal
    closing) and calls the standard org.freedesktop.Notifications
    CloseNotification method, which works on any notification daemon.
    If you already dismissed the notification, closing it again is a no-op
    (ids only count upward, so a stale id never hits a newer notification).
    Returns the helper's pid, or None if gdbus isn't available or the helper
    couldn't start.
    """
    gdbus = shutil.which("gdbus")
    if gdbus is None:
        return None
    try:
        helper = subprocess.Popen(
            ["sh", "-c",
             'sleep "$1" && exec "$2" call --session '
             "--dest org.freedesktop.Notifications "
             "--object-path /org/freedesktop/Notifications "
             '--method org.freedesktop.Notifications.CloseNotification "uint32 $3"',
             "ensign-close", str(delay_s), gdbus, str(notification_id)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
    except OSError:
        return None
    return helper.pid


def send(summary: dict, infected: list[dict], infected_timeout_s: int = 0,
         only_when_gaming: bool = False, interactive: bool = True,
         state_path: Path | str | None = None) -> bool:
    """Fire the notification. Returns True only if notify-send actually
    ran and exited successfully. Returns False if skipped (no
    notify-send), if the call itself failed, or if notify-send ran but
    exited nonzero (commonly caused by missing DBUS_SESSION_BUS_ADDRESS
    when run under sudo/cron outside the user's own session -- in that
    case notify-send fails silently from Ensign's point of view unless
    the return code is checked).

    infected_timeout_s: if > 0, the critical (infected) notification is
    closed after that many seconds instead of staying until dismissed.
    0 keeps the old behavior. Ordinary notifications are unaffected. If the
    notification's id can't be read or gdbus is missing, it simply stays
    until dismissed, as before.

    only_when_gaming / interactive: when the timeout applies (see
    _effective_timeout). `interactive` is False for a service or cron run.

    state_path: if given, the infected alert's notification id is saved
    there, and the next infected alert replaces it instead of stacking a
    second one on top (and cancels the old alert's pending close timer).
    """
    if not available():
        return False
    title, body, urgency = build_message(summary, infected)
    timeout_s = _effective_timeout(urgency, infected_timeout_s, interactive, only_when_gaming)
    critical = urgency == "critical"
    track = critical and (timeout_s > 0 or state_path is not None)
    state = _load_state(state_path) if (critical and state_path is not None) else {}

    base = ["notify-send", "-u", urgency, "-a", "Ensign"]
    if track:
        base.append("-p")  # print the new notification's id
    replace_id = state.get("id")
    if (isinstance(replace_id, int) and replace_id > 0
            and state.get("boot_id") == _boot_id() and _boot_id()):
        cmd = base + ["-r", str(replace_id), title, body]
    else:
        cmd = base + [title, body]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0 and "-r" in cmd:
            # older libnotify without --replace-id: show it, just don't replace
            result = subprocess.run(base + [title, body], capture_output=True,
                                    text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    if track:
        try:
            new_id = int(result.stdout.strip())
        except ValueError:
            new_id = None  # id not printed (older libnotify): leave it sticky
        if state_path is not None:
            _kill_close_helper(state.get("close_pid"))
        pid = _schedule_close(new_id, timeout_s) if (new_id and timeout_s > 0) else None
        if state_path is not None:
            _save_state(state_path, {"id": new_id, "boot_id": _boot_id(), "close_pid": pid}
                        if new_id else {})
    return True
