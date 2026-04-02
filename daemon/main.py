"""
sado daemon — runs as root, listens on a Unix domain socket.

Start via systemd socket activation (sado.socket + sado.service) or directly:
    python -m daemon.main
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .executor import execute
from .judge import judge
from .protocol import Request, Response

SOCKET_PATH = "/run/sado/judge.sock"
AUDIT_LOG = "/var/log/sado/audit.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("sado")

# Policy cache
_policy_text: str = ""
_policy_mtime: float = 0.0

# Per-session sado decision history: session_id → list of decision dicts
_session_history: dict[str, list[dict]] = {}


def _scrub_command(command: str, args: list[str]) -> str:
    """
    Return a loggable representation of the command: keep the command name and
    any flag tokens (starting with '-'), drop positional arguments and flag
    values to avoid logging PII such as usernames, file paths, or passwords.

    Example: useradd -m -s /bin/bash john  →  useradd -m -s
    """
    flags = [token for token in args if token.startswith("-")]
    if flags:
        return command + " " + " ".join(flags)
    return command


def _write_audit(entry: dict) -> None:
    """Append a single JSON line to the audit log. Creates the log dir if needed."""
    audit_path = Path(os.environ.get("SADO_AUDIT_LOG", AUDIT_LOG))
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        log.error("Failed to write audit log: %s", exc)


TRANSCRIPT_TURNS = 30  # max conversation turns to include from the transcript


def _read_transcript(path: str) -> str:
    """
    Read a Claude Code session JSONL transcript and return a formatted string
    of the last TRANSCRIPT_TURNS turns: user messages, assistant reasoning,
    and tool results. Skips tool_use blocks (those are in agent_log already).
    """
    if not path:
        return "(no transcript path provided)"
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        return f"(transcript unreadable: {exc})"

    turns = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Support both bare message objects and envelope-wrapped ones
        msg = entry.get("message", entry)
        role = msg.get("role", entry.get("role", ""))
        content = msg.get("content", entry.get("content", ""))

        if not role:
            continue

        text_parts = []
        if isinstance(content, str):
            text_parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_result":
                        # Include brief tool result so the judge can see outcomes
                        result_content = block.get("content", "")
                        if isinstance(result_content, list):
                            result_content = " ".join(
                                b.get("text", "") for b in result_content
                                if isinstance(b, dict) and b.get("type") == "text"
                            )
                        if result_content:
                            text_parts.append(f"[tool result] {str(result_content)[:300]}")
                    # Skip tool_use blocks — covered by agent_log

        text = "\n".join(t for t in text_parts if t.strip())
        if text.strip():
            turns.append((role, text.strip()))

    recent = turns[-TRANSCRIPT_TURNS:]
    if not recent:
        return "(transcript is empty or unrecognised format)"

    formatted = []
    for role, text in recent:
        label = "User" if role == "user" else "Agent"
        # Truncate very long turns
        if len(text) > 800:
            text = text[:800] + "…"
        formatted.append(f"[{label}]\n{text}")

    return "\n\n".join(formatted)


def _load_policy() -> str:
    """Load policy from SADO_POLICY env var path, caching by mtime."""
    global _policy_text, _policy_mtime

    path_str = os.environ.get("SADO_POLICY", "")
    if not path_str:
        return "(no policy file configured)"

    path = Path(path_str)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return "(policy file not readable)"

    if mtime != _policy_mtime:
        _policy_text = path.read_text()
        _policy_mtime = mtime
        log.info("Policy loaded from %s", path)

    return _policy_text


async def handle_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    peer = writer.get_extra_info("peername") or "unknown"
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not line:
            return

        try:
            data = json.loads(line)
            request = Request.from_dict(data)
        except Exception as exc:
            response = Response.deny(f"Malformed request: {exc}")
            writer.write(response.to_json().encode() + b"\n")
            await writer.drain()
            _write_audit({
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": None,
                "verdict": "DENY",
                "command": "(unparseable request)",
                "reason": response.reason,
            })
            return

        log.info(
            "Request from %s: session=%s %s %s (cwd=%s)",
            peer,
            request.session_id,
            request.command,
            request.args,
            request.cwd,
        )

        policy = _load_policy()
        sado_history = _session_history.get(request.session_id, [])
        transcript = _read_transcript(request.transcript_path)

        try:
            verdict, reason = await judge(
                policy=policy,
                command=request.command,
                args=request.args,
                cwd=request.cwd,
                goal=request.goal,
                agent_log=request.agent_log,
                sado_history=sado_history,
                transcript=transcript,
            )
        except Exception as exc:
            log.exception("Judge call failed")
            response = Response.deny(f"Judge unavailable: {exc}")
            writer.write(response.to_json().encode() + b"\n")
            await writer.drain()
            _write_audit({
                "ts": datetime.now(timezone.utc).isoformat(),
                "session_id": request.session_id,
                "verdict": "DENY",
                "command": _scrub_command(request.command, request.args),
                "reason": response.reason,
            })
            return

        log.info("Judge verdict: %s — %s", verdict, reason)

        scrubbed = _scrub_command(request.command, request.args)

        # Record this decision in the per-session in-memory history
        _session_history.setdefault(request.session_id, []).append({
            "verdict": verdict,
            "command": scrubbed,
            "reason": reason,
        })

        # Write to the persistent audit log
        _write_audit({
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": request.session_id,
            "verdict": verdict,
            "command": scrubbed,
            "reason": reason,
        })

        if verdict == "ALLOW":
            try:
                stdout, stderr, exit_code = await execute(
                    request.command, request.args, request.cwd
                )
                response = Response(
                    verdict="ALLOW",
                    reason=reason,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                )
            except asyncio.TimeoutError:
                response = Response.deny("Command timed out after 30 seconds.")
            except Exception as exc:
                response = Response.deny(f"Execution error: {exc}")
        else:
            response = Response.deny(reason)

        writer.write(response.to_json().encode() + b"\n")
        await writer.drain()

    except Exception:
        log.exception("Unhandled error in connection handler")
        try:
            response = Response.deny("Internal daemon error.")
            writer.write(response.to_json().encode() + b"\n")
            await writer.drain()
        except Exception:
            pass
    finally:
        writer.close()


async def _main() -> None:
    socket_path = os.environ.get("SADO_SOCKET", SOCKET_PATH)

    # Systemd socket activation: sd_listen_fds passes an open fd as fd 3
    # If SD_LISTEN_FDS_START (fd 3) is available, use it directly.
    listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    if listen_fds >= 1:
        import socket

        sock = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
        sock.setblocking(False)
        server = await asyncio.start_unix_server(handle_connection, sock=sock)
        log.info("Listening via systemd socket activation (fd 3)")
    else:
        # Direct launch: create the socket ourselves
        Path(socket_path).parent.mkdir(parents=True, exist_ok=True)
        # Remove stale socket file if present
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
        server = await asyncio.start_unix_server(handle_connection, path=socket_path)
        os.chmod(socket_path, 0o660)
        log.info("Listening on %s", socket_path)

    async with server:
        await server.serve_forever()


def main() -> None:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
