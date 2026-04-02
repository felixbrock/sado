import asyncio

# Hardcoded safe PATH — never use PATH from the environment
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
TIMEOUT = 30


async def execute(command: str, args: list[str], cwd: str) -> tuple[str, str, int]:
    """Run command as root, capture stdout/stderr. Raises on timeout."""
    env = {"PATH": SAFE_PATH}

    proc = await asyncio.create_subprocess_exec(
        command,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )

    try:
        raw_stdout, raw_stderr = await asyncio.wait_for(
            proc.communicate(), timeout=TIMEOUT
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise

    stdout = raw_stdout.decode(errors="replace")
    stderr = raw_stderr.decode(errors="replace")
    exit_code = proc.returncode if proc.returncode is not None else 1
    return stdout, stderr, exit_code
