#!/usr/bin/env python3
"""Opt-in live regression: project isolation, parallel terminals, and resume.

Requires the updated installed CLI and its native runtime/image. Model requests
use an offline loopback fixture; no real credentials or model API are used.
Only this run's temporary workspaces, volumes, and supervisor metadata are removed.
"""

import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import shutil
import signal
import subprocess
import struct
import tempfile
import termios
import time


class Terminal:
    def __init__(self, command, workspace):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
        os.set_blocking(self.master, False)
        self.process = subprocess.Popen(
            command, cwd=workspace, stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True,
        )
        os.close(slave)
        self.output = bytearray()
        self.queries = {}

    def pump(self):
        if select.select([self.master], [], [], 0.02)[0]:
            try:
                self.output.extend(os.read(self.master, 65536))
            except OSError:
                pass
        # Supply the terminal capability replies a real terminal sends. Without
        # these, Codex can wait for foreground/background/cursor detection.
        for query, response in (
            (b"\x1b]10;?\x1b\\", b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\"),
            (b"\x1b]11;?\x1b\\", b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
            (b"\x1b[6n", b"\x1b[1;1R"),
            (b"\x1b[?u", b"\x1b[?0u"),
            (b"\x1b[c", b"\x1b[?1;2c"),
        ):
            count = self.output.count(query)
            previous = self.queries.get(query, 0)
            if count > previous and self.process.poll() is None:
                os.write(self.master, response * (count - previous))
            self.queries[query] = count

    def send(self, text):
        os.write(self.master, text.encode())

    def wait(self, timeout=60):
        deadline = time.monotonic() + timeout
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump()
        self.pump()
        if self.process.poll() is None:
            raise RuntimeError("terminal did not finish")
        return self.process.returncode

    def text(self):
        return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", self.output.decode(errors="replace"))

    def close(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.wait(15)
            except RuntimeError:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        os.close(self.master)


def wait_file(filename, terminals, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        if filename.exists():
            value = filename.read_text().strip()
            if value:
                return value  # Creation can be visible before the guest write.
        for terminal in terminals:
            terminal.pump()
            if terminal.process.poll() is not None:
                raise RuntimeError("fixture shell exited before producing its marker: " + terminal.text())
        if time.monotonic() > deadline:
            raise RuntimeError("fixture marker did not appear")


def project_metadata(state, workspace):
    canonical = str(workspace.resolve())
    for filename in (state / "p").glob("*/project.json"):
        item = json.loads(filename.read_text())
        if item.get("workspace") == canonical:
            assert re.fullmatch(r"[0-9a-f]{32}", item["id"])
            assert filename.parent.name == item["id"]
            return filename.parent, item["id"]
    raise RuntimeError("project metadata was not created")


def thread_id(terminal):
    for line in terminal.text().splitlines():
        if line.startswith("{"):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "thread.started":
                value = event.get("thread_id", "")
                assert re.fullmatch(r"[a-f0-9-]{36}", value)
                return value
    raise RuntimeError("Codex did not report a thread: " + terminal.text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", default=shutil.which("envvault"))
    args = parser.parse_args()
    if not args.cli:
        parser.error("install the updated EnvVault CLI first")
    cli = str(Path(args.cli).resolve())
    setup = subprocess.check_output([cli, "sandbox", "setup"], text=True)
    helper = next((line.removeprefix("Microsandbox helper ready: ")
                   for line in setup.splitlines() if line.startswith("Microsandbox helper ready: ")), None)
    if not helper:
        raise RuntimeError("setup did not return its managed helper")
    state = Path(os.environ.get("MSB_HOME", Path.home() / ".envvault-msb-trial")).resolve()
    msb = str(state / "bin/msb")
    runtime_env = dict(os.environ, MSB_HOME=str(state))

    def sandboxes():
        return set(subprocess.check_output([msb, "list", "--quiet"], env=runtime_env, text=True).splitlines())

    def wait_removed(names):
        deadline = time.monotonic() + 40
        while names & sandboxes():
            if time.monotonic() > deadline:
                raise RuntimeError("project VMs were not cleaned up after their last terminal")
            time.sleep(0.1)

    original = sandboxes()
    terminals, owned = [], []
    with tempfile.TemporaryDirectory(prefix="envvault-session-regression-") as directory:
        a, b = Path(directory) / "project a", Path(directory) / "project b"
        a.mkdir()
        b.mkdir()

        def start(command, workspace):
            terminal = Terminal(command, workspace)
            terminals.append(terminal)
            return terminal

        def shell(workspace, marker):
            terminal = start([helper, "shell", "--workspace", str(workspace)], workspace)
            terminal.send("git init --quiet /workspace\ncat /proc/sys/kernel/random/boot_id > /workspace/" + shlex.quote(marker) + "\n")
            boot = wait_file(workspace / marker, [terminal])
            return terminal, boot

        def offline_exec(workspace, extra):
            terminal = start([cli, "sandbox", "codex", "exec", "--json", *extra], workspace)
            # Connection refusal/denial from the loopback fixture is expected.
            if terminal.wait() != 1:
                raise RuntimeError("offline exec returned an unexpected status: " + terminal.text())
            return thread_id(terminal)

        def interactive_resume(workspace, extra, expected):
            terminal = start([cli, "sandbox", "codex", "resume", *extra,
                              "--include-non-interactive", "--no-alt-screen"], workspace)
            deadline = time.monotonic() + 30
            while not all(value in terminal.text() for value in expected):
                terminal.pump()
                if terminal.process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("interactive resume did not show fixture history: " + terminal.text())
            for _ in range(2):
                if terminal.process.poll() is not None:
                    break
                try:
                    terminal.send("\x03")
                except OSError as error:
                    if error.errno == errno.EIO:
                        break  # The picker can exit on the first Ctrl+C.
                    raise
                for _ in range(10):
                    terminal.pump()
            if terminal.wait(20) not in (0, 130):
                raise RuntimeError("interactive resume did not exit cleanly: " + terminal.text())

        try:
            first, boot_a = shell(a, "first-boot")
            second, boot_a2 = shell(a, "second-boot")
            foreign, boot_b = shell(b, "other-boot")
            assert boot_a == boot_a2 and boot_a != boot_b, (boot_a, boot_a2, boot_b)
            owned = [project_metadata(state, a), project_metadata(state, b)]
            names = {"envvault-project-" + value for _, value in owned}
            assert len(sandboxes() - original) == 2
            print("PASS: parallel terminals share one project VM; another project has a separate VM", flush=True)

            first.send("printf 'fixture-a' > /home/agent/.envvault-fixture\nexit\n")
            assert first.wait() == 0
            second.send("test -f /home/agent/.envvault-fixture && cat /proc/sys/kernel/random/boot_id > /workspace/after-first-exit\n")
            assert wait_file(a / "after-first-exit", [second]) == boot_a
            foreign.send("test ! -e /home/agent/.envvault-fixture && printf isolated > /workspace/isolation\n")
            assert wait_file(b / "isolation", [foreign]) == "isolated"
            print("PASS: exiting one terminal keeps the other alive; writable session files stay project-private", flush=True)

            # This fresh fixture project contains only a dummy key. All model
            # traffic targets a closed guest loopback port, never an API service.
            config = '''model = "offline-fixture"
model_provider = "fixture"
check_for_update_on_startup = false
[projects."/workspace"]
trust_level = "trusted"
[model_providers.fixture]
name = "Offline regression fixture"
base_url = "http://127.0.0.1:9/v1"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
'''
            second.send("mkdir -p \"$CODEX_HOME\"\ncat > \"$CODEX_HOME/config.toml\" <<'FIXTURE_CONFIG'\n" + config + "FIXTURE_CONFIG\n")
            auth = json.dumps({"OPENAI_API_KEY": "offline-fixture-value"})
            second.send("printf '%s' " + shlex.quote(auth) + " > \"$CODEX_HOME/auth.json\"\nchmod 0600 \"$CODEX_HOME/auth.json\"\nprintf ready > /workspace/offline-ready\n")
            wait_file(a / "offline-ready", [second])
            alpha = offline_exec(a, ["offline fixture alpha"])
            time.sleep(1)
            beta = offline_exec(a, ["offline fixture beta"])
            assert alpha != beta
            assert offline_exec(a, ["resume", "--last", "offline follow-up"]) == beta
            assert offline_exec(a, ["resume", alpha, "offline follow-up"]) == alpha
            print("PASS: Codex resume --last and explicit conversation IDs find history across terminal launches", flush=True)
            time.sleep(1)
            offline_exec(a, ["offline fixture newest"])
            interactive_resume(a, [], ["offline fixture alpha", "offline fixture beta", "offline fixture newest"])
            interactive_resume(a, ["--last"], ["offline fixture newest"])
            interactive_resume(a, [alpha], ["offline fixture alpha"])
            print("PASS: interactive Codex resume picker, --last, and conversation IDs use project history", flush=True)

            second.send("exit\n")
            foreign.send("exit\n")
            assert second.wait() == foreign.wait() == 0
            wait_removed(names)
            assert offline_exec(a, ["resume", alpha, "offline follow-up after restart"]) == alpha
            wait_removed(names)
            print("PASS: Codex history survives project VM shutdown and restart", flush=True)

            crash_terminal, _ = shell(a, "before-supervisor-crash")
            metadata, _ = project_metadata(state, a)
            owner = int((metadata / "owner.lock").read_text().strip())
            assert owner > 1 and owner != os.getpid()
            assert owner not in {terminal.process.pid for terminal in terminals}
            os.kill(owner, signal.SIGKILL)  # Only this temporary project's supervisor.
            assert crash_terminal.wait(20) == 1
            assert "supervision was lost" in crash_terminal.text()
            assert offline_exec(a, ["resume", alpha, "offline follow-up after supervisor recovery"]) == alpha
            wait_removed(names)
            print("PASS: supervisor loss cancels its terminal; the next launch safely recovers project history", flush=True)
            assert original <= sandboxes()
            print("PASS: pre-existing sandboxes were left running", flush=True)
        finally:
            for terminal in terminals:
                terminal.close()
            # Discover only this run's generated project associations, including
            # partial runs that failed before both projects finished booting.
            for workspace in (a, b):
                try:
                    item = project_metadata(state, workspace)
                    if item not in owned:
                        owned.append(item)
                except RuntimeError:
                    pass
            names = {"envvault-project-" + value for _, value in owned}
            wait_removed(names)
            for metadata, identity in owned:
                subprocess.run([msb, "volume", "remove", "--quiet", "envvault-project-home-" + identity], env=runtime_env, check=True)
                shutil.rmtree(metadata)


if __name__ == "__main__":
    main()
