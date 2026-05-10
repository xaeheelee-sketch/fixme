from __future__ import annotations
import json as _json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(ABC):
    @abstractmethod
    def run(self, cmd: str, cwd: Path | None = None, timeout: int = 600) -> CommandResult: ...


class SubprocessRunner(CommandRunner):
    def run(self, cmd: str, cwd: Path | None = None, timeout: int = 600) -> CommandResult:
        try:
            proc = subprocess.run(
                cmd, shell=True, cwd=cwd, timeout=timeout,
                capture_output=True, text=True,
            )
            return CommandResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(124, "", f"TIMEOUT: {exc}")


class BuildRunner(ABC):
    @abstractmethod
    def build(self, cwd: Path) -> CommandResult: ...


class TestRunner(ABC):
    @abstractmethod
    def test(self, cwd: Path) -> CommandResult: ...


class SanitizerRunner(ABC):
    @abstractmethod
    def build_and_test(self, cwd: Path) -> CommandResult: ...


class MetisRunner(ABC):
    @abstractmethod
    def scan(self, cwd: Path, files: list[str] | None = None) -> dict: ...


class GitOps(ABC):
    @abstractmethod
    def current_sha(self, cwd: Path) -> str: ...
    @abstractmethod
    def create_branch(self, cwd: Path, name: str) -> None: ...
    @abstractmethod
    def commit(self, cwd: Path, message: str, files: list[str]) -> str: ...
    @abstractmethod
    def reset_hard_head_minus_one(self, cwd: Path) -> None: ...
    @abstractmethod
    def diff(self, cwd: Path, files: list[str] | None = None) -> str: ...


class CmdBuildRunner(BuildRunner):
    def __init__(self, cmd: str, runner: CommandRunner):
        self.cmd = cmd
        self.runner = runner

    def build(self, cwd: Path) -> CommandResult:
        return self.runner.run(self.cmd, cwd=cwd)


class CmdTestRunner(TestRunner):
    def __init__(self, cmd: str, runner: CommandRunner):
        self.cmd = cmd
        self.runner = runner

    def test(self, cwd: Path) -> CommandResult:
        return self.runner.run(self.cmd, cwd=cwd)


class CmdSanitizerRunner(SanitizerRunner):
    def __init__(self, build_cmd: str, test_cmd: str, runner: CommandRunner):
        self.build_cmd = build_cmd
        self.test_cmd = test_cmd
        self.runner = runner

    def build_and_test(self, cwd: Path) -> CommandResult:
        b = self.runner.run(self.build_cmd, cwd=cwd)
        if b.returncode != 0:
            return b
        return self.runner.run(self.test_cmd, cwd=cwd)


class CmdMetisRunner(MetisRunner):
    def __init__(self, cmd: str, runner: CommandRunner):
        self.cmd = cmd
        self.runner = runner

    def scan(self, cwd: Path, files: list[str] | None = None) -> dict:
        full_cmd = self.cmd
        if files:
            full_cmd = f"{self.cmd} {' '.join(files)}"
        result = self.runner.run(full_cmd, cwd=cwd)
        if result.returncode != 0:
            raise RuntimeError(f"Metis failed: {result.stderr}")
        return _json.loads(result.stdout)


class CliGitOps(GitOps):
    def __init__(self, runner: CommandRunner):
        self.runner = runner

    def current_sha(self, cwd: Path) -> str:
        return self.runner.run("git rev-parse HEAD", cwd=cwd).stdout.strip()

    def create_branch(self, cwd: Path, name: str) -> None:
        self.runner.run(f"git checkout -b {name}", cwd=cwd)

    def commit(self, cwd: Path, message: str, files: list[str]) -> str:
        self.runner.run(f"git add -- {' '.join(files)}", cwd=cwd)
        msg_escaped = message.replace('"', '\\"')
        result = self.runner.run(f'git commit -m "{msg_escaped}"', cwd=cwd)
        if result.returncode != 0:
            raise RuntimeError(f"git commit failed: {result.stderr}")
        return self.current_sha(cwd)

    def reset_hard_head_minus_one(self, cwd: Path) -> None:
        self.runner.run("git reset --hard HEAD~1", cwd=cwd)

    def diff(self, cwd: Path, files: list[str] | None = None) -> str:
        target = " -- " + " ".join(files) if files else ""
        return self.runner.run(f"git diff HEAD~1 HEAD{target}", cwd=cwd).stdout
