import argparse
import errno
import os
import pty
import select
import signal
import struct
import sys
import termios
import time


def wait_for_exit(pid: int, timeout_seconds: float) -> int | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            return status
        time.sleep(0.05)
    return None


def signal_process_group(pid: int, signal_number: int) -> None:
    try:
        os.killpg(pid, signal_number)
    except ProcessLookupError:
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--transcript", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command or args.timeout_seconds <= 0:
        parser.error("a command and positive timeout are required")
    return args


def main() -> int:
    args = parse_args()
    started = time.monotonic()
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execvpe(args.command[0], args.command, os.environ.copy())

    output = bytearray()
    deadline = started + args.timeout_seconds
    next_exit = started + 0.5
    status = None
    try:
        import fcntl

        fcntl.ioctl(descriptor, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    except OSError:
        pass

    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_exit:
            try:
                os.write(descriptor, b"/exit\r")
            except OSError:
                pass
            next_exit = now + 0.5
        readable, _, _ = select.select([descriptor], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(descriptor, 65536)
                if chunk:
                    output.extend(chunk)
                    if len(output) > 1024 * 1024:
                        del output[: len(output) - 1024 * 1024]
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
        waited_pid, waited_status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            status = waited_status
            break

    if status is None:
        signal_process_group(pid, signal.SIGTERM)
        status = wait_for_exit(pid, 1.0)
    if status is None:
        signal_process_group(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
    signal_process_group(pid, signal.SIGKILL)
    os.close(descriptor)
    with open(args.transcript, "wb") as transcript:
        transcript.write(output)

    elapsed_ms = int((time.monotonic() - started) * 1000)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        print(f"elapsed_ms={elapsed_ms}")
        return 0
    sys.stderr.buffer.write(output)
    print(f"prompt process failed after {elapsed_ms}ms", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
