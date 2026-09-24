"""Cross-platform development sanity check script."""

import os
import subprocess
import sys


def run_step(name: str, cmd: list[str], cwd: str = ".") -> bool:
    print(f"\n--- Running {name} ---")
    print(f"Command: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        print(f"[FAIL] {name} failed with exit code {result.returncode}")
        return False
    print(f"[PASS] {name} passed.")
    return True


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    success = True

    # 1. Backend Lint
    if not run_step(
        "Backend Lint (Ruff)", [sys.executable, "-m", "ruff", "check", "backend"], cwd=root
    ):
        success = False

    # 2. Backend Tests
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(root, "backend")
    print("\n--- Running Backend Tests (Pytest) ---")
    res = subprocess.run([sys.executable, "-m", "pytest", "backend/tests"], cwd=root, env=env)
    if res.returncode != 0:
        print(f"[FAIL] Backend Tests failed with exit code {res.returncode}")
        success = False
    else:
        print("[PASS] Backend Tests passed.")

    if not success:
        sys.exit(1)
    print("\nAll checks passed successfully!")


if __name__ == "__main__":
    main()
