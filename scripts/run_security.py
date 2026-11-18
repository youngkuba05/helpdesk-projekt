"""Run blocking security checks and save reports outside the scanned repository."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def scan_sast(target: Path, reports: Path) -> int:
    """Bandit findings may quote passwords: publish only location and rule metadata."""
    with tempfile.TemporaryDirectory(prefix="ticketdesk-bandit-") as temp:
        raw = Path(temp) / "bandit.json"
        command = [sys.executable, "-m", "bandit", "-r", str(target),
                   "--severity-level", "all", "--confidence-level", "all",
                   "--format", "json", "--output", str(raw)]
        result = subprocess.run(command, capture_output=True, check=False)
        try:
            report = json.loads(raw.read_text())
            findings = report["results"]
            errors = report["errors"]
            if not isinstance(findings, list) or not isinstance(errors, list):
                raise ValueError("Invalid report structure")
            safe = {"results": [{key: item.get(key) for key in
                                 ("filename", "line_number", "test_id", "issue_severity",
                                  "issue_confidence", "issue_cwe", "more_info")}
                                for item in findings],
                    "errors": [{"filename": item.get("filename")} for item in errors]}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            print("SAST did not produce a valid report.", file=sys.stderr)
            return 2
        (reports / "bandit.json").write_text(json.dumps(safe, indent=2) + "\n")
        print(f"SAST: {len(findings)} finding(s), {len(errors)} file error(s).")
        # Bandit can exit zero for unparseable files: these must still block CI.
        if errors or result.returncode not in (0, 1):
            return 2
        return int(bool(findings) or result.returncode != 0)


def scan_secrets(target: Path, reports: Path) -> int:
    """Publish only metadata; discard scanner output and raw JSON."""
    repository = subprocess.run(["git", "-C", str(target), "rev-parse", "--show-toplevel"],
                                capture_output=True, text=True, check=False)
    if repository.returncode != 0 or Path(repository.stdout.strip()).resolve() != target:
        print("Secret scanning requires the root of a Git repository.", file=sys.stderr)
        return 2
    failed = False
    with tempfile.TemporaryDirectory(prefix="ticketdesk-gitleaks-") as temp:
        for mode in ("git", "dir"):
            raw = Path(temp) / f"{mode}.json"
            command = ["gitleaks", mode, "--redact=100", "--no-banner",
                       f"--config={ROOT / '.gitleaks.toml'}",
                       "--report-format=json", f"--report-path={raw}"]
            if mode == "git":
                command.append("--log-opts=--all")
            command.append(str(target))
            result = subprocess.run(command, cwd=target, capture_output=True, check=False)
            if result.returncode not in (0, 1) or not raw.is_file():
                print(f"Gitleaks {mode}: scanner error (exit {result.returncode}).", file=sys.stderr)
                failed = True
                continue
            try:
                findings = json.loads(raw.read_text())
                if not isinstance(findings, list):
                    raise ValueError("Expected a JSON list")
                safe = [{key: finding.get(key) for key in
                         ("RuleID", "File", "StartLine", "EndLine", "Commit", "Fingerprint")}
                        for finding in findings]
            except (ValueError, TypeError, AttributeError):
                print(f"Gitleaks {mode}: invalid report.", file=sys.stderr)
                failed = True
                continue
            (reports / f"gitleaks-{mode}.json").write_text(json.dumps(safe, indent=2) + "\n")
            print(f"Gitleaks {mode}: {len(safe)} finding(s).")
            failed = failed or bool(findings) or result.returncode != 0
    return int(failed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("sast", "sca", "secrets"))
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--target", type=Path, help="Override the default scan target")
    args = parser.parse_args()
    reports = args.report_dir.resolve()
    if reports.is_relative_to(ROOT):
        parser.error("Reports must be outside the repository (e.g. /tmp/ticketdesk-reports).")
    reports.mkdir(parents=True, exist_ok=True)
    defaults = {"sast": ROOT / "ticketdesk/app",
                "sca": ROOT / "ticketdesk/requirements-test.txt", "secrets": ROOT}
    target = (args.target or defaults[args.check]).resolve()
    if not target.exists():
        parser.error("Scan target does not exist.")
    try:
        if args.check == "secrets":
            return scan_secrets(target, reports)
        if args.check == "sast":
            return scan_sast(target, reports)
        command = [sys.executable, "-m", "pip_audit", "--requirement", str(target),
                   "--strict", "--format", "json", "--progress-spinner", "off",
                   "--output", str(reports / "pip-audit.json")]
        return subprocess.run(command, check=False).returncode
    except OSError as error:
        print(f"Unable to start scanner: {error.strerror}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
