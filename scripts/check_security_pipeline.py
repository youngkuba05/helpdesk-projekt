"""Local negative tests: prove that scanners and the deployment gate reject problems.

Install security/requirements.txt and put the pinned Gitleaks on PATH first.
TICKETDESK_TEST_SCA=1 also enables a test against the public advisory database.
Fixtures live only in temporary directories, never in the real repository history.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run_security.py"
WORKFLOW = yaml.load((ROOT / ".github/workflows/ci-cd.yml").read_text(), Loader=yaml.BaseLoader)


class SecurityChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ticketdesk-security-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.target = self.base / "source"
        self.target.mkdir()
        self.reports = self.base / "reports"

    def scan(self, mode):
        return subprocess.run([sys.executable, str(RUNNER), mode, "--target", str(self.target),
                               "--report-dir", str(self.reports)],
                              capture_output=True, text=True, check=False)

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.target), *args], check=True, capture_output=True)

    def init_repo(self):
        self.git("init", "-q")
        self.git("config", "user.name", "Security test")
        self.git("config", "user.email", "security-test@example.invalid")
        (self.target / "readme.txt").write_text("Synthetic scanner fixture\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Initial fixture")

    def test_sast_rejects_unsafe_code_then_accepts_fix(self):
        source = self.target / "example.py"
        source.write_text('def unsafe(value):\n    return eval(value)\n')
        self.assertEqual(self.scan("sast").returncode, 1)
        findings = json.loads((self.reports / "bandit.json").read_text())["results"]
        self.assertTrue(any(item["test_id"] == "B307" for item in findings))
        source.write_text('def safe(value):\n    return value\n')
        self.assertEqual(self.scan("sast").returncode, 0)

    def test_secrets_detect_removed_history_and_redact_reports(self):
        self.init_repo()
        # Construct an invalid synthetic PAT in memory; never commit it to TicketDesk.
        synthetic = "".join(("gh", "p_", "a1B2c3D4e5F6" * 3))
        source = self.target / "example.txt"
        source.write_text(f'api_token = "{synthetic}"\n')
        result = self.scan("secrets")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(synthetic, result.stdout + result.stderr)
        report = (self.reports / "gitleaks-dir.json").read_text()
        self.assertNotIn(synthetic, report)
        self.assertTrue(json.loads(report))
        self.git("add", ".")
        self.git("commit", "-qm", "Add synthetic fixture")
        source.write_text("Removed fixture\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Remove synthetic fixture")
        result = self.scan("secrets")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads((self.reports / "gitleaks-dir.json").read_text()), [])
        history = (self.reports / "gitleaks-git.json").read_text()
        self.assertTrue(json.loads(history))
        self.assertNotIn(synthetic, history + result.stdout + result.stderr)

    def test_sast_report_does_not_publish_passwords(self):
        synthetic = "".join(("gh", "p_", "a1B2c3D4e5F6" * 3))
        (self.target / "example.py").write_text(f'password = "{synthetic}"\n')
        result = self.scan("sast")
        self.assertEqual(result.returncode, 1)
        report = (self.reports / "bandit.json").read_text()
        self.assertNotIn(synthetic, report + result.stdout + result.stderr)
        self.assertTrue(json.loads(report)["results"])

    def test_demo_exception_is_limited_to_one_value_and_one_file(self):
        self.init_repo()
        allowed = self.target / "ticketdesk/tests/test_ticket_flow.py"
        allowed.parent.mkdir(parents=True)
        # Build this negative-test fixture in memory, just like the synthetic PAT.
        demo_credential = "pracownik" + "123"
        allowed.write_text('credentials = {"password": "' + demo_credential + '"}\n')
        self.assertEqual(self.scan("secrets").returncode, 0)
        (self.target / "outside.py").write_text(allowed.read_text())
        self.assertEqual(self.scan("secrets").returncode, 1)
        (self.target / "outside.py").unlink()
        synthetic = "".join(("gh", "p_", "a1B2c3D4e5F6" * 3))
        allowed.write_text(f'api_token = "{synthetic}"\n')
        self.assertEqual(self.scan("secrets").returncode, 1)

    def test_scanner_error_is_not_success(self):
        self.assertNotEqual(self.scan("secrets").returncode, 0)  # Not a Git repository.
        (self.target / "syntax_error.py").write_text("def broken(\n")
        self.assertNotEqual(self.scan("sast").returncode, 0)

    @unittest.skipUnless(os.getenv("TICKETDESK_TEST_SCA") == "1", "SCA fixture requires network")
    def test_sca_rejects_known_vulnerable_dependency(self):
        self.target = self.base / "vulnerable-requirements.txt"
        self.target.write_text("jinja2==3.1.3\n")
        self.assertEqual(self.scan("sca").returncode, 1)
        dependencies = json.loads((self.reports / "pip-audit.json").read_text())["dependencies"]
        self.assertTrue(any(item["vulns"] for item in dependencies))


class DeploymentGateChecks(unittest.TestCase):
    def test_gate_blocks_failure_skipped_cancelled_and_missing_checks(self):
        gate = WORKFLOW["jobs"]["security-gate"]
        self.assertEqual(set(gate["needs"]), {"test", "sast", "sca", "secrets", "image-security"})
        self.assertEqual(gate["if"], "${{ always() }}")
        shell = gate["steps"][0]["run"]

        def run_gate(results):
            return subprocess.run(["bash", "-e", "-c", shell],
                                  env={**os.environ, "RESULTS": json.dumps(results),
                                       "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]},
                                  capture_output=True, check=False).returncode

        success = {name: {"result": "success"} for name in gate["needs"]}
        self.assertEqual(run_gate(success), 0)
        for name in gate["needs"]:
            for status in ("failure", "skipped", "cancelled"):
                with self.subTest(job=name, status=status):
                    self.assertNotEqual(run_gate({**success, name: {"result": status}}), 0)
            self.assertNotEqual(run_gate({key: value for key, value in success.items() if key != name}), 0)

    def test_deployment_only_after_gate_and_only_on_main_outside_pr(self):
        jobs = WORKFLOW["jobs"]
        self.assertEqual(jobs["deploy"]["needs"], "security-gate")
        self.assertEqual(jobs["deploy"]["if"],
                         "github.event_name != 'pull_request' && github.ref == 'refs/heads/main'")
        self.assertIn("lab6-security", WORKFLOW["on"]["push"]["branches"])
        self.assertIn("pull_request", WORKFLOW["on"])
        for name in ("test", "sast", "sca", "secrets", "image-security"):
            self.assertNotIn("continue-on-error", jobs[name])
            for step in jobs[name]["steps"]:
                self.assertNotIn("continue-on-error", step)
                self.assertNotIn("secrets.AWS", json.dumps(step))

    def test_deployment_uses_the_checked_image_and_verifies_before_ecs(self):
        steps = WORKFLOW["jobs"]["deploy"]["steps"]
        runs = "\n".join(step.get("run", "") for step in steps)
        self.assertNotIn("docker build", runs)
        self.assertTrue(any("actions/download-artifact@" in step.get("uses", "") for step in steps))
        signature = next(step for step in steps if step.get("name") == "Podpisanie i weryfikacja obrazu")
        render = next(step for step in steps if step.get("id") == "render")
        self.assertEqual(signature["env"]["IMAGE"], "${{ steps.image.outputs.image }}")
        self.assertEqual(render["with"]["image"], signature["env"]["IMAGE"])
        self.assertEqual(signature["env"]["EXPECTED_IDENTITY"],
                         "https://github.com/${{ github.repository }}/.github/workflows/ci-cd.yml@refs/heads/main")
        self.assertLess(steps.index(signature), steps.index(render))
        self.assertNotIn("continue-on-error", signature)


class SignatureChecks(unittest.TestCase):
    """Run the real signing shell with a local stand-in, never with registry access."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ticketdesk-signature-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.log = self.base / "cosign-calls.jsonl"
        mock = self.base / "cosign"
        mock.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['COSIGN_TEST_LOG'], 'a') as stream:\n"
            "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "status = 'SIGN_TEST_EXIT' if sys.argv[1] == 'sign' else 'VERIFY_TEST_EXIT'\n"
            "sys.exit(int(os.environ.get(status, '0')))\n"
        )
        mock.chmod(0o700)
        self.step = next(step for step in WORKFLOW["jobs"]["deploy"]["steps"]
                         if step.get("name") == "Podpisanie i weryfikacja obrazu")
        self.image = "registry.example.invalid/ticketdesk@sha256:" + "a" * 64
        self.identity = "https://github.com/example/ticketdesk/.github/workflows/ci-cd.yml@refs/heads/main"

    def run_signature(self, sign_status=0, verify_status=0):
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", self.step["run"]],
            env={**os.environ, "PATH": str(self.base) + os.pathsep + os.environ["PATH"],
                 "IMAGE": self.image, "EXPECTED_IDENTITY": self.identity,
                 "COSIGN_TEST_LOG": str(self.log), "SIGN_TEST_EXIT": str(sign_status),
                 "VERIFY_TEST_EXIT": str(verify_status)},
            capture_output=True, text=True, check=False,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def test_success_signs_and_verifies_same_digest_with_exact_identity_and_issuer(self):
        result, calls = self.run_signature()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[0] for call in calls], ["sign", "verify"])
        for call in calls:
            self.assertIn(self.image, call)
        verification = calls[1]
        for option, expected in (
            ("--certificate-identity", self.identity),
            ("--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"),
        ):
            self.assertIn(option, verification)
            self.assertEqual(verification[verification.index(option) + 1], expected)
        self.assertFalse(any(option.startswith("--insecure-ignore") for option in verification))

    def test_signing_failure_stops_before_verification(self):
        result, calls = self.run_signature(sign_status=17)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[0] for call in calls], ["sign"])

    def test_invalid_signature_blocks_deployment(self):
        result, calls = self.run_signature(verify_status=19)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[0] for call in calls], ["sign", "verify"])


class ImageDigestChecks(unittest.TestCase):
    """Exercise the publish shell without contacting Docker or AWS."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ticketdesk-digest-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.output = self.base / "github-output.txt"
        for name, body in {
            "docker": "import sys\nsys.exit(0)\n",
            "aws": ("import os, sys\n"
                    "print(os.environ['DIGEST_TEST_VALUE'])\n"
                    "sys.exit(int(os.environ.get('AWS_TEST_EXIT', '0')))\n"),
        }.items():
            tool = self.base / name
            tool.write_text(f"#!{sys.executable}\n" + body)
            tool.chmod(0o700)
        self.step = next(step for step in WORKFLOW["jobs"]["deploy"]["steps"]
                         if step.get("id") == "image")

    def run_publish(self, digest, aws_status=0):
        self.output.write_text("")
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", self.step["run"]],
            env={**os.environ, "PATH": str(self.base) + os.pathsep + os.environ["PATH"],
                 "GITHUB_OUTPUT": str(self.output), "REGISTRY": "registry.example.invalid",
                 "ECR_REPOSITORY": "ticketdesk-app", "TAG": "synthetic-revision",
                 "DIGEST_TEST_VALUE": digest, "AWS_TEST_EXIT": str(aws_status)},
            capture_output=True, text=True, check=False,
        )
        return result, self.output.read_text()

    def test_valid_registry_digest_is_the_only_image_output(self):
        digest = "sha256:" + "a" * 64
        result, output = self.run_publish(digest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, f"image=registry.example.invalid/ticketdesk-app@{digest}\n")

    def test_missing_or_malformed_registry_digest_blocks_publication_output(self):
        for digest in ("None", "", "sha256:abc", "sha512:" + "a" * 64):
            with self.subTest(digest=digest):
                result, output = self.run_publish(digest)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")

    def test_registry_command_error_blocks_even_with_a_valid_digest(self):
        result, output = self.run_publish("sha256:" + "a" * 64, aws_status=13)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")


class ImageArtifactChecks(unittest.TestCase):
    """Check archive integrity and identity using the real deployment shell."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ticketdesk-artifact-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.log = self.base / "docker-calls.jsonl"
        self.image_id = "sha256:" + "a" * 64
        (self.base / "image-id.txt").write_text(self.image_id + "\n")
        payload = b"Synthetic image archive for checksum test\n"
        (self.base / "image.tar").write_bytes(payload)
        (self.base / "image.tar.sha256").write_text(hashlib.sha256(payload).hexdigest() + "  image.tar\n")
        mock = self.base / "docker"
        mock.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['ARTIFACT_TEST_LOG'], 'a') as stream:\n"
            "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1:3] == ['image', 'inspect']:\n"
            "    print(os.environ['ARTIFACT_TEST_IMAGE_ID'])\n"
            "elif sys.argv[1] != 'load':\n"
            "    sys.exit(2)\n"
        )
        mock.chmod(0o700)
        self.step = next(step for step in WORKFLOW["jobs"]["deploy"]["steps"]
                         if step.get("name") == "Weryfikacja i wczytanie sprawdzonego obrazu")

    def run_load(self, loaded_id=None):
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", self.step["run"]],
            cwd=self.base,
            env={**os.environ, "PATH": str(self.base) + os.pathsep + os.environ["PATH"],
                 "ARTIFACT_TEST_LOG": str(self.log),
                 "ARTIFACT_TEST_IMAGE_ID": loaded_id or self.image_id},
            capture_output=True, text=True, check=False,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def test_checked_archive_and_matching_image_are_accepted(self):
        result, calls = self.run_load()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[0] for call in calls], ["load", "image"])

    def test_changed_archive_is_rejected_before_docker_load(self):
        (self.base / "image.tar").write_bytes(b"Modified archive\n")
        result, calls = self.run_load()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_different_loaded_image_is_rejected(self):
        result, calls = self.run_load(loaded_id="sha256:" + "b" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[0] for call in calls], ["load", "image"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
