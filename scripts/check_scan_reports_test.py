"""Offline regression tests for the blocking policy and malformed scan reports."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from check_scan_reports import main


def trivy_report(*vulnerabilities):
    return {
        "SchemaVersion": 2,
        "CreatedAt": "2026-11-18T20:00:00Z",
        "ArtifactName": "ticketdesk:test",
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": "sha256:" + "a" * 64},
        "Results": [{"Target": "image", "Class": "os-pkgs", "Type": "debian",
                     "Vulnerabilities": list(vulnerabilities)}],
    }


def vulnerability(severity, fixed_version=""):
    return {"VulnerabilityID": "CVE-SYNTHETIC", "PkgName": "synthetic-package",
            "InstalledVersion": "1.0", "Severity": severity, "FixedVersion": fixed_version}


def alert(plugin, risk, name="Synthetic alert"):
    reference = "90004-1" if str(plugin) == "90004" else str(plugin)
    return {"pluginid": str(plugin), "alertRef": reference, "riskcode": str(risk),
            "name": name, "instances": [{"uri": "http://app:8000/login"}]}


def zap_report(*alerts):
    return {"@generated": "Wed, 18 Nov 2026 20:00:00",
            "site": [{"@name": "http://app:8000", "alerts": list(alerts)}]}


class ScanReportTests(unittest.TestCase):
    def run_report(self, scanner, report, exit_code=None):
        with tempfile.TemporaryDirectory(prefix="ticketdesk-report-test-") as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report))
            arguments = [scanner, "--report", str(path)]
            if exit_code is not None:
                arguments += ["--exit-code", str(exit_code)]
            output, errors = StringIO(), StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                code = main(arguments)
            return code, output.getvalue(), errors.getvalue()

    def test_trivy_blocks_critical_even_without_a_fix(self):
        for fixed_version in ("", "2.0"):
            with self.subTest(fixed=fixed_version):
                code, output, _ = self.run_report(
                    "trivy", trivy_report(vulnerability("CRITICAL", fixed_version))
                )
                self.assertEqual(code, 1)
                self.assertIn("BLOCK: CRITICAL", output)

    def test_trivy_blocks_fixable_high_and_keeps_unfixed_high_visible(self):
        self.assertEqual(self.run_report("trivy", trivy_report(vulnerability("HIGH", "2.0")))[0], 1)
        code, output, _ = self.run_report("trivy", trivy_report(vulnerability("HIGH")))
        self.assertEqual(code, 0)
        self.assertIn("NONBLOCKING: HIGH", output)
        self.assertIn("fix=not available", output)

    def test_trivy_clean_report_and_lower_severities_pass(self):
        for report in (trivy_report(), trivy_report(vulnerability("LOW"), vulnerability("MEDIUM"))):
            with self.subTest(report=report):
                self.assertEqual(self.run_report("trivy", report)[0], 0)

    def test_trivy_rejects_missing_metadata_results_and_scan_errors(self):
        invalid = [None, {}, [], trivy_report()]
        invalid[-1]["Metadata"] = {}
        for key, value in [("Results", []), ("Results", None), ("Results", {}),
                           ("ArtifactType", "filesystem"), ("Error", "scan failed")]:
            report = trivy_report()
            report[key] = value
            invalid.append(report)
        for report in invalid:
            with self.subTest(report=report):
                self.assertEqual(self.run_report("trivy", report)[0], 2)

    def test_trivy_rejects_malformed_findings(self):
        fixtures = []
        for key, value in [("Severity", "unrecognized"), ("Severity", None),
                           ("FixedVersion", None), ("PkgName", "")]:
            finding = vulnerability("HIGH")
            finding[key] = value
            fixtures.append(trivy_report(finding))
        wrong_list = trivy_report()
        wrong_list["Results"][0]["Vulnerabilities"] = {}
        fixtures.append(wrong_list)
        for report in fixtures:
            with self.subTest(report=report):
                self.assertEqual(self.run_report("trivy", report)[0], 2)

    def test_zap_known_lab_risks_pass_but_remain_visible(self):
        for plugin in (10038, 10202, 90004, 10063):
            for risk in (1, 2):
                with self.subTest(plugin=plugin, risk=risk):
                    code, output, _ = self.run_report("zap", zap_report(alert(plugin, risk)), 2)
                    self.assertEqual(code, 0)
                    self.assertIn("ACCEPTED LAB RISK", output)
                    self.assertIn("not fixed", output)
                    self.assertIn(str(plugin), output)

    def test_zap_high_risk_always_blocks_including_known_plugins(self):
        for plugin in (10038, 10202, 90004, 10063, 12345):
            with self.subTest(plugin=plugin):
                code, output, _ = self.run_report("zap", zap_report(alert(plugin, 3)), 2)
                self.assertEqual(code, 1)
                self.assertIn("BLOCK: HIGH", output)

    def test_zap_known_rule_on_a_new_path_still_blocks(self):
        item = alert(10202, 2)
        item["instances"].append({"uri": "http://app:8000/admin/users/new"})
        code, output, _ = self.run_report("zap", zap_report(item), 2)
        self.assertEqual(code, 1)
        self.assertIn("BLOCK: MEDIUM 10202", output)
        self.assertNotIn("ACCEPTED LAB RISK", output)

    def test_zap_lab_scope_is_limited_to_known_paths_and_refs(self):
        for plugin, path, expected in [(10038, "/", 0), (10202, "/login", 0),
                                       (10063, "/static/style.css", 0),
                                       (90004, "/static/style.css", 0),
                                       (10038, "/static/style.css", 1)]:
            with self.subTest(plugin=plugin, path=path):
                item = alert(plugin, 2)
                item["instances"] = [{"uri": "http://app:8000" + path}]
                self.assertEqual(self.run_report("zap", zap_report(item), 2)[0], expected)
        item = alert(90004, 1)
        item["alertRef"] = "90004-99"
        self.assertEqual(self.run_report("zap", zap_report(item), 2)[0], 1)

    def test_zap_known_warning_without_valid_instances_does_not_pass(self):
        for instances in (None, [], {}, [None], [{}], [{"uri": "/login"}],
                          [{"uri": "http://[broken/login"}]):
            with self.subTest(instances=instances):
                item = alert(10202, 2)
                item["instances"] = instances
                self.assertEqual(self.run_report("zap", zap_report(item), 2)[0], 1)

    def test_zap_new_alerts_and_fixed_header_regressions_block(self):
        for plugin in (10020, 10021, 12345, 10049, 10111):
            for risk in (1, 2):
                with self.subTest(plugin=plugin, risk=risk):
                    self.assertEqual(self.run_report("zap", zap_report(alert(plugin, risk)), 0)[0], 1)

    def test_zap_informational_alerts_are_visible_and_nonblocking(self):
        code, output, _ = self.run_report(
            "zap", zap_report(alert(10049, 0), alert(10111, 0), alert(12345, 0)), 2
        )
        self.assertEqual(code, 0)
        self.assertEqual(output.count("INFO: INFO"), 3)

    def test_zap_accepts_alertref_variants_but_rejects_conflicting_ids(self):
        item = alert(90004, 1)
        item["alertRef"] = "90004-1"
        self.assertEqual(self.run_report("zap", zap_report(item), 2)[0], 0)
        no_plugin = deepcopy(item)
        del no_plugin["pluginid"]
        self.assertEqual(self.run_report("zap", zap_report(no_plugin), 2)[0], 0)
        item["alertRef"] = "12345-1"
        self.assertEqual(self.run_report("zap", zap_report(item), 2)[0], 2)

    def test_zap_scanner_fail_and_error_never_pass_even_with_clean_report(self):
        for scanner_exit, expected in [(0, 0), (2, 0), (1, 1), (3, 2), (127, 2), (-1, 2)]:
            with self.subTest(scanner_exit=scanner_exit):
                self.assertEqual(self.run_report("zap", zap_report(), scanner_exit)[0], expected)

    def test_zap_missing_sites_or_malformed_alerts_fail_closed(self):
        fixtures = [{}, None, {"@generated": "date", "site": []},
                    {"@generated": "date", "site": {}},
                    {"@generated": "date", "site": [{"@name": "app"}]},
                    {"site": [{"@name": "app", "alerts": []}]}]
        for field, value in [("riskcode", "4"), ("riskcode", True),
                             ("riskcode", "bad"), ("pluginid", "bad"), ("name", "")]:
            item = alert(10038, 2)
            item[field] = value
            fixtures.append(zap_report(item))
        for report in fixtures:
            with self.subTest(report=report):
                self.assertEqual(self.run_report("zap", report, 0)[0], 2)

    def test_missing_and_invalid_json_reports_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="ticketdesk-invalid-report-") as directory:
            path = Path(directory) / "report.json"
            for scanner in ("trivy", "zap"):
                for content in (None, "{", "not JSON"):
                    with self.subTest(scanner=scanner, content=content):
                        if content is not None:
                            path.write_text(content)
                        elif path.exists():
                            path.unlink()
                        arguments = [scanner, "--report", str(path)]
                        if scanner == "zap":
                            arguments += ["--exit-code", "0"]
                        with redirect_stderr(StringIO()):
                            self.assertEqual(main(arguments), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
