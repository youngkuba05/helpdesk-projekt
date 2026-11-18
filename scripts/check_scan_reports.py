"""Apply the LAB6 policy to complete Trivy and ZAP JSON reports.

Exit 0: policy passed; 1: blocking findings; 2: scanner/report error.
The caller must also require Trivy itself to finish successfully. A JSON report
cannot establish whether a later scanner invocation failed or reused an old file.
"""
import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


# Accepted laboratory risks remain in the report and console, not marked fixed.
ZAP_LAB_RISKS = {
    "10038": "CSP is not enforced; a Report-Only policy does not fix this",
    "10202": "anti-CSRF protection is incomplete",
    "90004": "cross-origin isolation policies are not configured",
    "10063": "Permissions-Policy is not configured",
}
ZAP_LAB_PATHS = {
    "10038": {"/", "/login"},
    "10202": {"/", "/login"},
    "90004": {"/", "/login", "/static/style.css"},
    "10063": {"/", "/login", "/static/style.css"},
}
RISK_NAMES = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}


def nonempty_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or invalid {field}")
    return value


def check_trivy(report):
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ValueError("Expected a Trivy SchemaVersion 2 report")
    if report.get("ArtifactType") != "container_image":
        raise ValueError("Expected a container image scan")
    nonempty_string(report.get("ArtifactName"), "ArtifactName")
    nonempty_string(report.get("CreatedAt"), "CreatedAt")
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", str(metadata.get("ImageID", ""))
    ):
        raise ValueError("Missing or invalid image scan metadata")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Expected nonempty Trivy Results")
    if report.get("Error") or report.get("Errors"):
        raise ValueError("Trivy report contains scan errors")

    findings = []
    for result in results:
        if not isinstance(result, dict) or result.get("Error") or result.get("Errors"):
            raise ValueError("Invalid Trivy result or scan error")
        for field in ("Target", "Class", "Type"):
            nonempty_string(result.get(field), f"Results.{field}")
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("Expected a Vulnerabilities list")
        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                raise ValueError("Invalid Trivy vulnerability")
            for field in ("VulnerabilityID", "PkgName", "InstalledVersion"):
                nonempty_string(finding.get(field), field)
            severity = finding.get("Severity")
            if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("Invalid Trivy severity")
            fixed_version = finding.get("FixedVersion", "")
            if not isinstance(fixed_version, str):
                raise ValueError("Invalid Trivy FixedVersion")
            blocked = severity == "CRITICAL" or (
                severity == "HIGH" and bool(fixed_version.strip())
            )
            findings.append((finding, blocked))

    for finding, blocked in findings:
        decision = "BLOCK" if blocked else "NONBLOCKING"
        print(f"{decision}: {finding['Severity']} {finding['VulnerabilityID']} "
              f"{finding['PkgName']}@{finding['InstalledVersion']} "
              f"fix={finding.get('FixedVersion') or 'not available'}")
    blocked_count = sum(blocked for _, blocked in findings)
    print(f"Trivy: {len(findings)} finding(s), {blocked_count} blocking. "
          "Policy: every CRITICAL and fixable HIGH blocks.")
    return int(blocked_count > 0)


def zap_plugin_id(alert):
    plugin = alert.get("pluginid", alert.get("alertRef"))
    if isinstance(plugin, bool) or not re.fullmatch(r"\d+(?:-\d+)?", str(plugin)):
        raise ValueError("Missing or invalid ZAP plugin ID")
    plugin = str(plugin).split("-", 1)[0]
    if "alertRef" in alert:
        reference = str(alert["alertRef"])
        if not re.fullmatch(r"\d+(?:-\d+)?", reference) or reference.split("-", 1)[0] != plugin:
            raise ValueError("ZAP pluginid and alertRef disagree")
    return plugin


def known_zap_scope(alert, plugin):
    if plugin == "90004" and "alertRef" in alert:
        if str(alert["alertRef"]) not in {"90004-1", "90004-2", "90004-3"}:
            return False
    instances = alert.get("instances")
    if not isinstance(instances, list) or not instances:
        return False
    for instance in instances:
        if not isinstance(instance, dict) or not isinstance(instance.get("uri"), str):
            return False
        try:
            uri = urlsplit(instance["uri"])
        except ValueError:
            return False
        if (uri.scheme not in {"http", "https"} or not uri.netloc
                or (uri.path or "/") not in ZAP_LAB_PATHS[plugin]):
            return False
    return True


def check_zap(report, exit_code):
    if not isinstance(report, dict):
        raise ValueError("Expected a ZAP report object")
    nonempty_string(report.get("@generated"), "ZAP @generated")
    sites = report.get("site")
    if not isinstance(sites, list) or not sites:
        raise ValueError("Expected nonempty ZAP site results")
    findings = []
    for site in sites:
        if not isinstance(site, dict):
            raise ValueError("Invalid ZAP site result")
        nonempty_string(site.get("@name"), "ZAP site name")
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            raise ValueError("Expected a ZAP alerts list")
        for alert in alerts:
            if not isinstance(alert, dict):
                raise ValueError("Invalid ZAP alert")
            plugin = zap_plugin_id(alert)
            risk = alert.get("riskcode")
            if isinstance(risk, bool) or str(risk) not in {"0", "1", "2", "3"}:
                raise ValueError("Missing or invalid ZAP riskcode")
            risk = int(risk)
            name = nonempty_string(alert.get("name", alert.get("alert")), "ZAP alert name")
            accepted = (risk in (1, 2) and plugin in ZAP_LAB_RISKS
                        and known_zap_scope(alert, plugin))
            blocked = risk > 0 and not accepted
            findings.append((plugin, risk, name, accepted, blocked))

    for plugin, risk, name, accepted, blocked in findings:
        decision = "BLOCK" if blocked else ("ACCEPTED LAB RISK" if accepted else "INFO")
        note = f"; {ZAP_LAB_RISKS[plugin]} (not fixed)" if accepted else ""
        print(f"{decision}: {RISK_NAMES[risk]} {plugin} {name}{note}")
    blocked_count = sum(blocked for _, _, _, _, blocked in findings)
    print(f"ZAP: {len(findings)} alert(s), {blocked_count} blocking; scanner exit {exit_code}.")
    if exit_code not in (0, 1, 2):
        print("ZAP scanner did not finish successfully.", file=sys.stderr)
        return 2
    # Baseline exit 1 always means FAIL; exit 2 means WARN, subject to the policy above.
    return int(exit_code == 1 or blocked_count > 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", choices=("trivy", "zap"))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, help="Required: original ZAP Baseline exit code")
    args = parser.parse_args(argv)
    if args.scanner == "zap" and args.exit_code is None:
        parser.error("ZAP requires --exit-code from the scanner invocation")
    if args.scanner == "trivy" and args.exit_code is not None:
        parser.error("--exit-code is supported only for ZAP")
    try:
        report = json.loads(args.report.read_text())
        return check_trivy(report) if args.scanner == "trivy" else check_zap(report, args.exit_code)
    except (OSError, ValueError, TypeError) as error:
        print(f"Scan report rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
