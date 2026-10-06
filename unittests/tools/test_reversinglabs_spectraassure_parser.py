# ruff: noqa: RUF100
# ruff: noqa: I001
from dojo.models import Finding, Test
from dojo.tools.reversinglabs_spectraassure.parser import ReversinglabsSpectraassureParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3

"""
run with:

./run-unittest.sh --test-case
    unittests.tools.test_reversinglabs_spectraassure_parser.TestReversingLabsSpectraAssureParser

FD13-FullUSB.zip:       no CVE; two 'threats' and one 'secrets' policy violation
putty_win_x64-0.80.exe: one CVE, no policy violation findings
HxDSetup_2.5.0.exe:     two executables, each in 18 language builds: same name and path, different sha256,
                        so different binaries and separate findings
azure-cli-2.84.0-x64:   many CVE plus one 'secrets' violation that carries secret detail;
                        the only fixture whose CVE findings carry a purl, so it covers Locations
synthetic-shared-component: hand-built, NOT a scanner output. One component carrying a CVE and
                        two violations per category, in a report whose info.file has no sha256,
                        plus the same binary (same sha256) at a second path.

"""

_WHERE = "reversinglabs_spectraassure"


# mypy gives:  error: Class cannot subclass "DojoTestCase" (has type "Any")  [misc]
class TestReversingLabsSpectraAssureParser(DojoTestCase):  # type: ignore[misc]

    def common_checks(self, finding: Finding) -> None:
        self.assertTrue(finding.title)
        self.assertLessEqual(len(finding.title), 250)
        self.assertNotIn("  ", finding.title)  # no collapsed-empty parts in the joined title

        self.assertIn(finding.severity, Finding.SEVERITIES)
        if finding.cwe:
            self.assertIsInstance(finding.cwe, int)

        self.assertEqual(True, finding.static_finding)  # by specification
        self.assertEqual(False, finding.dynamic_finding)  # by specification

        self.assertIsNotNone(finding.date)
        self.assertTrue(finding.vuln_id_from_tool)

        # the description opens with the title as a markdown heading: '#' needs the space
        self.assertTrue(finding.description.startswith(f"# {finding.title}\n"))
        # merging a repeat must not append the whole description again
        self.assertEqual(1, finding.description.count(f"# {finding.title}"))

        # the dedupe identity (HASHCODE_FIELDS_PER_SCANNER): what was found, in which component file;
        # the parser itself never sets hash_code, DefectDojo computes it from the settings
        self.assertTrue(finding.unique_id_from_tool.startswith(f"{finding.vuln_id_from_tool}/"))
        self.assertIsNone(getattr(finding, "hash_code", None))

    def split_cve_and_violation(
        self,
        findings: list[Finding],
    ) -> tuple[list[Finding], list[Finding]]:
        # CVE findings carry a vulnerability id; policy violation findings never do
        cves = [f for f in findings if f.unsaved_vulnerability_ids]
        violations = [f for f in findings if not f.unsaved_vulnerability_ids]

        for f in cves:
            self.assertEqual(1, len(f.unsaved_vulnerability_ids))
            self.assertTrue(
                f.unsaved_vulnerability_ids[0].startswith(("CVE-", "GHSA-")),
            )

        for f in violations:
            # <category>-<rule_id>, e.g. 'secrets-SQ34201'
            self.assertIn("-", f.vuln_id_from_tool)
            self.assertIsNone(f.cvssv3_score)
            self.assertIsNone(f.cvssv4_score)

        return cves, violations

    def rule_ids(self, findings: list[Finding], category: str) -> set[str]:
        return {f.vuln_id_from_tool for f in findings if f.vuln_id_from_tool.startswith(f"{category}-")}

    def severity_counts(self, findings: list[Finding]) -> dict[str, int]:
        # pins the CVSS score -> severity mapping, which nothing else asserts
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def test_parse_file_with_no_vuln(self) -> None:
        # no CVE: two 'threats' violations (malware) and one 'secrets' violation
        with (get_unit_tests_scans_path(_WHERE) / "FD13-FullUSB.zip-report.rl.json").open(encoding="utf-8") as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(3, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(0, len(cves))
            self.assertEqual(3, len(violations))

            self.assertEqual({"threats-SQ30110", "threats-SQ30108"}, self.rule_ids(violations, "threats"))
            self.assertEqual({"secrets-SQ34201"}, self.rule_ids(violations, "secrets"))
            self.assertEqual({"High": 3}, self.severity_counts(findings))

    def test_parse_file_with_one_vuln(self) -> None:
        with (get_unit_tests_scans_path(_WHERE) / "putty_win_x64-0.80.exe-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(1, len(cves))
            self.assertEqual(0, len(violations))
            self.assertEqual("CVE-2024-31497", cves[0].vuln_id_from_tool)
            self.assertEqual({"Medium": 1}, self.severity_counts(findings))

    def test_parse_file_with_many_vulns(self) -> None:
        # --------------------------------------
        with (get_unit_tests_scans_path(_WHERE) / "HxDSetup_2.5.0.exe-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            # 6 CVE x 2 executables x 18 language builds
            self.assertEqual(216, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(216, len(cves))
            self.assertEqual(0, len(violations))

            self.assertEqual({"Critical": 108, "High": 108}, self.severity_counts(findings))

            # same name and same path, but a different sha256 is a different binary: every build is its own
            # finding, with its own dedupe identity, and a title that tells it apart from its 17 siblings
            self.assertEqual(216, len({f.unique_id_from_tool for f in findings}))
            self.assertEqual(216, len({f.title for f in findings}))

            hxd64 = [
                f for f in findings if f.vuln_id_from_tool == "CVE-2016-9840" and f.file_path.endswith("/HxD64.exe")
            ]
            self.assertEqual(18, len(hxd64))
            self.assertEqual({"zlib"}, {f.component_name for f in hxd64})
            self.assertEqual({1}, {f.nb_occurences for f in hxd64})

    def test_parse_file_with_secrets(self) -> None:
        # many CVE plus one 'secrets' violation whose description carries the secret detail
        with (get_unit_tests_scans_path(_WHERE) / "azure-cli-2.84.0-x64-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(105, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(104, len(cves))
            self.assertEqual(1, len(violations))

            self.assertEqual({"Critical": 2, "High": 50, "Low": 19, "Medium": 34}, self.severity_counts(findings))

            secret = violations[0]
            self.assertEqual("secrets-SQ34304", secret.vuln_id_from_tool)
            self.assertEqual("High", secret.severity)

            # the secret detail is rendered as a fenced block by RlJsonInfo
            self.assertIn("```", secret.description)
            self.assertIn("service: ", secret.description)
            self.assertIn("liveness: ", secret.description)
            self.assertIn("exposed: ", secret.description)

    def test_parse_file_with_shared_component(self) -> None:
        # Synthetic fixture, hand-built. Covers what no real sample does:
        #  - several violations on the SAME component must stay separate findings: results are
        #    keyed on <category>-<rule_id>; keying on None collapsed them into one, silently.
        #    Two per category, so either collector regressing on its own is caught.
        #  - report.info.file has no sha256: that used to abort the whole import, on both the
        #    CVE path and the violation path, so the fixture carries one of each.
        #  - CVSS version "3.1" rather than the "3" every real sample has.
        with (get_unit_tests_scans_path(_WHERE) / "synthetic-shared-component-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(5, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(1, len(cves))
            self.assertEqual(4, len(violations))

            self.assertEqual({"threats-SQ30110", "threats-SQ30108"}, self.rule_ids(violations, "threats"))
            self.assertEqual({"secrets-SQ34304", "secrets-SQ34101"}, self.rule_ids(violations, "secrets"))
            self.assertEqual({"Critical": 2, "High": 1, "Medium": 1, "Low": 1}, self.severity_counts(findings))

            # everything sits on the one component
            self.assertEqual({"payload.dll"}, {f.component_name for f in findings})
            self.assertEqual({"synthetic-installer.exe/payload.dll"}, {f.file_path for f in findings})

            # the same binary (same sha256) also sits at a second path: one finding, counted twice,
            # with the second location noted rather than the whole description repeated
            self.assertEqual({1}, {f.nb_occurences for f in violations})

            threat = next(f for f in violations if f.vuln_id_from_tool == "threats-SQ30110")
            self.assertIn("Threat name: Win32.Trojan.Synthetic", threat.description)

            cve = cves[0]
            self.assertEqual("CVE-2099-0001", cve.vuln_id_from_tool)
            self.assertEqual(9.8, cve.cvssv3_score)  # version "3.1" routes to the v3 field
            self.assertIsNone(cve.cvssv4_score)
            self.assertEqual(["Fix Available"], cve.unsaved_tags)
            self.assertEqual(2, cve.nb_occurences)
            self.assertIn("- also at: synthetic-installer.exe/backup/payload.dll", cve.description)

    # mypy gives:  error: Untyped decorator makes function "test_dependency_locations" untyped  [untyped-decorator]
    @skip_unless_v3  # type: ignore[untyped-decorator]
    def test_dependency_locations(self) -> None:
        # with V3_FEATURE_LOCATIONS on, a CVE finding with a purl gets exactly one dependency
        # location for that package; findings without a purl, and violations, get none
        with (get_unit_tests_scans_path(_WHERE) / "azure-cli-2.84.0-x64-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.validate_locations(findings)

            with_location = [f for f in findings if f.unsaved_locations]
            self.assertEqual(71, len(with_location))

            for finding in findings:
                dependencies = [loc.data for loc in finding.unsaved_locations if loc.type == "dependency"]
                self.assertEqual(len(finding.unsaved_locations), len(dependencies))  # nothing but dependencies

                if not finding.unsaved_vulnerability_ids:
                    self.assertEqual([], dependencies)  # policy violations carry no package
                    continue

                if dependencies:
                    self.assertEqual(1, len(dependencies))
                    purl = dependencies[0]["purl"]
                    self.assertTrue(purl.startswith("pkg:"))
                    self.assertEqual(finding.file_path, dependencies[0]["file_path"])

                    if " on dependency:" in finding.title:
                        # the location names the vulnerable dependency, not the package containing it
                        # (e.g. requests inside requests-oauthlib). purl names are normalized, so lower()
                        expected = f"/{finding.component_name}@{finding.component_version}".lower()
                        self.assertIn(expected, purl.lower())

            requests = [
                loc.data
                for f in findings
                for loc in f.unsaved_locations
                if loc.data["purl"] == "pkg:pypi/requests@2.32.4?artifact_tag=py3-none-any"
            ]
            self.assertTrue(requests)
