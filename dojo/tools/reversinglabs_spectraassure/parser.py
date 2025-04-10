from typing import (
    List,
    Any,
    Dict,
)
import datetime
import json
import copy
import logging

from dojo.models import Finding
from dojo.tools.reversinglabs_spectraassure.rlJsonParser import RlJsonParser

logger = logging.getLogger(__name__)

"""
    we have a file, components and dependencies in the rl-json
    vulnerabilities are basically cve info
    violations are reversinglabs rules that fail depending on the scan level
    a component may have no dependencies but still have violations

    file -> component -> dependencies -> vulnerabilities -> violations
    file -> components -> violations

    Finding template:
        date
            # "The date the flaw was discovered."
                datetime
        title
            # "A short description of the flaw."
                text, max 511
        description
            # "Longer more descriptive information about the flaw."
                text
        severity
            # "The severity level of this flaw (Critical, High, Medium, Low, Info).
                mandatory; text max 200
        severity_justification
            # "Text describing why a certain severity was associated with this flaw.":
                optional; text
        component_name
            # "Name of the affected component (library name, part of a system, ...).":
                optional; text 500
        component_version
            # "Version of the affected component.":
                optional; text 100
        unique_id_from_tool
            # "Vulnerability technical id from the source tool. Allows to track unique vulnerabilities."
                optional; text 500
        vuln_id_from_tool
            # "Non-unique technical id from the source tool associated with the vulnerability type.":
                optional; text 500
        cve
            # "Vulnerability Id":
                optional; str 50, may be a non CVE based id, e.g. RL
        cvssv3_score
            # "CVSSv3 score":
                float between 0 and 10
        references
            # "The external documentation available for this flaw.":
                optional; text (urls to external sources)
        file_path
            # "Identified file(s) containing the flaw.":
                optional; text 4000

        test=test
        static_finding=True
        dynamic_finding=False

"""
WHAT = "ReversingLabsSpectraAssure"


class ReversinglabsSpectraassureParser(object):
    """
    Parser for Spectra Assure rl-json files

    This class MUST implement 3 methods:

    - def get_scan_types(self)
        This function return a list of all the scan_type supported by your parser.
        These identifiers are used internally.
        Your parser can support more than one scan_type.
        e.g. some parsers use different identifier to modify the behavior of the parser (aggregate, filter, etc…)

    - def get_label_for_scan_types(self, scan_type)
        This function return a string used to provide some text in the UI (short label)

    - def get_description_for_scan_types(self, scan_type)
        This function return a string used to provide some text in the UI (long description)

    - def get_findings(self, file, test)
        This function return a list of findings

    If your parser has more than 1 scan_type (for detailed mode) you MUST implement:
    - def set_mode(self, mode) method
    """

    # --------------------------------------------
    # This class MUST have an empty constructor or no constructor

    def _one_finding(
        self,
        *,
        node: Dict[str, Any],
        test: Any,
    ) -> Finding:
        # print(node)

        severity = self.fix_severity(node.get("severity", "Info"))
        finding = Finding(
            date=node["date"],
            title=node.get("title", ""),
            description=node.get("description", ""),
            severity=severity,
            #
            cvssv3_score=node.get("score"),
            cve=node.get("cve"),
            vuln_id_from_tool=node.get("vuln_id_from_tool"),
            unique_id_from_tool=node.get("unique_id_from_tool"),
            file_path=node.get("file_path"),
            #
            references=None,
            active=True,
            test=test,
            static_finding=True,
            dynamic_finding=False,
        )

        return finding

    def fix_severity(self, severity: str) -> str:
        if severity.lower() in ["info", "low", "medium", "high", "critical"]:
            return severity.lower().capitalize()
        return "Info"

    def _make_description_component_violation(
        self,
        component: Dict[str, Any],
        viol_id: str,
        violation: Dict[str, Any],
    ) -> str:
        viol_description = violation.get("description", "missing-violation-description")

        comp = copy.deepcopy(component)
        del comp["identity"]  # we dont need this here
        del comp["violations"]  # we dont need this here
        violation["violation"] = viol_id

        info = {
            "file_info": self.file_info,
            "component": comp,
            "violation": violation,
        }

        s = json.dumps(info, indent=4)
        description = f"{viol_description}\n{s}"
        return description

    def _make_description_comp_dep_vul_viol(
        self,
        component: Dict[str, Any],
        dependency: Dict[str, Any],
        vul_id: str,
        vulnerability: Dict[str, Any],
        viol_id: str,
        violation: Dict[str, Any],
    ) -> str:
        viol_description = violation.get("description", "missing-violation-description")

        comp = copy.deepcopy(component)
        dep = copy.deepcopy(dependency)
        vul = copy.deepcopy(vulnerability)
        viol = copy.deepcopy(violation)

        # minimize the info we use in description
        del comp["identity"]
        del comp["violations"]
        del dep["vulnerabilities"]
        del vul["cvss"]["violations"]

        vul["vulnerability"] = vul_id
        viol["violation"] = viol_id

        info = {
            "file_info": self.file_info,
            "component": comp,
            "dependency": dep,
            "vulnerability": vul,
            "violation": viol,
        }

        s = json.dumps(info, indent=4)
        description = f"{viol_description}\n{s}"

        return description

    def _make_component_name(
        self,
        component: Dict[str, Any],
    ) -> str:
        product = component.get("product", "missing-product")
        path = component.get("path", "missing-path")
        sha256 = component.get("sha256", "missing-sha256")
        name = f"{product}; {path}; {sha256}"
        return name

    def _do_component_violations(
        self,
        component_uuid: str,
        component: Dict[str, Any],
        viol_id: str,
        violation: Dict[str, Any],
    ) -> Dict[str, Any]:
        viol_description = violation.get("description", "missing-violation-description")

        node = {
            "date": self.scan_date,
            "component_name": self._make_component_name(component=component),
            "component_version": component.get("version", "missing-version"),
        }

        node["title"] = viol_description
        node["unique_id_from_tool"] = " ".join(
            [
                f"component:{component_uuid}",
                f"violation:{viol_id}",
            ],
        )
        node["vuln_id_from_tool"] = violation.get("rule", "missing-violation-rule-id")
        node["severity"] = self.fix_severity(violation.get("severity"))
        node["file_path"] = " ".join(
            [
                "file:" + self.file_info.get("name"),
                "component:" + component.get("path", "missing-path"),
            ],
        )
        node["description"] = self._make_description_component_violation(
            component=component,
            viol_id=viol_id,
            violation=violation,
        )
        return node

    def _do_comp_dep_vul_viol(
        self,
        #
        component_uuid: str,
        component: Dict[str, Any],
        #
        dep_uuid: str,
        dependency: Dict[str, Any],
        #
        vul_id: str,
        vulnerability: Dict[str, Any],
        #
        viol_id: str,
        violation: Dict[str, Any],
    ) -> Dict[str, Any]:
        viol_description = violation.get("description", "missing-violation-description")

        dep_name = dependency.get("product", "missing-product")
        dep_version = dependency.get("version", "missing-version")

        c = "component: "
        d = "dependency: "

        node = {
            "date": self.scan_date,
            # TODO: is component now component or dependency ?
            "component_name": c
            + self._make_component_name(component=component)
            + d
            + dep_name,
            "component_version": c
            + component.get("version", "missing-version")
            + d
            + dep_version,
        }
        node["title"] = viol_description
        node["cve"] = viol_id
        node["file_path"] = " ".join(
            [
                "file:" + self.file_info.get("name"),
                "component:" + component.get("path", "missing-path"),
                "dependency:" + dependency.get("product", "missing-product"),
            ],
        )

        node["vuln_id_from_tool"] = f"{vul_id} {viol_id}"
        node["unique_id_from_tool"] = " ".join(
            [
                f"component:{component_uuid}",
                f"dependency:{dep_uuid}",
                f"vulnerability:{vul_id}",
                f"violation:{viol_id}",
            ],
        )

        score = vulnerability.get("cvss", {}).get("baseScore")
        if score:
            score = float(score)

        node["severity"] = self.fix_severity(violation.get("severity"))

        node["score"] = score
        node["cve"] = vul_id
        node["description"] = self._make_description_comp_dep_vul_viol(
            component=component,
            dependency=dependency,
            vul_id=vul_id,
            vulnerability=vulnerability,
            viol_id=viol_id,
            violation=violation,
        )
        return node

    def _one_component(
        self,
        #
        component_uuid: str,
        component: Dict[str, Any],
    ) -> None:
        # walk the tree compo -> dep -> vul -> viol
        dependencies = component.get("identity", {}).get("dependencies", {})
        for dep_uuid, dependency in dependencies.items():
            for vul_id, vulnerability in (
                dependency.get("vulnerabilities", {}).get("active", {}).items()
            ):
                for viol_id, violation in (
                    vulnerability.get("cvss", {}).get("violations", {}).items()
                ):
                    node = self._do_comp_dep_vul_viol(
                        component_uuid=component_uuid,
                        component=component,
                        dep_uuid=dep_uuid,
                        dependency=dependency,
                        vul_id=vul_id,
                        vulnerability=vulnerability,
                        viol_id=viol_id,
                        violation=violation,
                    )
                    self.nodes.append(node)

        if 1:
            return

        # do the violations on the component level: compo -> viol
        compo_violations = component.get("violations", {})
        for viol_id, violation in compo_violations.items():
            node = self._do_component_violations(
                component_uuid=component_uuid,
                component=component,
                viol_id=viol_id,
                violation=violation,
            )
            self.nodes.append(node)

    # --------------------------------------------
    # PUBLIC
    def get_scan_types(self) -> List[str]:
        return [WHAT]

    def get_label_for_scan_types(self, scan_type: str) -> str:
        return scan_type

    def get_description_for_scan_types(self, scan_type: str) -> str:
        if scan_type == WHAT:
            return "SpectraAssure report.rl-json file can be imported in JSON format."
        return f"Unknown Scan Type; {scan_type}"

    def get_findings(
        self,
        file: Any,
        test: Any,
    ) -> List[Finding]:
        # ------------------------------------
        rjp = RlJsonParser(file_handle=file)
        data = rjp.from_components()

        self.file_info = data.get("file_info", {})
        self.scan_info = data.get("scan_info", {})
        self.components = data.get("components", {})
        self.scan_date = datetime.datetime.fromisoformat(
            self.scan_info["scan_date"]
        ).date()

        # ------------------------------------
        self.nodes: List[Any] = []
        for component_uuid, component in self.components.items():
            self._one_component(
                component_uuid=component_uuid,
                component=component,
            )

        self.findings: List[Finding] = []
        for node in self.nodes:
            finding = self._one_finding(
                node=node,
                test=test,
            )
            self.findings.append(finding)

        # ------------------------------------
        return self.findings
