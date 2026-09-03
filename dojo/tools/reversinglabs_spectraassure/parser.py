# noqa: RUF100
import hashlib
import json
import logging
from typing import Any

from dojo.models import Finding
from dojo.tools.reversinglabs_spectraassure.rl_json_info import RlJsonInfo
from dojo.tools.reversinglabs_spectraassure.rl_json_info.cve_info_node import CveInfoNode

logger = logging.getLogger(__name__)

SCAN_TYPE = "ReversingLabs Spectra Assure"

"""
The actual parsing is done by `RlJsonInfo` and it stores data as a collection of `CveInfoNode`
A `CveInfoNode` matches a dd.Finding more closely and makes the collection of Findings easy.
"""


class ReversinglabsSpectraassureParser:

    # --------------------------------------------
    # This class MUST have an empty constructor or no constructor

    def _make_hash(
        self,
        data: str,
    ) -> str:
        logger.debug("_make_hash")

        d = data.encode()
        return hashlib.sha256(d).hexdigest()

    def _one_finding(
        self,
        *,
        node: CveInfoNode,
        test: Any,
    ) -> Finding:
        logger.debug("_one_finding: %s", node)

        key = self._make_hash(node.title + " " + node.component_file_path)

        cvssv3_score = None
        if node.cvss_version == 3:
            cvssv3_score = node.score or None

        cvssv4_score = None
        if node.cvss_version == 4:
            cvssv4_score = node.score or None

        finding = Finding(
            date=node.scan_date,
            title=node.title,
            description=node.title + " " + node.description + "\n",
            cve=node.cve,
            cvssv3_score=cvssv3_score,
            cvssv4_score=cvssv4_score,
            severity=node.score_severity,
            vuln_id_from_tool=node.vuln_id_from_tool,
            file_path=node.component_file_path,
            component_name=node.component_name,
            component_version=node.component_version,
            nb_occurences=1,
            hash_code=key,
            references=None,  # future: urls
            active=True,  # this is the DefectDojo active field, nothing to do with node.active field
            test=test,
            static_finding=True,
            dynamic_finding=False,
            known_exploited=node.known_exploited,
        )

        finding.unsaved_vulnerability_ids = [node.cve] if node.cve else []
        finding.unsaved_tags = node.tags
        finding.impact = node.impact

        return finding

    # --------------------------------------------
    # PUBLIC
    def get_scan_types(self) -> list[str]:
        logger.debug("get_scan_types")
        return [SCAN_TYPE]

    def get_label_for_scan_types(self, scan_type: str) -> str:
        logger.debug("get_label_for_scan_types")
        return scan_type

    def get_description_for_scan_types(self, scan_type: str) -> str:
        logger.debug("get_description_for_scan_types")

        if scan_type == SCAN_TYPE:
            return "Import the SpectraAssure report.rl.json file."
        return f"Unknown Scan Type; {scan_type}"

    def get_findings(
        self,
        file: Any,
        test: Any,
    ) -> list[Finding]:
        logger.debug("get_findings")

        self._findings: list[Finding] = []
        self._duplicates: dict[str, Finding] = {}

        try:
            info = RlJsonInfo(file_handle=file)
            info.build_findings()

            for cve_info_node_instance in info.get_results_list():
                finding = self._one_finding(
                    node=cve_info_node_instance,
                    test=test,
                )
                if finding is None:
                    continue

                key = finding.hash_code
                if key not in self._duplicates:
                    self._findings.append(finding)
                    self._duplicates[key] = finding
                    continue

                dup = self._duplicates[key]
                if dup:
                    dup.description += finding.description
                    dup.nb_occurences += 1

        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            msg = f"Not a valid Spectra Assure rl.json report: {e}"
            raise ValueError(msg) from e

        return self._findings


# ---- for dedup add the following to: ./django-DefectDojo/dojo/settings/settings.dist.py
#
# HASHCODE_FIELDS_PER_SCANNER = {
#  "ReversingLabs Spectra Assure": ["title", "component_name", "component_version", "vulnerability_ids", "file_path"],
#  ....
# }
# DEDUPLICATION_ALGORITHM_PER_PARSER = {
#  "ReversingLabs Spectra Assure": DEDUPE_ALGO_HASH_CODE,
#  ....
# }
