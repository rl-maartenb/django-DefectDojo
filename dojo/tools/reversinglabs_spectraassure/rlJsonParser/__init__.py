from typing import (
    Any,
    List,
    Dict,
)

import json
import logging

from .rlInfo import RlInfo
from .rlMetaData import RlMetaData

logger = logging.getLogger(__name__)


class RlJsonParser:
    def __init__(
        self,
        *,
        file_handle: Any,
        **kwargs: str,
    ) -> None:
        # --------------------------
        self.data: Dict[str, Any] = {}

        # --------------------------
        self.scan_info: Dict[str, Any] = {}
        self.file_info: Dict[str, Any] = {}
        self.components: Dict[str, Any] = {}
        self.dependencies: Dict[str, Any] = {}
        self.violations: Dict[str, Any] = {}
        self.vulnerabilities: Dict[str, Any] = {}
        self.viols_compact_info: Dict[str, Any] = {}
        self.rest: Dict[str, Any] = {}

        # --------------------------
        self.options: Dict[str, Any] = {}
        for k, v in kwargs.items():
            self.options[k] = v

        # --------------------------
        self._load_and_populate(file_handle=file_handle)

        self.components = getattr(self.metadata, "components")
        self.dependencies = getattr(self.metadata, "dependencies")
        self.violations = getattr(self.metadata, "violations")
        self.vulnerabilities = getattr(self.metadata, "vulnerabilities")
        self.viols_compact_info = self._compact_all_viol_info()

    # -------------------------------------------------------
    def _extract_scan_info(
        self,
        report: Dict[str, Any],
    ) -> None:
        # get scan tool, scan tool version and, scan date

        self.scan_info["tool_name"] = "ReversingLabs.SpectraAssure"
        self.scan_info["tool_version"] = report.get("version")
        self.scan_info["scan_date"] = report.get("timestamp")
        self.scan_info["scan_level"] = (
            report.get(
                "report",
                {},
            )
            .get(
                "info",
                {},
            )
            .get(
                "inhibitors",
                {},
            )
            .get(
                "scan_level",
            )
        )

    def _extractInfo(
        self,
        report: Dict[str, Any],
    ) -> None:
        k = "info"  # extract the Info subtree
        subtree = report.get(k, {})
        self.info = RlInfo(raw_subtree=subtree)

        f = getattr(self.info, "file")
        if f:
            # file name, size sha256 verdict:
            self.file_info["status"] = f.get("quality", {}).get("status")
            for j in ["name", "size", "version"]:
                self.file_info[j] = f.get(j)
            hh = f.get("hashes", [])
            for h in hh:
                if h[0] == "sha256":
                    self.file_info["sha256"] = h[1]

        del report[k]

    def _extractMeta(
        self,
        report: Dict[str, Any],
    ) -> None:
        k = "metadata"  # extract the Info subtree
        subtree = report.get(k, {})
        self.metadata = RlMetaData(raw_subtree=subtree)
        del report[k]

    def verify_supported_schema(self) -> None:
        schema = self.data.get("schema")
        supported_schema = [3]
        if schema not in supported_schema:
            msg = f"unsupported schema version: {schema}, we expect {supported_schema}"
            logger.exception(msg)
            raise RuntimeError(msg)

    def _load_and_populate(
        self,
        file_handle: Any,
    ) -> None:
        self.data = json.load(file_handle)
        self.verify_supported_schema()
        self._extract_scan_info(report=self.data)

        report = self.data.get("report", {})
        self._extractInfo(report=report)
        self._extractMeta(report=report)

        if len(report) == 0:
            del self.data["report"]

        self.rest = self.data

    # -------------------------------------------------------
    def _get_ref_components(
        self,
        data: Dict[str, Dict[str, List[str]]],
    ) -> List[str]:
        return data.get("references", {}).get("component", [])

    def _my_compact_viol_info(self, v: Dict[str, Any]) -> Dict[str, Any]:
        description = v.get("description")
        category = v.get("category")
        severity = v.get("severity")
        status = v.get("status")

        vv = {
            "description": description,
            "category": category,
            "severity": severity,
            "status": status,
        }

        return vv

    def _compact_all_viol_info(self) -> Dict[str, Any]:
        rr: Dict[str, Any] = {}

        for k, v in self.violations.items():
            rule_id = v.get("rule_id")
            r = self._my_compact_viol_info(v=v)
            rr[rule_id] = r
        return rr

    # -------------------------------------------------------
    def _get_one_vul(
        self,
        cve: str,
    ) -> Dict[str, Any]:
        cve_info = self.vulnerabilities.get(cve, {})

        rr: Dict[str, Any] = {}

        cvss = cve_info.get("cvss", {})
        baseScore = cvss.get("baseScore", "")

        violations = cve_info.get("violations")
        if violations is None:
            violations = []

        zz = {}
        for rule_id in violations:
            vv = self.viols_compact_info.get(rule_id)
            if vv and vv.get("status", "") != "fail":
                continue
            zz[rule_id] = vv

        if self.options.get("REMOVE_CVE_WITHOUT_VIOLATIONS") is True and len(zz) == 0:
            return {}

        rr = {
            "cvss": {
                "baseScore": baseScore,
                "violations": zz,  # no need to add: not 'fail', no need to add my self
            }
        }

        return rr

    def _get_all_vulnerabilities(
        self,
        vul_active_list: List[str],
    ) -> Dict[str, Any]:

        rr: Dict[str, Any] = {}
        for cve in vul_active_list:
            r = self._get_one_vul(
                cve,
            )
            if self.options.get("REMOVE_CVE_WITHOUT_VIOLATIONS") is True and len(r) == 0:
                continue

            rr[cve] = r
        return rr

    # -------------------------------------------------------
    def _one_dependency(
        self,
        dependency_uuid: str,
    ) -> Dict[str, Any]:
        # look if vulnerabilities->active is not empty
        dep = self.dependencies.get(dependency_uuid, {})
        if dep is None or len(dep) == 0:
            return {}

        product = dep.get("product")
        version = dep.get("version")
        publisher = dep.get("publisher")

        vul = dep.get("vulnerabilities", {})
        if vul is None or len(vul) == 0:
            return {}

        vul_active_list = vul.get("active", [])
        if len(vul_active_list) == 0:
            return {}

        vul_dict = self._get_all_vulnerabilities(
            vul_active_list=vul_active_list,
        )

        return {
            "product": product,
            "version": version,
            "publisher": publisher,
            "vulnerabilities": {
                "active": vul_dict,
            },
        }

    def _all_dependencies(
        self,
        dependencies_uuid_list: List[str],
    ) -> Dict[str, Any]:
        rr: Dict[str, Any] = {}

        for dependency_uuid in dependencies_uuid_list:
            r = self._one_dependency(
                dependency_uuid=dependency_uuid,
            )
            if len(r) > 0:
                rr[dependency_uuid] = r

        return rr

    def _get_failed_components(self) -> List[str]:
        key_list: List[str] = []
        for k, component in self.components.items():
            status = component.get("quality", {}).get("status")
            if status not in ["fail"]:
                continue
            key_list.append(k)
        return key_list

    def _find_my_violations(
        self,
        component_uuid: str,
    ) -> Dict[str, Any]:
        vvv: Dict[str, Any] = {}

        for k, v in self.violations.items():
            z = self._one_violation(k=k, v=v, with_subtree=False)
            if len(z):
                if component_uuid in z.get("components", []):
                    del z["components"]
                    vvv[k] = z

        return vvv

    # -------------------------------------------------------
    def _one_component(
        self,
        component_uuid: str,
    ) -> Dict[str, Any]:
        if component_uuid not in self.components:
            logger.error("missing uuid '%s' in metadata.components", component_uuid)
            return {}

        # --------------------------
        component = self.components.get(component_uuid, {})
        status = component.get("quality", {}).get("status")
        if status not in ["fail"]:
            return {}

        # --------------------------
        path = component.get("path")
        size = component.get("size")
        identity = component.get("identity", {})
        product = identity.get("product")
        version = identity.get("version")

        # --------------------------
        hashes = component.get("hashes", [])
        sha256: str = ""
        for item in hashes:
            if item[0] == "sha256":
                sha256 = item[1]

        z = component.get("identity", {}).get("dependencies", [])
        dependencies = self._all_dependencies(
            dependencies_uuid_list=(z),
        )

        # --------------------------
        vvv = {
            "path": path,
            "size": size,
            "sha256": sha256,
            "product": product,
            "version": version,
            "status": status,
            "identity": {
                "dependencies": dependencies,
            },
        }

        # note: we can have violations that are never revferenced via vulnerabilities,
        # so also add the list of violations directly to the component
        # in case it is never referenced by vulnerabilities
        # collect all violations (status fail) that mention this component

        viols = self._find_my_violations(component_uuid=component_uuid)
        vvv["violations"] = viols

        return vvv

    def _all_components(
        self,
        component_uuid_list: List[str],
    ) -> Dict[str, Any]:
        rr: Dict[str, Any] = {}
        for component_uuid in component_uuid_list:
            r = self._one_component(
                component_uuid=component_uuid,
            )
            rr[component_uuid] = r
        return rr

    # -------------------------------------------------------
    def _one_violation(
        self,
        k: str,
        v: Any,
        with_subtree: bool = True,
    ) -> Dict[str, Any]:
        status = v.get("status")

        # filter
        if status not in ["fail"]:
            return {}

        category = v.get("category")
        severity = v.get("severity")
        rule_id = v.get("rule_id")
        description = v.get("description")

        vv = {
            "category": category,
            "severity": severity,
            "status": status,
            "rule": rule_id,
            "description": description,
        }

        components_list: List[str] = self._get_ref_components(v)
        if with_subtree is True:
            r: Dict[str, Any] = self._all_components(
                component_uuid_list=components_list,
            )
            vv["components"] = r
        else:
            vv["components"] = components_list

        return vv

    # PUBLIC
    def from_components(
        self,
    ) -> Dict[str, Any]:
        key_list: List[str] = self._get_failed_components()
        r = self._all_components(
            component_uuid_list=key_list,
        )

        return {
            "scan_info": self.scan_info,
            "file_info": self.file_info,
            "components": r,
        }

    def from_violations(
        self,
    ) -> Dict[str, Any]:
        vvv: Dict[str, Any] = {}

        for k, v in self.violations.items():
            z = self._one_violation(k=k, v=v)
            if len(z):
                vvv[k] = z

        return {
            "scan_info": self.scan_info,
            "file_info": self.file_info,
            "violations": vvv,
        }
