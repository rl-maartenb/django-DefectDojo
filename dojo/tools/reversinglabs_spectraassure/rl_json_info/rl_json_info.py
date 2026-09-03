import datetime
import json
import logging
from collections.abc import Iterator
from typing import Any, ClassVar

from packageurl import PackageURL

from .cve_info_node import CveInfoNode

logger = logging.getLogger(__name__)


class RlJsonInfo:

    SCAN_TOOL_NAME: str = "ReversingLabs SpectraAssure"

    info: dict[str, Any]

    # we currently only use components, dependencies and vulnerabilities
    known_metadata_sub_keys: ClassVar[list[str]] = [
        "assessments",
        "components",  # we use this
        "cryptography",
        "dependencies",  # we use this
        "indicators",
        "licenses",
        "ml_models",
        "services",
        "secrets",
        "violations",
        "vulnerabilities",  # we use this
    ]

    assessments: dict[str, Any]
    components: dict[str, Any]
    cryptography: dict[str, Any]
    dependencies: dict[str, Any]
    indicators: dict[str, Any]
    licenses: dict[str, Any]
    ml_models: dict[str, Any]
    services: dict[str, Any]
    secrets: dict[str, Any]
    violations: dict[str, Any]
    vulnerabilities: dict[str, Any]

    _rest: dict[str, Any]  # after extracting and removing known sub key data, what remains goes here

    severity_map: ClassVar[dict[int, str]] = {
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    ignored_exploit_keys: ClassVar[set[str]] = {"UNPROVEN"}

    common_tags_map: ClassVar[dict[str, str]] = {
        "FIXABLE": "Fix Available",
        "EXISTS": "Exploit Exists",
        "MALWARE": "Exploited by Malware",
        "MANDATE": "Patching Mandated",
        # "UNPROVEN": "CVE Discovered",
    }

    # sort order, to align with Spectra Assure Portal
    # 1: Fix Available
    # 2: Exploit exists
    # 3: Exploited my malware
    # 4: Patch mandated

    impact_sort_order: ClassVar[list[str]] = [
        "Fix Available",
        "Exploit Exists",
        "Exploited by Malware",
        "Patching Mandated",  # if present also set known_exploited to True
        # "CVE Discovered",
    ]

    # dict:cve, comp_uuid, dep_uuid | None -> CveInfoNode
    # for cve on components we get the info with path: cve.comp_uuid.None
    # for cve on dependency on component we het the info with path: cve.dep_uuid.comp_uuid
    _results: dict[str | None, dict[str, dict[str | None, CveInfoNode]]]

    def __init__(
        self,
        file_handle: Any,
    ) -> None:
        self.file_name: str = file_handle.name
        logger.debug("file: %s", self.file_name)
        self.info = {}

        self.data: dict[str, Any] = json.load(file_handle)
        self._results = {}
        self._get_info()
        self._get_meta()
        self._get_rest()

    def _get_info(
        self,
    ) -> None:
        logger.debug("_get_info")
        report = self.data.get("report", {})
        key = "info"
        if key in report:
            self.info = report.get(key, {})
            del report[key]

    def _get_meta(
        self,
    ) -> None:
        logger.debug("_get_meta")

        report = self.data.get("report", {})
        metadata = report.get("metadata", {})
        for name in self.known_metadata_sub_keys:
            setattr(self, name, metadata.pop(name, {}))

        if len(metadata) == 0:
            del report["metadata"]

        if len(report) == 0:
            del self.data["report"]

    def _get_rest(
        self,
    ) -> None:
        logger.debug("_get_rest")

        self._rest = self.data
        self.data = {}

    def _find_sha256_in_components(
        self,
        sha256: str,
    ) -> bool:
        logger.debug("_find_sha256_in_components")

        for component in self.components.values():
            comp_sha256 = self._get_sha256(data=component)
            if comp_sha256 == sha256:
                return True

        return False

    def _add_to_results(
        self,
        *,
        cve: str | None,
        comp_uuid: str,
        cve_info_node_instance: CveInfoNode | None,
        dep_uuid: str | None = None,
    ) -> None:
        logger.debug("_add_to_results")

        if cve_info_node_instance is None:
            return

        # prep empty keys
        if cve not in self._results:
            self._results[cve] = {}

        if comp_uuid not in self._results[cve]:
            self._results[cve][comp_uuid] = {}

        # put the data in
        logger.debug("add to results: %s, %s, %s", cve, comp_uuid, dep_uuid)
        if dep_uuid not in self._results[cve][comp_uuid]:
            logger.debug("add cve_info_node_instance: %s", cve_info_node_instance)
            self._results[cve][comp_uuid][dep_uuid] = cve_info_node_instance

    def _get_sha256(
        self,
        data: dict[str, Any],
        what: str = "sha256",
    ) -> str:
        logger.debug("_get_%s", what)

        # all components are derived from unpacked files and so have a hash set: we need the sha256
        h = data.get("hashes", [])
        for item in h:
            if isinstance(h, list) and len(item) >= 2:
                if item[0] == what:
                    return str(item[1])

        msg = f"no '{what}' found for this item {data}"
        raise ValueError(msg) from None

    def _score_to_severity(
        self,
        score: float,
    ) -> str:
        logger.debug("_score_to_severity")

        if score >= 9:
            return self.severity_map[5]

        if score >= 7:
            return self.severity_map[4]

        if score >= 4:
            return self.severity_map[3]

        if score > 0:
            return self.severity_map[2]

        return self.severity_map[1]

    def _use_path_or_name(
        self,
        *,
        data: dict[str, Any],
        purl: str | None = None,
        name_first: bool = False,
        prefer_path: bool = True,
    ) -> str:
        logger.debug("_use_path_or_name")

        # path or name may be empty so look for the non empty one
        # with name_first we first look at the name
        # with prefer path we use path if it is not empty
        # if we have a valid purl
        #   prefer to derive the name from the purl

        path = data.get("path", "")
        name = data.get("name", "")

        if name_first and len(name) > 0:
            return str(name)

        if prefer_path and len(path) > 0:
            return str(path)

        if purl:
            p = PackageURL.from_string(purl)
            return f"{p.namespace}/{p.name}" if p.namespace else p.name

        if name_first is False:
            if path:
                return str(path)
            if name:
                return str(name)
        else:
            if name:
                return str(name)
            if path:
                return str(path)

        return ""

    def _get_tags_from_cve(self, this_cve: dict[str, Any]) -> list[str]:
        logger.debug("_get_tags_from_cve")

        tags: list[str] = []
        exploit = this_cve.get("exploit", [])
        if len(exploit) == 0:
            return tags  # we have no exploit info so no tags

        # turn cve exploit info into tags
        for key in exploit:
            if key in self.ignored_exploit_keys:
                continue

            tag = self.common_tags_map.get(key)
            if tag is None:
                logger.warning("missing tag for key: %s", key)
                continue

            tags.append(tag)

        return tags

    def _make_impact_from_tags(
        self,
        tags: list[str],
        impact: str | None,
    ) -> str:
        logger.debug("_make_impact_from_tags")

        if not impact:
            impact = ""

        for tag in self.impact_sort_order:
            if tag in tags:
                impact += tag + "\n"

        return impact

    def _make_new_cve_info_node(
        self,
        *,
        cve: str,
        active: Any,
        comp_uuid: str,
        dep_uuid: str | None = None,
    ) -> tuple[CveInfoNode | None, dict[str, Any] | None]:
        """Collect all info we can extract from the cve and put in in the CveInfoNode"""
        logger.debug("_make_new_cve_info_node")

        this_cve = self.vulnerabilities.get(cve)
        if this_cve is None:
            logger.error("missing cve info for: %s", cve)
            return None, None

        cve_info_node_instance = CveInfoNode()
        cve_info_node_instance.cve = cve
        cve_info_node_instance.comp_uuid = comp_uuid
        cve_info_node_instance.dep_uuid = dep_uuid
        cve_info_node_instance.active = bool(active)

        f_info: dict[str, Any] = self.info.get("file", {})
        # cve_info_node_instance.original_file = str(f_info.get("name", ""))
        cve_info_node_instance.original_file_sha256 = self._get_sha256(f_info)

        cve_info_node_instance.scan_date = datetime.datetime.fromisoformat(self._rest["timestamp"]).date()
        # cve_info_node_instance.scan_tool = self.SCAN_TOOL_NAME
        # cve_info_node_instance.scan_tool_version = self._rest.get("version", "no_scan_tool_version_specified")

        # score related
        cve_info_node_instance.cvss_version = int(this_cve.get("cvss", {}).get("version") or 0)

        score: float = float(this_cve.get("cvss", {}).get("baseScore") or 0.0)
        cve_info_node_instance.score = score
        cve_info_node_instance.score_severity = self._score_to_severity(score=score)

        cve_info_node_instance.tags = self._get_tags_from_cve(this_cve)
        cve_info_node_instance.impact = self._make_impact_from_tags(
            cve_info_node_instance.tags,
            cve_info_node_instance.impact,
        )
        if "Patching Mandated" in cve_info_node_instance.tags:
            cve_info_node_instance.known_exploited = True

        return cve_info_node_instance, this_cve

    def _get_component_purl(
        self,
        component: dict[str, Any],
    ) -> str:
        logger.debug("_get_component_purl")

        return str(component.get("identity", {}).get("purl", ""))

    def _get_dependency_purl(
        self,
        dependency: dict[str, Any],
    ) -> str:
        logger.debug("_get_dependency_purl")

        return str(dependency.get("purl", ""))

    def _do_one_cve_component_without_dependencies(
        self,
        comp_uuid: str,
        component: dict[str, Any],
        cve: str,
        active: Any,
    ) -> CveInfoNode | None:
        logger.debug("_do_one_cve_component_without_dependencies: %s; cve: %s", comp_uuid, cve)

        # one: component -> cve
        # the cve part (now we have one component and one vulnerability)

        cve_info_node_instance, this_cve = self._make_new_cve_info_node(
            cve=cve,
            active=active,
            comp_uuid=comp_uuid,
        )
        if cve_info_node_instance is None:
            return None

        identity = component.get("identity", {})
        version = identity.get("version", "")

        c_purl = self._get_component_purl(component=component)
        summary: str | None = this_cve.get("summary") if this_cve else None

        cve_info_node_instance.component_file_path = self._use_path_or_name(data=component, purl=c_purl)
        cve_info_node_instance.component_file_sha256 = self._get_sha256(data=component)
        cve_info_node_instance.component_file_purl = c_purl
        cve_info_node_instance.component_file_version = version
        cve_info_node_instance.component_file_name = component.get("name", "")
        cve_info_node_instance.component_type = "component"
        cve_info_node_instance.component_name = self._use_path_or_name(data=component, purl=c_purl, name_first=True)
        cve_info_node_instance.component_version = version
        cve_info_node_instance.component_purl = c_purl
        cve_info_node_instance.make_title_cin(cve=cve)
        cve_info_node_instance.make_description_cin(cve=cve, purl=c_purl, summary=summary)
        cve_info_node_instance.vuln_id_from_tool = cve

        logger.debug("%s", cve_info_node_instance)

        return cve_info_node_instance

    def _get_all_active_cve_on_components_without_dependencies(
        self,
    ) -> None:
        # all: component -> cve
        # the component part, could have many vulnerabilities
        logger.debug("_get_all_active_cve_on_components_without_dependencies")

        for comp_uuid, component in self.components.items():
            v = component.get("identity", {}).get("vulnerabilities", None)
            if v is None:
                logger.info("no vulnerabilities for component: %s", comp_uuid)
                continue

            for cve in v.get("active", []):
                cve_info_node_instance = self._do_one_cve_component_without_dependencies(
                    comp_uuid=comp_uuid,
                    component=component,
                    cve=cve,
                    active=True,
                )
                self._add_to_results(
                    cve=cve,
                    comp_uuid=comp_uuid,
                    dep_uuid=None,
                    cve_info_node_instance=cve_info_node_instance,
                )

    # =========================================================
    # component -> dependency -> cve
    def _do_one_cve_component_dependency(
        self,
        comp_uuid: str,
        component: dict[str, Any],
        dep_uuid: str,
        dependency: dict[str, Any],
        cve: str,
        active: Any,
    ) -> CveInfoNode | None:
        logger.debug("_do_one_cve_component_dependency: %s; dep: %s; cve: %s", comp_uuid, dep_uuid, cve)

        # one: component -> dependency -> cve
        # the cve part (now we have one component, one dependency, one vulnerability)

        cve_info_node_instance, this_cve = self._make_new_cve_info_node(
            cve=cve,
            active=active,
            comp_uuid=comp_uuid,  # component
            dep_uuid=dep_uuid,  # dependency
        )
        if cve_info_node_instance is None:
            return None

        ident = component.get("identity", {})
        c_purl = self._get_component_purl(component=component)
        summary: str | None = this_cve.get("summary") if this_cve else None

        cve_info_node_instance.component_file_path = self._use_path_or_name(data=component, purl=c_purl)
        cve_info_node_instance.component_file_sha256 = self._get_sha256(data=component)
        cve_info_node_instance.component_file_purl = c_purl
        cve_info_node_instance.component_file_version = ident.get("version", "")
        cve_info_node_instance.component_file_name = component.get("name", "")
        cve_info_node_instance.component_type = "dependency"
        cve_info_node_instance.component_name = dependency.get(
            "product",
            f"no_{cve_info_node_instance.component_type}_product_provided",
        )
        cve_info_node_instance.component_version = dependency.get(
            "version",
            f"no_{cve_info_node_instance.component_type}_version_provided",
        )

        d_purl = self._get_dependency_purl(dependency=dependency)
        cve_info_node_instance.component_purl = d_purl
        cve_info_node_instance.make_title_cin(cve=cve)
        cve_info_node_instance.make_description_cin(cve=cve, purl=d_purl, summary=summary)
        cve_info_node_instance.vuln_id_from_tool = cve

        # dep_purl = dependency.get("purl", "")
        # dep_name = dependency.get("product", "")
        # dep_version = dependency.get("version", "")
        # if we have a dependency purl then purl, otherwise component product + version
        # tail = dep_purl
        # if len(tail) == 0:
        #     tail = f"{dep_name}@{dep_version}"

        logger.debug("%s", cve_info_node_instance)
        return cve_info_node_instance

    def _get_one_active_cve_component_dependency(
        self,
        comp_uuid: str,
        component: dict[str, Any],
        dep_uuid: str,
    ) -> None:
        logger.debug("_get_one_active_cve_component_dependency")

        # one: component -> dependency -> cve
        # the dependency (could have many vulnerabilties)

        dependency = self.dependencies.get(dep_uuid)
        if dependency is None:
            logger.error("missing dependency: %s", dep_uuid)
            return

        # -------------------------------
        v = dependency.get("vulnerabilities")
        if v is None:
            logger.info("no vulnerabilities for dependency: %s", dep_uuid)
            return

        # -------------------------------
        for cve in v.get("active", []):  # active is a list of CVE_strings
            cve_info_node_instance = self._do_one_cve_component_dependency(
                comp_uuid=comp_uuid,
                component=component,
                dep_uuid=dep_uuid,
                dependency=dependency,
                cve=cve,
                active=True,
            )
            self._add_to_results(
                cve=cve,
                comp_uuid=comp_uuid,
                dep_uuid=dep_uuid,
                cve_info_node_instance=cve_info_node_instance,
            )

    def _get_all_active_cve_on_components_with_dependencies(
        self,
    ) -> None:
        logger.debug("_get_all_active_cve_on_components_with_dependencies")

        # all: component -> dependency -> cve
        # the component part

        for comp_uuid, component in self.components.items():
            d = component.get("identity", {}).get("dependencies", None)
            if d is None:
                logger.info("no dependencies for component: %s", comp_uuid)
                continue

            for dep_uuid in d:
                # returns one dep_uuid, multiple cve (if any cve)
                self._get_one_active_cve_component_dependency(
                    comp_uuid=comp_uuid,
                    component=component,
                    dep_uuid=dep_uuid,
                )

    def _verify_file_is_also_component(
        self,
    ) -> bool:
        logger.debug("_verify_file_is_also_component")

        # the file mentioned in the info part of the report must also be a component.
        f_info: dict[str, Any] = self.info.get("file", {})
        file_sha256 = self._get_sha256(f_info)

        file_is_component = self._find_sha256_in_components(file_sha256)
        if file_is_component is False:
            msg = f"file cannot be found as component: {f_info}"
            raise ValueError(msg)

        return file_is_component

    def _find_severity_string(self, severity: str) -> str:
        logger.debug("_find_severity_string")

        for s in self.severity_map.values():
            if severity.lower() == s.lower():
                return s
        logger.warning("unmapped violation severity %r, defaulting to Info", severity)
        return self.severity_map[1]  # "Info"

    def _find_score_from_severity(self, severity: str) -> int:
        logger.debug("_find_score_from_severity")

        for k, v in self.severity_map.items():
            if severity.lower() == v.lower():
                return k
        return 0

    def _filter_violations_failed_of_category(
        self,
        category: str,
    ) -> list[dict[str, Any]]:
        logger.debug("_filter_violations_failed_of_category")

        ll: list[dict[str, Any]] = []
        for viol in self.violations.values():
            # filter for relevant
            s = viol.get("status", "")
            if s != "fail":
                continue

            c = viol.get("category")
            if not c or c != category:
                continue

            logger.debug("violation: %s", viol)

            for comp_uuid in viol.get("references", {}).get("component", []):
                logger.debug("component_uuid: %s", comp_uuid)
                comp = self.components.get(comp_uuid)
                if not comp:
                    continue  # missing components, ignore for now

                logger.debug("component: %s", comp)

                # we have a relevant entry

                rr: dict[str, Any] = {}

                rr["status"] = s
                rr["category"] = c
                rr["rule_id"] = viol.get("rule_id")
                rr["description"] = viol.get("description")
                rr["score_severity"] = self._find_severity_string(viol.get("severity", ""))
                rr["score"] = None  # self._find_score_from_severity(rr["score_severity"])
                rr["comp_uuid"] = comp_uuid
                rr["comp_class_result"] = comp.get("classification", {}).get("result")
                rr["comp_sha256"] = self._get_sha256(comp)
                rr["name"] = comp.get("name")
                rr["name_or_path"] = self._use_path_or_name(data=comp)

                ll.append(rr)
        return ll

    def _make_simple_title(
        self,
        data: dict[str, Any],
    ) -> str:
        logger.debug("_make_simple_title")

        rr: list[str] = [
            data["description"],
            f"({data['category']})",
            f"on {data['name']}",
        ]
        return " ".join(rr)

    def _make_simple_description(
        self,
        data: dict[str, Any],
    ) -> str:
        logger.debug("_make_simple_description")

        rr: list[str] = []  # title will be added to the description on dojo insert by the partser module
        if data["comp_class_result"]:
            rr.append(f"Threat name: {data['comp_class_result']}")
        return " ".join(rr)

    def _make_simple_node(
        self,
        data: dict[str, Any],
    ) -> CveInfoNode:
        logger.debug("_make_simple_node")

        cve_info_node_instance = CveInfoNode()
        cve_info_node_instance.active = True

        my_id = f"{data['category']}-{data['rule_id']}"

        f_info: dict[str, Any] = self.info.get("file", {})

        # cve_info_node_instance.original_file = str(f_info.get("name", ""))
        cve_info_node_instance.original_file_sha256 = self._get_sha256(f_info)

        cve_info_node_instance.scan_date = datetime.datetime.fromisoformat(self._rest["timestamp"]).date()
        # cve_info_node_instance.scan_tool = self.SCAN_TOOL_NAME
        # cve_info_node_instance.scan_tool_version = self._rest.get("version", "no_scan_tool_version_specified")

        cve_info_node_instance.component_file_path = data["name_or_path"]
        cve_info_node_instance.component_file_sha256 = data["comp_sha256"]
        cve_info_node_instance.component_file_name = data["name"]
        cve_info_node_instance.component_type = "component"
        cve_info_node_instance.component_name = data["name"]
        cve_info_node_instance.vuln_id_from_tool = my_id
        # cve_info_node_instance.cve = f"{data['category']}-{data['rule_id']}"

        cve_info_node_instance.title = self._make_simple_title(data)
        cve_info_node_instance.description = self._make_simple_description(data)
        cve_info_node_instance.score = data["score"]
        cve_info_node_instance.score_severity = data["score_severity"]

        return cve_info_node_instance

    def _collect_violations_by_category(self, category: str) -> None:
        logger.debug("_collect_violations_by_category")

        result_list = self._filter_violations_failed_of_category(category)
        for item in result_list:
            logger.debug("violations_by_category: %s: %s", category, item)

            cve_info_node_instance = self._make_simple_node(item)
            self._add_to_results(
                cve=None,  # cve_info_node_instance.cve,
                comp_uuid=item["comp_uuid"],
                dep_uuid=None,
                cve_info_node_instance=cve_info_node_instance,
            )

    def _get_cve_active_all(self) -> None:
        """
        0: verify that the info -> file sha256 comes back as a component,
           so we can forget about it as it will be processed as a component
        A: walk over components with active vulnerabilities
        B: walk over components -> dependencies with active vulnerabilities
        """
        logger.debug("_get_cve_active_all")

        self.file_is_component = self._verify_file_is_also_component()
        self._get_all_active_cve_on_components_without_dependencies()
        self._get_all_active_cve_on_components_with_dependencies()

    # ==== PUBLIC ======
    def get_results_list(self) -> Iterator[CveInfoNode]:
        logger.debug("get_results_list")

        # self.results[cve][comp_uuid][dep_uuid] -> cve_info_node_instance
        try:
            for components in self._results.values():
                for component in components.values():
                    for cve_info_node_instance in component.values():
                        logger.debug("result: %s", cve_info_node_instance)
                        yield cve_info_node_instance
        except Exception as e:
            msg = f"Exception iterating over results: {e}"
            logger.exception(msg)
            raise ValueError(msg) from e

    def build_findings(self) -> None:
        logger.debug("build_findings")
        self._get_cve_active_all()
        self._collect_violations_by_category("threats")
        self._collect_violations_by_category("secrets")
