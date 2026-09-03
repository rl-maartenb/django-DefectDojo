import datetime
import logging

logger = logging.getLogger(__name__)


class CveInfoNode:

    def __init__(self) -> None:
        self.active: bool = True
        self.title: str = ""
        self.description: str = ""

        self.component_file_name: str = ""
        self.component_file_path: str = ""
        self.component_file_purl: str = ""
        self.component_file_sha256: str = ""
        self.component_file_version: str = ""
        self.component_name: str = ""
        self.component_purl: str = ""
        self.component_type: str = "component"
        self.component_version: str = ""
        self.comp_uuid: str = ""

        self.cve: str | None = None
        self.vuln_id_from_tool: str = ""

        self.dep_uuid: str | None = None
        self.impact: str = ""

        self.original_file_sha256: str = ""
        # self.original_file: str = ""

        self.scan_date: datetime.date = datetime.datetime.now(tz=datetime.UTC).date()
        # self.scan_tool: str = ""
        # self.scan_tool_version: str = ""

        self.cvss_version: int = 0
        self.score: float = 0.0  # this is normally the v3 score, we have no v4 in the report yet
        self.score_severity: str = "Info"  # score mapped to severity

        self.tags: list[str] = []
        # self.unique_id_from_tool: str = ""
        self.known_exploited: bool = False

    def __str__(self) -> str:
        return f"{self.__dict__}"

    def make_title_cin(
        self,
        cve: str,
    ) -> str:
        logger.debug("make_title_cin")

        tt: list[str] = [
            f"{cve}",
            f"on {self.component_type}",
        ]

        purl = self.component_purl
        if self.component_type == "component":
            purl = self.component_file_purl

        if purl:
            tt.append(f"purl: {purl}")
        else:
            tt.extend(
                [
                    f"name: {self.component_name}",
                    f"version: {self.component_version}",
                ],
            )

        #        with_sha256: bool = False
        #        if self.component_type == "component":
        #            if with_sha256:
        #                tt.append(f" (sha256: {self.component_file_sha256})")

        self.title = " ".join(tt)
        return self.title

    def append_summary(
        self,
        dd: list[str],
        summary: str | None = None,
    ) -> str:
        logger.debug("append_summary")

        if summary:
            dd.insert(0, summary)
        self.description = " ".join(dd)
        return self.description

    def make_description_cin(
        self,
        *,
        cve: str,
        purl: str,
        summary: str | None = None,
    ) -> str:
        logger.debug("make_description_cin")

        dd: list[str] = []
        if self.component_type == "component":
            dd = [
                f"On {self.component_type}",
                f"purl: {purl}",
                f"version: {self.component_version}",
                f"path: {self.component_file_path}",
                f"(sha256: {self.component_file_sha256})",
            ]
        else:
            purl = self.component_file_purl
            if not purl:
                purl = self.component_file_name + "@" + self.component_file_version

            dd = [
                "On component",
                f"purl: {purl}",
                f"path: {self.component_file_path}",
                f"(sha256: {self.component_file_sha256})",
            ]
        return self.append_summary(dd, summary)
