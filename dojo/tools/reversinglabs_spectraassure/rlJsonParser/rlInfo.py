from typing import (
    Any,
    Dict,
)

import logging
from .treeLoader import TreeLoader


logger = logging.getLogger(__name__)


class RlInfo(TreeLoader):
    fields = {  # toplevel fields
        "detections": "dict",
        "inhibitors": "dict",
        "file": "dict",
        "statistics": "dict",
        "unpacking": "dict",
        "properties": "list",
        "disabled": "list",
        "warnings": "list",
    }

    def __init__(
        self,
        *,
        raw_subtree: Dict[str, Any],
    ) -> None:
        super().__init__(
            fields=self.fields,
            raw_subtree=raw_subtree,
        )
