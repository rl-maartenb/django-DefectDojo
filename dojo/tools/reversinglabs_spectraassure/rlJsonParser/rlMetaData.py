from typing import (
    Any,
    Dict,
)

import logging
from .treeLoader import TreeLoader

logger = logging.getLogger(__name__)


class RlMetaData(TreeLoader):
    fields = {
        "assessments": "dict",
        "components": "dict",
        "cryptography": "Crypto",
        "dependencies": "dict",
        "indicators": "dict",
        "licenses": "dict",
        "secrets": "dict",
        "services": "dict",
        "violations": "dict",
        "vulnerabilities": "dict",
        "ml_models": "dict",
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
