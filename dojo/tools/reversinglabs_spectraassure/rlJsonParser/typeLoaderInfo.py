import logging

logger = logging.getLogger(__name__)


class TypeLoaderInfo:
    def __init__(
        self,
        name: str,
        _type: str = "dict",
    ) -> None:
        self.name = name
        self._type = _type
