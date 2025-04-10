from typing import (
    Any,
    List,
    Dict,
)

import json
import logging

from .typeLoaderInfo import TypeLoaderInfo

logger = logging.getLogger(__name__)


class TreeLoader:
    fields: Dict[str, Any] = {}
    _rest: Dict[str, Any] = {}

    def __init__(
        self,
        fields: Dict[str, str],
        raw_subtree: Dict[str, Any],
    ):
        self.var_populate(
            fields=self.fields,
        )

        self.load_subtree(
            raw_subtree=raw_subtree,
            names=self.make_names(fields=self.fields),
        )

    def no_key(
        self,
        name: str,
        _type: str,
    ) -> Any:
        logger.warning("no key: %s", name)

        if _type == "dict":
            return {}
        if _type == "list":
            return []

        return None

    def no_data(
        self,
        name: str,
        _type: str,
    ) -> Any:
        logger.warning("no data for: %s", name)
        if _type == "dict":
            return {}
        if _type == "list":
            return []
        return None

    def load_one_item(
        self,
        item: TypeLoaderInfo,
        raw_subtree: Dict[str, Any],
    ) -> Any:
        name = item.name
        var = getattr(self, name)
        _type = item._type

        if name not in raw_subtree:
            return self.no_key(name=name, _type=_type)

        comp = raw_subtree.get(name)
        if comp is None:
            del raw_subtree[name]
            return self.no_data(name=name, _type=_type)

        if _type == "dict":
            for k, v in comp.items():
                var[k] = v
            del raw_subtree[name]
            return var

        if _type == "list":
            for item in comp:
                var.append(item)
            del raw_subtree[name]
            return var

        if _type == "Crypto":
            subtree_crypto = raw_subtree.get(name, {})
            var = RlCrypto(raw_subtree=subtree_crypto)
            if len(subtree_crypto) == 0:
                del raw_subtree[name]
            return var

    def load_subtree(
        self,
        *,
        raw_subtree: Dict[str, Any],
        names: List[TypeLoaderInfo],
    ) -> None:
        for item in names:
            setattr(
                self,
                item.name,
                self.load_one_item(
                    item=item,
                    raw_subtree=raw_subtree,
                ),
            )

        self._rest = raw_subtree

    def var_populate(
        self,
        fields: Dict[str, str],
    ) -> None:
        for k, v in self.fields.items():
            if v == "dict":
                setattr(self, k, {})
                continue
            if v == "list":
                setattr(self, k, [])
                continue
            setattr(self, k, None)

    def make_names(
        self,
        fields: Dict[str, str],
    ) -> List[TypeLoaderInfo]:
        names: List[TypeLoaderInfo] = []
        for k, v in self.fields.items():
            names.append(
                TypeLoaderInfo(name=k, _type=v),
            )
        return names

    def __str__(self) -> str:
        z = {}
        for k, v in self.fields.items():
            if v in ["dict", "list"]:
                z[k] = getattr(self, k)
            else:
                z[k] = getattr(self, k).__dict__

        return json.dumps(z, sort_keys=True, indent=2)

    def __repr__(self) -> str:
        return json.dumps(self.__dict__)


class RlCrypto(TreeLoader):
    fields = {
        "algorithms": "dict",
        "materials": "dict",
        "certificates": "dict",
        "protocols": "dict",
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

    def __repr__(self) -> str:
        return json.dumps(self.__dict__)
