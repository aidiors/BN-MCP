"""Symbol classification shared by current and compatibility query methods."""

from __future__ import annotations

from itertools import chain
from typing import Any

import binaryninja as bn


def symbols_for(view: Any, kind: str):
    import_types = (
        bn.SymbolType.ImportedFunctionSymbol,
        bn.SymbolType.ImportAddressSymbol,
        bn.SymbolType.ImportedDataSymbol,
        bn.SymbolType.ExternalSymbol,
    )
    if kind == "imports":
        return chain.from_iterable(
            view.get_symbols_of_type(symbol_type) for symbol_type in import_types
        )
    if kind != "exports":
        raise ValueError("kind must be imports or exports")
    export_bindings = (bn.SymbolBinding.GlobalBinding, bn.SymbolBinding.WeakBinding)
    return (
        symbol
        for symbol in view.get_symbols()
        if symbol.type not in import_types and getattr(symbol, "binding", None) in export_bindings
    )
