"""Load real plugin modules while replacing only the unavailable application SDK."""

import importlib
import json
import re
import sys
import types
from contextlib import contextmanager
from enum import IntEnum
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace as Obj
from typing import Any


class SymbolType(IntEnum):
    FunctionSymbol = 0
    DataSymbol = 1
    ImportedFunctionSymbol = 2
    ImportAddressSymbol = 3
    ImportedDataSymbol = 4
    ExternalSymbol = 5
    SymbolicFunctionSymbol = 6


class SymbolBinding(IntEnum):
    NoBinding = 0
    LocalBinding = 1
    GlobalBinding = 2
    WeakBinding = 3


_modules = None


def load_plugin_modules():
    global _modules
    if _modules is not None:
        return _modules
    root = Path(__file__).resolve().parents[1]
    for name in list(sys.modules):
        if name == "plugin" or name.startswith("plugin."):
            del sys.modules[name]
    for name in ("plugin", "plugin.api", "plugin.core", "plugin.server", "plugin.utils"):
        package = types.ModuleType(name)
        package.__path__ = [str(root / name.replace(".", "/"))]
        sys.modules[name] = package
    bn = types.ModuleType("binaryninja")
    for name in ("log_info", "log_error", "log_debug", "log_warn"):
        setattr(bn, name, lambda *_: None)
    for name in ("BinaryView", "Function", "Type", "Symbol"):
        setattr(bn, name, object)
    setattr(bn, "SymbolType", SymbolType)
    setattr(bn, "SymbolBinding", SymbolBinding)
    sys.modules["binaryninja"] = bn
    enums = types.ModuleType("binaryninja.enums")
    setattr(enums, "StructureVariant", Obj())
    setattr(enums, "TypeClass", Obj())
    sys.modules["binaryninja.enums"] = enums
    operations = importlib.import_module("plugin.core.binary_operations")
    endpoints = importlib.import_module("plugin.api.endpoints")
    server = importlib.import_module("plugin.server.agent_http_server")
    config = importlib.import_module("plugin.core.config")
    _modules = operations, endpoints, server, config
    return _modules


class FakeView:
    def __init__(self, filename="sample.exe", view_type="PE"):
        self.file = Obj(filename=filename, original_filename=None)
        self.view_type = view_type
        self.arch = Obj(name="x86_64")
        self.start, self.end = 0x1000, 0x100000
        self.endianness = Obj(name="LittleEndian")
        self.entry_point = 0x1000
        self.functions = [Obj(name="sub_1000", raw_name="sub_1000", start=0x1000, symbol=None)]
        self.symbols: list[Any] = []
        self.comments: dict[int, str] = {}
        self.sections = {}
        self.segments = []
        self._strings = []
        self._data = {}
        self._types = {}
        self._history = []
        self.analysis_updates = 0
        self.analysis_progress = Obj(state=Obj(name="IdleState"), count=1, total=1)

    def parse_type_string(self, declaration, import_dependencies=True):
        if "(" in declaration and ")" in declaration:
            return FakeType(declaration, kind="FunctionTypeClass"), ""
        if (
            declaration in ("int32_t", "uint32_t", "uint64_t", "int", "char *")
            or declaration.rstrip(" *") in self._types
        ):
            return FakeType(declaration), ""
        raise SyntaxError("Invalid declaration")

    def parse_types_from_string(self, declaration, import_dependencies=True):
        names = re.findall(r"struct\s+(\w+)\s*\{", declaration)
        if not names:
            raise SyntaxError("Invalid declaration")
        return Obj(
            types={name: FakeType(f"struct {name}", declaration=declaration) for name in names},
            functions={},
            variables={},
        )

    def get_type_by_name(self, name):
        return self._types.get(name)

    def define_user_type(self, name, value):
        self._types[str(name)] = value

    def update_analysis(self):
        self.analysis_updates += 1

    @contextmanager
    def undoable_transaction(self):
        snapshot = (
            dict(self._types),
            [
                (f, getattr(f, "type", None), [(v, v.name, v.type) for v in getattr(f, "vars", ())])
                for f in self.functions
            ],
        )
        self._history.append(snapshot)
        try:
            yield
        except Exception:
            self.undo()
            raise

    def undo(self):
        self._types, functions = self._history.pop()
        for function, value, variables in functions:
            function.type = value
            for variable, name, var_type in variables:
                variable.name, variable.type = name, var_type

    def get_strings(self, start=None, length=None):
        if start is None:
            return self._strings
        return [ref for ref in self._strings if start <= ref.start < start + length]

    def read(self, address, length):
        for start, data in self._data.items():
            if start <= address < start + len(data):
                return data[address - start : address - start + length]
        return b"\x90" * min(length, max(0, self.end - address))

    def get_functions_containing(self, address):
        return [
            function
            for function in self.functions
            if function.start <= address < function.start + 16
        ]

    def get_code_refs(self, address):
        return []

    def get_data_refs(self, address):
        return []

    def get_function_at(self, address):
        return next((function for function in self.functions if function.start == address), None)

    def get_functions_by_name(self, name):
        return [function for function in self.functions if function.name == name]

    def get_symbol_by_raw_name(self, name):
        return next((symbol for symbol in self.symbols if symbol.name == name), None)

    def get_symbol_by_name(self, name):
        return self.get_symbol_by_raw_name(name)

    def get_symbol_at(self, address):
        return next((symbol for symbol in self.symbols if symbol.address == address), None)

    def get_symbols(self):
        return self.symbols

    def get_symbols_of_type(self, kind):
        return [symbol for symbol in self.symbols if symbol.type == kind]

    def is_valid_offset(self, address):
        return self.start <= address < self.end

    def get_comment_at(self, address):
        return self.comments.get(address, "")

    def set_comment_at(self, address, comment):
        self.comments[address] = comment


class StringReference:
    def __init__(self, view, start, raw, string_type="Utf8String"):
        self._view = view
        self.start = start
        self.length = len(raw)
        self.type = Obj(name=string_type)
        view._data[start] = raw

    @property
    def value(self):
        raise AssertionError("Query must not invoke unbounded SDK StringReference.value")


class TextLine:
    operation: Any
    dest: Any
    params: list[Any]
    instr_index: int

    def __init__(self, address, text):
        self.address = address
        self.text = text

    def __str__(self):
        return self.text


class FakeType:
    def __init__(self, value, kind="IntegerTypeClass", declaration=None):
        self.value = value
        self.type_class = Obj(name=kind)
        self.width = 8 if "64" in value or "*" in value else 4
        self.alignment = self.width
        self.parameters = []
        self.declaration = declaration or value

    def __str__(self):
        return self.value

    def __eq__(self, other):
        return isinstance(other, FakeType) and self.declaration == other.declaration

    def get_lines(self, view, name):
        return self.declaration.splitlines()


class FakeFunction(Obj):
    def is_var_user_defined(self, variable):
        return True

    def create_user_var(self, variable, var_type, name):
        variable.name = name
        variable.type = var_type


def populated_view():
    view = FakeView()
    function = FakeFunction(**vars(view.functions[0]))
    view.functions[0] = function
    function.type = FakeType("int32_t(int32_t value)", kind="FunctionTypeClass")
    function.type.parameters = [Obj(name="value", type=FakeType("int32_t"))]
    function.return_type = FakeType("int32_t")
    function.total_bytes = 2
    function.address_ranges = [Obj(start=0x1000, end=0x1002)]
    function.vars = [
        Obj(
            identifier=1,
            name="value",
            type=FakeType("int32_t"),
            storage=0,
            source_type=Obj(name="RegisterVariableSourceType"),
            is_parameter_variable=True,
        ),
        Obj(
            identifier=2,
            name="local",
            type=FakeType("int32_t"),
            storage=-4,
            source_type=Obj(name="StackVariableSourceType"),
            is_parameter_variable=False,
        ),
    ]
    argument = Obj(possible_values=Obj(type=Obj(name="ConstantValue"), value=16))
    destination = Obj(possible_values=Obj(type=Obj(name="ConstantPointerValue"), value=0x1000))
    call = TextLine(0x1001, "sub_1000(16)")
    call.operation, call.dest, call.params, call.instr_index = (
        Obj(name="MLIL_CALL"),
        destination,
        [argument],
        1,
    )
    function.call_sites = [Obj(address=0x1001, function=function, mlil=call)]
    function.caller_sites = []
    il = Obj(instructions=[TextLine(0x1000, "return 1"), TextLine(0x1001, "return 2")], root=Obj())
    il.ssa_form = il
    function.hlil = function.mlil = function.llil = il
    function.language_representation = lambda _: Obj(get_linear_lines=lambda root: il.instructions)
    function.callers = function.callees = []
    function.stack_layout = [Obj(name="local", storage=-8, type=Obj(width=8))]
    lines = [TextLine(0x1000, "nop"), TextLine(0x1001, "ret")]
    function.basic_blocks = [
        Obj(
            start=0x1000,
            end=0x1002,
            index=0,
            length=2,
            instruction_count=2,
            can_exit=True,
            outgoing_edges=[],
            get_disassembly_text=lambda: lines,
        )
    ]
    view._strings = [StringReference(view, 0x2000, b"fixture string")]
    view.sections = {".text": Obj(name=".text", start=0x1000, end=0x3000)}
    view.segments = [Obj(start=0x1000, end=0x3000, readable=True, writable=False, executable=True)]
    view.symbols = [
        Obj(
            name="exported",
            type=SymbolType.FunctionSymbol,
            address=0x1000,
            binding=SymbolBinding.GlobalBinding,
        )
    ]
    return view


class HTTPFixture:
    def __init__(self, token="", read_timeout=0.3):
        _, _, server, config = load_plugin_modules()
        settings = config.Config()
        settings.server.host = "127.0.0.1"
        settings.server.port = 0
        settings.server.auth_token = token
        settings.server.read_timeout = read_timeout
        settings.server.shutdown_timeout = 0.3
        self.mcp = server.MCPServer(settings)
        self.mcp.start()
        self.http = self.mcp.server
        self.port = self.http.server_port

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            encoded = json.dumps(body).encode() if body is not None else None
            supplied = {"Content-Type": "application/json"}
            if headers:
                supplied.update(headers)
            connection.request(method, path, body=encoded, headers=supplied)
            response = connection.getresponse()
            data = response.read()
            return response.status, json.loads(data) if data else None
        finally:
            connection.close()

    def close(self):
        self.mcp.stop()
        self.http.wait_workers(2)
