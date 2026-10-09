import os
from dataclasses import dataclass, field


@dataclass
class ServerConfig:
    host: str = "localhost"
    port: int = 9009
    debug: bool = False
    read_timeout: float = 5.0
    shutdown_timeout: float = 1.0
    auth_token: str = field(
        repr=False, default_factory=lambda: os.environ.get("BINJA_MCP_TOKEN", "")
    )


@dataclass
class BinaryNinjaConfig:
    api_version: str | None = None
    log_level: str = "INFO"


class Config:
    def __init__(self):
        self.server = ServerConfig()
        self.binary_ninja = BinaryNinjaConfig()
