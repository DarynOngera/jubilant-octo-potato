"""Local, read-mostly web UI for the VulnForge factory."""

from .server import create_server, serve

__all__ = ["create_server", "serve"]
