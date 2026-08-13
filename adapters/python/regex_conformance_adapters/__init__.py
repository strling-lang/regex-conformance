"""Thin, verdict-free adapters for the governed P17 vertical slice."""

from .manifest import AdapterManifest, load_manifest
from .server import AdapterServer

__all__ = ["AdapterManifest", "AdapterServer", "load_manifest"]
