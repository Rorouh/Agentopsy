"""Model layer: a common interface over local (default) and cloud backends."""

from forensia.models.base import ModelBackend, ModelCapabilities, get_backend

__all__ = ["ModelBackend", "ModelCapabilities", "get_backend"]
