"""Track view identity with a lock held only for registry operations."""

from __future__ import annotations

import threading
import weakref
from typing import Any


def same_view(first: Any, second: Any) -> bool:
    if first is second:
        return True
    if first is None or second is None:
        return False
    # BinaryView equality compares native handles, unlike a filename comparison.
    try:
        return bool(first == second)
    except (ReferenceError, ValueError):
        return False


class ViewRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._views: dict[str, weakref.ReferenceType] = {}
        self._ui_views: dict[str, Any] = {}
        self._next_id = 1
        self._edit_versions: dict[tuple[str, int, str | None], int] = {}
        self.current: Any = None

    def _prune(self) -> None:
        alive = {}
        for key, ref in self._views.items():
            view = ref()
            if view is not None:
                try:
                    getattr(view, "handle", None)
                except ReferenceError:
                    continue
                alive[key] = ref
        self._views = alive
        self._ui_views = {key: view for key, view in self._ui_views.items() if key in alive}
        self._edit_versions = {
            key: value for key, value in self._edit_versions.items() if key[0] in alive
        }

    def edit_version(
        self, view_id: str, address: int, *, variable_id: str | None = None, advance: bool = False
    ) -> int:
        with self._lock:
            key = (view_id, address, variable_id)
            value = self._edit_versions.get(key, 0) + int(advance)
            if advance:
                self._edit_versions[key] = value
            return value

    def register(self, view: Any, *, keep_alive: bool = False) -> str:
        with self._lock:
            self._prune()
            for key, ref in self._views.items():
                if same_view(ref(), view):
                    self._views[key] = weakref.ref(view)
                    if keep_alive:
                        self._ui_views[key] = view
                    return key
            key = str(self._next_id)
            self._next_id += 1
            self._views[key] = weakref.ref(view)
            if keep_alive:
                self._ui_views[key] = view
            return key

    def resolve(self, view_id: str) -> Any:
        with self._lock:
            self._prune()
            ref = self._views.get(view_id)
            view = ref() if ref is not None else None
            if view is None:
                raise LookupError("Binary view is closed or unknown. Call list_binaries.")
            return view

    def set_current(self, view: Any) -> None:
        with self._lock:
            self.current = view
            if view is not None:
                self.register(view)

    def listing(self) -> list[dict[str, Any]]:
        with self._lock:
            self._prune()
            rows = []
            for key, ref in self._views.items():
                view = ref()
                if view is not None:
                    rows.append(
                        {
                            "id": key,
                            "filename": getattr(view.file, "filename", None),
                            "active": same_view(view, self.current),
                            "view_type": getattr(view, "view_type", None),
                        }
                    )
            return sorted(rows, key=lambda row: (row["filename"] or "", row["id"]))

    def unregister_file(self, metadata: Any) -> int:
        """Remove the actual closing file session, including all its view types."""
        with self._lock:
            removed = []
            for key, ref in self._views.items():
                view = ref()
                if view is None or same_view(getattr(view, "file", None), metadata):
                    removed.append(key)
            for key in removed:
                self._views.pop(key, None)
                self._ui_views.pop(key, None)
            self._prune()
            if self.current is not None and same_view(self.current.file, metadata):
                self.current = None
            return len(removed)

    def unregister_filename(self, filename: str) -> int:
        with self._lock:
            metadata = []
            for ref in self._views.values():
                view = ref()
                if view is not None and view.file.filename == filename:
                    metadata.append(view.file)
            return sum(self.unregister_file(file) for file in metadata)
