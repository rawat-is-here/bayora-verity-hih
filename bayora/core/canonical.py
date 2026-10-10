from __future__ import annotations
import json
from typing import Any

def canonicalize_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): canonicalize_obj(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [canonicalize_obj(item) for item in obj]
    if isinstance(obj, float):
        if obj.is_integer():
            return int(obj)
        return obj
    return obj

def canonical_json_bytes(data: Any) -> bytes:
    normalized = canonicalize_obj(data)
    return json.dumps(normalized, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def canonical_json_str(data: Any) -> str:
    return canonical_json_bytes(data).decode('utf-8')
