"""Bounded, checksummed JSONL capture storage with legacy-file compatibility."""
import hashlib
import json
import os
import re
from pathlib import Path

MAX_PART_BYTES = 16 * 1024 * 1024

def _atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.tmp')
    with temporary.open('wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)

def _index(path):
    return path.with_suffix('.index.json')

def read_captures(path):
    path = Path(path)
    index = _index(path)
    if not index.exists():
        return None
    value = json.loads(index.read_text())
    if set(value) != {'schema_version', 'rows', 'parts'} or value['schema_version'] != 1:
        raise ValueError('invalid capture index')
    rows = []
    seen = set()
    for part in value['parts']:
        name = part['path']
        if not re.fullmatch(r'captures/[0-9a-f]{64}\.jsonl', name) or name in seen:
            raise ValueError('invalid or duplicate capture part')
        seen.add(name)
        target = path.parent / name
        if target.is_symlink():
            raise ValueError('symlink capture part')
        body = target.read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        if len(body) > MAX_PART_BYTES or digest != part['sha256'] or target.stem != digest:
            raise ValueError('capture part integrity failure')
        chunk = [json.loads(line) for line in body.splitlines() if line.strip()]
        if len(chunk) != part['rows'] or any(not isinstance(row, dict) for row in chunk):
            raise ValueError('capture part row mismatch')
        canonical = ''.join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n' for row in chunk).encode()
        if canonical != body:
            raise ValueError('non-canonical capture part')
        rows.extend(chunk)
    if len(rows) != value['rows']:
        raise ValueError('capture index row mismatch')
    return rows

def write_captures(path, rows, part_bytes=MAX_PART_BYTES):
    path = Path(path)
    if not 1 <= part_bytes <= MAX_PART_BYTES:
        raise ValueError('invalid capture part limit')
    parts = []
    body = bytearray()
    count = total = 0
    def save(data, count):
        digest = hashlib.sha256(data).hexdigest()
        name = 'captures/' + digest + '.jsonl'
        _atomic(path.parent / name, data)
        parts.append({'path': name, 'sha256': digest, 'rows': count})
    for row in rows:
        line = (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if len(line) > part_bytes:
            raise ValueError('single capture exceeds part limit')
        if body and len(body) + len(line) > part_bytes:
            save(body, count)
            body = bytearray()
            count = 0
        body.extend(line)
        count += 1
        total += 1
    if body:
        save(body, count)
    value = {'schema_version': 1, 'rows': total, 'parts': parts}
    _atomic(_index(path), (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())
    # The index is durable before removing the legacy representation.
    if path.exists():
        path.unlink()
    keep = {part['path'] for part in parts}
    for old in (path.parent / 'captures').glob('*.jsonl'):
        if 'captures/' + old.name not in keep:
            old.unlink()
