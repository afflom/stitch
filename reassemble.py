#!/usr/bin/env python3
"""Verify and reassemble this distribution using Python 3 standard library only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile


def reassemble(root, output):
    manifest = json.loads((root / 'manifest.json').read_text())
    if output.exists():
        raise ValueError(f'Refusing to replace existing output: {output}')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        total = 0
        digest = hashlib.sha256()
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.guest-source-', delete=False) as target:
            temporary = Path(target.name)
            for entry in manifest['parts']:
                relative = Path(entry['path'])
                if relative.is_absolute() or '..' in relative.parts:
                    raise ValueError('Invalid part path')
                part_hash = hashlib.sha256()
                blob_hash = hashlib.sha1(f"blob {entry['size']}\0".encode())
                size = 0
                with (root / relative).open('rb') as source:
                    for block in iter(lambda: source.read(1024 * 1024), b''):
                        size += len(block)
                        part_hash.update(block)
                        blob_hash.update(block)
                        digest.update(block)
                        target.write(block)
                if (size != entry['size'] or part_hash.hexdigest() != entry['sha256']
                        or blob_hash.hexdigest() != entry['git_blob_sha']):
                    raise ValueError(f"Part verification failed: {relative}")
                total += size
            if total != manifest['archive']['size'] or digest.hexdigest() != manifest['archive']['sha256']:
                raise ValueError('Complete archive verification failed')
            target.flush()
            os.fsync(target.fileno())
        # Atomic creation, refusing to overwrite even if another process creates output.
        os.link(temporary, output)
        print(f"Verified {total} bytes: {digest.hexdigest()}\nSaved {output}")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('stitch-guest-corresponding-source.tar.gz'))
    args = parser.parse_args()
    try:
        reassemble(Path(__file__).resolve().parent, args.output.resolve())
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f'Error: {error}\n')
