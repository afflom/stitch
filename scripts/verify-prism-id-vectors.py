#!/usr/bin/env python3
"""Independent check of prism id canonical JSON and kappa vectors.

Written from docs/prism-id.md, not from src/prism-id.js, using only the Python
standard library. A native, mobile or embedded implementation can be checked
against the same vectors the same way.
"""
import hashlib
import json
import sys
import unicodedata


class Refused(Exception):
    pass


def string(text):
    try:
        text.encode('utf-8')
    except UnicodeEncodeError as error:
        raise Refused('not well-formed Unicode') from error
    if unicodedata.normalize('NFC', text) != text:
        raise Refused('not NFC')
    out = ['"']
    for ch in text:
        c = ord(ch)
        simple = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\t': '\\t', '\n': '\\n', '\f': '\\f', '\r': '\\r'}
        if ch in simple:
            out.append(simple[ch])
        elif c < 0x20:
            out.append('\\u%04x' % c)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def canonical(value):
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, int):
        if abs(value) > 2 ** 53 - 1:
            raise Refused('integer outside the safe range')
        return str(value)
    if isinstance(value, float):
        raise Refused('number outside the integer subset')
    if isinstance(value, str):
        return string(value)
    if isinstance(value, list):
        return '[' + ','.join(canonical(v) for v in value) + ']'
    if isinstance(value, dict):
        for key in value:
            string(key)
        keys = sorted(value, key=lambda k: k.encode('utf-8'))
        return '{' + ','.join(string(k) + ':' + canonical(value[k]) for k in keys) + '}'
    raise Refused('not JSON')


def kappa(value):
    return 'sha256:' + hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def main(path):
    with open(path, encoding='utf-8') as handle:
        vectors = json.load(handle)
    for v in vectors['canonical']:
        got = canonical(v['value'])
        if got != v['canonical'] or kappa(v['value']) != v['kappa']:
            print('mismatch: ' + v['name'], file=sys.stderr)
            return 1
    for v in vectors['refused']:
        try:
            canonical(v['value'])
        except Refused:
            continue
        print('accepted a refused vector: ' + v['name'], file=sys.stderr)
        return 1
    for record in vectors['prism']['records']:
        if record['body']['kind'] == 'prism/genesis/1' and kappa(record['body']) != vectors['prism']['id']:
            print('prism id is not the kappa of its genesis', file=sys.stderr)
            return 1
        if record['body']['kind'] in ('prism/genesis/1', 'prism/bind/1'):
            device = record['body']['device']
            if record['body']['kind'] == 'prism/genesis/1' and kappa(device) != record['signer']:
                print('genesis signer is not the kappa of its device record', file=sys.stderr)
                return 1
    print('verified %d canonical vectors and %d refusals' % (len(vectors['canonical']), len(vectors['refused'])))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
