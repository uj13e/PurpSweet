"""Decoder transforms and Comparer helpers.

All transforms operate on text as UTF-8. Hashing uses hashlib (md5/sha*).
Pure functions — unit-tested; no state.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import html
import io
import urllib.parse
import zlib
from typing import Any, Dict, List, Optional

import httpx

from .config import settings


def httpx_client_kwargs(read_timeout: float = 30.0) -> Dict[str, Any]:
    """Shared httpx client options: a short connect timeout (so unreachable
    targets fail fast, not after ~20s) plus an optional upstream proxy."""
    to = httpx.Timeout(
        connect=settings.connect_timeout,
        read=read_timeout, write=read_timeout, pool=read_timeout,
    )
    kw: Dict[str, Any] = {"timeout": to}
    if settings.upstream_proxy:
        kw["proxy"] = settings.upstream_proxy
    return kw


class TransformError(ValueError):
    pass


def _charset_from_ct(content_type: str) -> str:
    import re
    m = re.search(r'charset=["\']?([\w\-]+)', content_type or "", re.I)
    return m.group(1).strip().lower() if m else ""


# ---------------------------------------------------------------------------
# Content-Encoding handling
# ---------------------------------------------------------------------------
# Browsers (esp. Chrome) advertise `br` and `zstd`. If the capture engine can't
# decode those, the stored body is raw compressed bytes and renders as garbage.
# We (a) ask upstream for gzip/deflate at the proxy, (b) decode here as a
# fallback, and (c) show a readable placeholder when a body truly can't be
# decoded (so the user never sees a wall of binary).

_COMPRESSIONS = {"gzip", "x-gzip", "deflate", "br", "zstd", "compress"}
ENCODING_HEADERS = {"content-encoding", "content-length"}


def _first_token(encoding: str) -> str:
    return (encoding or "").split(",")[0].strip().lower()


def is_compressed_encoding(encoding: str) -> bool:
    tok = _first_token(encoding)
    return bool(tok) and tok in _COMPRESSIONS and tok != "identity"


def decompress(data: bytes, encoding: str) -> Optional[bytes]:
    """Best-effort decompress by Content-Encoding. Returns None if it can't
    (unknown encoding, missing optional lib, or the bytes aren't actually
    compressed with that scheme)."""
    enc = _first_token(encoding)
    if not data or not enc:
        return None
    try:
        if enc in ("gzip", "x-gzip"):
            if data[:2] != b"\x1f\x8b":
                return None
            return gzip.decompress(data)
        if enc == "deflate":
            try:
                return zlib.decompress(data)
            except zlib.error:
                try:
                    return zlib.decompress(data, -zlib.MAX_WBITS)
                except zlib.error:
                    return None
        if enc == "br":
            try:
                import brotli  # type: ignore
            except Exception:
                return None
            try:
                return brotli.decompress(data)
            except Exception:
                return None
        if enc == "zstd":
            try:
                import zstandard  # type: ignore
            except Exception:
                return None
            dctx = zstandard.ZstdDecompressor()
            try:
                return dctx.decompress(data)
            except Exception:
                # frames without an embedded content size need the streaming API
                try:
                    return dctx.stream_reader(io.BytesIO(data)).read()
                except Exception:
                    return None
    except Exception:
        return None
    return None


def strip_encoding_headers(pairs: List[List[str]]) -> List[List[str]]:
    """Remove content-encoding/content-length from a header list once we've
    stored the *decoded* body, so the viewer treats the body as plain text."""
    return [[k, v] for (k, v) in (pairs or []) if str(k).lower() not in ENCODING_HEADERS]


def decode_body(data: bytes, content_type: str = "", content_encoding: str = "") -> str:
    """Decode a response/request body to text.

    1. If a Content-Encoding is still present, try to decompress it (the capture
       engine normally does this, so this only fires for bodies it couldn't
       handle). If decompression isn't possible, return a short placeholder
       instead of raw binary.
    2. Guess the charset: declared charset, then UTF-8, then common Japanese
       encodings (Shift_JIS/EUC-JP), finally UTF-8 with replacement.
    """
    if not data:
        return ""
    data = bytes(data)

    if is_compressed_encoding(content_encoding):
        dec = decompress(data, content_encoding)
        if dec is not None:
            data = dec
        else:
            tok = _first_token(content_encoding)
            hint = (" — install the decoder: pip install brotli zstandard"
                    if tok in ("br", "zstd") else "")
            return f"[{tok}-compressed body, {len(data)} bytes; could not decode{hint}]"

    tried = []
    cs = _charset_from_ct(content_type)
    if cs:
        # normalize a few common aliases
        alias = {"shift_jis": "cp932", "shift-jis": "cp932", "sjis": "cp932", "x-sjis": "cp932"}
        tried.append(alias.get(cs, cs))
    tried += ["utf-8", "cp932", "euc_jp"]
    for enc in tried:
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", "replace")


def _fix_b64_padding(s: str) -> str:
    s = s.strip()
    return s + "=" * ((4 - len(s) % 4) % 4)


def transform(op: str, data: str) -> str:
    op = (op or "").lower()

    # ---- Base64 ----
    if op == "b64encode":
        return base64.b64encode(data.encode("utf-8")).decode("ascii")
    if op == "b64decode":
        raw = data.strip()
        try:
            # accept both standard and url-safe alphabets
            std = raw.replace("-", "+").replace("_", "/")
            return base64.b64decode(_fix_b64_padding(std), validate=False).decode("utf-8", "replace")
        except (binascii.Error, ValueError) as e:
            raise TransformError(f"invalid base64: {e}")

    # ---- URL ----
    if op == "urlencode":
        return urllib.parse.quote(data, safe="")
    if op == "urldecode":
        return urllib.parse.unquote_plus(data)

    # ---- HTML entities ----
    if op == "htmlencode":
        return html.escape(data, quote=True)
    if op == "htmldecode":
        return html.unescape(data)

    # ---- Hex ----
    if op == "hexencode":
        return data.encode("utf-8").hex()
    if op == "hexdecode":
        cleaned = "".join(data.split())  # tolerate whitespace/newlines
        try:
            return bytes.fromhex(cleaned).decode("utf-8", "replace")
        except ValueError as e:
            raise TransformError(f"invalid hex: {e}")

    # ---- Hashes (one-way) ----
    if op in ("md5", "sha1", "sha256", "sha512"):
        h = hashlib.new(op)
        h.update(data.encode("utf-8"))
        return h.hexdigest()

    raise TransformError(f"unknown operation: {op}")


OPS = [
    "b64encode", "b64decode", "urlencode", "urldecode",
    "htmlencode", "htmldecode", "hexencode", "hexdecode",
    "md5", "sha1", "sha256", "sha512",
]
