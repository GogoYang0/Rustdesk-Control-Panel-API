#!/usr/bin/env python3
"""Patch a pinned RustDesk source tree with one panel build manifest.

Standard library only. Every source anchor must occur exactly once; a missing or
duplicated anchor is a hard failure (the template targets RustDesk v1.5.0).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import tempfile
from pathlib import Path

CONFIG_RS = Path("libs/hbb_common/src/config.rs")
COMMON_RS = Path("src/common.rs")
ICON = Path("res/icon.png")
FLUTTER_LOGO_GLOB = "flutter/assets/logo*.png"
ANDROID_ICON_GLOB = "flutter/android/app/src/main/res/mipmap-*/ic_launcher.png"
API_SERVER_FALLBACK = '"https://admin.rustdesk.com"'


class PatchError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PatchError(message)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def replace_once(path: Path, pattern: str, replacement: str, label: str) -> None:
    text = read_text(path)
    updated, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    if count != 1:
        fail(f"anchor {label} in {path} matched {count} times, expected exactly 1")
    write_text(path, updated)


def safe_value(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"manifest {label} is empty")
    if any(ch in value for ch in ('"', "\\", "\n", "\r", "\x00")):
        fail(f"manifest {label} contains a character that is unsafe in Rust source")
    return value


def validate_manifest(manifest: dict) -> dict:
    if manifest.get("schema_version") != 1:
        fail("manifest schema_version must be 1")
    build_id = manifest.get("build_id")
    if not isinstance(build_id, int) or build_id <= 0:
        fail("manifest build_id must be a positive integer")
    for key in ("app_name", "server", "server_key", "api_server", "upstream_version"):
        safe_value(manifest.get(key), key)
    if not re.fullmatch(r"[A-Za-z0-9+/]{16,128}={0,2}", manifest["server_key"]):
        fail("manifest server_key is not valid base64")
    if not re.fullmatch(r"\d+\.\d+\.\d+", manifest["upstream_version"]):
        fail("manifest upstream_version must be a semantic version")
    if not isinstance(manifest.get("platforms"), list) or not manifest["platforms"]:
        fail("manifest platforms must be a non-empty list")
    return manifest


def load_manifest(path: Path) -> dict:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read manifest {path}: {exc}")
    if not isinstance(manifest, dict):
        fail("manifest must be a JSON object")
    return validate_manifest(manifest)


def png_dimensions(data: bytes) -> tuple[int, int]:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        fail("logo is not a PNG")
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def validate_logo_metadata(manifest: dict, logo: Path | None) -> None:
    meta = manifest.get("logo")
    if meta is None:
        return
    if logo is None or not logo.is_file():
        fail("manifest declares a logo but the bundle has no logo.png")
    data = logo.read_bytes()
    width, height = png_dimensions(data)
    if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
        fail("logo sha256 does not match the manifest")
    if (width, height) != (meta.get("width"), meta.get("height")):
        fail("logo dimensions do not match the manifest")


def patch_config(source: Path, manifest: dict) -> None:
    config = source / CONFIG_RS
    if not config.is_file():
        fail(f"missing {config}")
    server = manifest["server"]
    app_name = manifest["app_name"]
    server_key = manifest["server_key"]
    replace_once(
        config,
        r'^(\s*pub\s+(?:const|static\s+ref)\s+RENDEZVOUS_SERVERS\s*:\s*&\[&str\]\s*=\s*&\[)[^\]]*(\]\s*;)',
        lambda m: f'{m.group(1)}["{server}"]{m.group(2)}',
        "RENDEZVOUS_SERVERS",
    )
    replace_once(
        config,
        r'^(\s*pub\s+(?:const|static\s+ref)\s+RS_PUB_KEY\s*:\s*&str\s*=\s*")[^"]*(")',
        lambda m: f'{m.group(1)}{server_key}{m.group(2)}',
        "RS_PUB_KEY",
    )
    replace_once(
        config,
        r'^(\s*pub\s+static\s+ref\s+APP_NAME\s*:\s*RwLock<String>\s*=\s*RwLock::new\(")[^"]*(".*)$',
        lambda m: f'{m.group(1)}{app_name}{m.group(2)}',
        "APP_NAME",
    )


def patch_api_server(source: Path, manifest: dict) -> None:
    common = source / COMMON_RS
    if not common.is_file():
        fail(f"missing {common}")
    text = read_text(common)
    count = text.count(API_SERVER_FALLBACK)
    if count != 1:
        fail(f"API server fallback anchor matched {count} times, expected exactly 1")
    updated = text.replace(
        API_SERVER_FALLBACK,
        '"' + manifest["api_server"] + '"',
        1,
    )
    write_text(common, updated)


def replace_logo(source: Path, logo: Path) -> None:
    if not logo.is_file():
        fail(f"logo file is missing: {logo}")
    data = logo.read_bytes()
    if not data:
        fail("logo file is empty")
    icon = source / ICON
    if not icon.parent.is_dir():
        fail(f"missing icon directory {icon.parent}")
    icon.write_bytes(data)

    flutter = sorted(source.glob(FLUTTER_LOGO_GLOB))
    if not flutter:
        fallback = source / "flutter/assets/logo.png"
        if fallback.parent.is_dir():
            fallback.write_bytes(data)
        else:
            print("warning: no Flutter logo asset found; skipped Flutter logo", file=sys.stderr)
    for target in flutter:
        target.write_bytes(data)

    android = sorted(source.glob(ANDROID_ICON_GLOB))
    if not android:
        print("warning: no Android mipmap icon found; skipped Android icon", file=sys.stderr)
    for target in android:
        target.write_bytes(data)


def prepare(source: Path, manifest_path: Path, logo: Path | None) -> None:
    manifest = load_manifest(manifest_path)
    if not source.is_dir():
        fail(f"source directory is missing: {source}")
    validate_logo_metadata(manifest, logo)
    patch_config(source, manifest)
    patch_api_server(source, manifest)
    if logo is not None:
        replace_logo(source, logo)
    else:
        print("warning: no logo supplied; upstream icons are kept", file=sys.stderr)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "libs/hbb_common/src").mkdir(parents=True)
        (root / "src").mkdir()
        (root / "res").mkdir()
        (root / "flutter/assets").mkdir(parents=True)
        (root / "flutter/android/app/src/main/res/mipmap-xxxhdpi").mkdir(parents=True)
        (root / CONFIG_RS).write_text(
            'pub static ref RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];\n'
            'pub const RS_PUB_KEY: &str = "OLDKEY";\n'
            'pub static ref APP_NAME: RwLock<String> = RwLock::new("RustDesk".to_owned());\n',
            encoding="utf-8",
        )
        (root / COMMON_RS).write_text(
            'fn get_api_server_() -> String { "https://admin.rustdesk.com".to_owned() }\n',
            encoding="utf-8",
        )
        (root / "res/icon.png").write_bytes(b"old-icon")
        (root / "flutter/assets/logo.png").write_bytes(b"old-logo")
        (root / "flutter/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png").write_bytes(b"old-android")
        logo_bytes = (
            b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" +
            struct.pack(">II", 256, 256) + b"\x08\x06\x00\x00\x00"
        )
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps({
            "schema_version": 1,
            "build_id": 7,
            "app_name": "Acme Ops",
            "server": "relay.example.com:21117",
            "server_key": "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo=",
            "api_server": "https://panel.example.com",
            "upstream_version": "1.5.0",
            "platforms": ["linux-x64"],
            "logo": {
                "sha256": hashlib.sha256(logo_bytes).hexdigest(),
                "width": 256,
                "height": 256,
            },
        }), encoding="utf-8")
        logo = root / "logo.png"
        logo.write_bytes(logo_bytes)
        prepare(root, manifest_path, logo)
        config = (root / CONFIG_RS).read_text(encoding="utf-8")
        assert '["relay.example.com:21117"]' in config
        assert 'RS_PUB_KEY: &str = "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo="' in config
        assert 'RwLock::new("Acme Ops".to_owned())' in config
        assert '"https://panel.example.com"' in (root / COMMON_RS).read_text(encoding="utf-8")
        assert (root / "res/icon.png").read_bytes() == logo_bytes
        assert (root / "flutter/assets/logo.png").read_bytes() == logo_bytes
        assert (root / "flutter/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png").read_bytes() == logo_bytes

        tampered = load_manifest(manifest_path)
        tampered["logo"]["sha256"] = "00"
        try:
            validate_logo_metadata(tampered, logo)
        except PatchError:
            pass
        else:
            fail("self-test: tampered logo sha256 was not rejected")

        # A missing or duplicated anchor must fail, not silently patch.
        (root / CONFIG_RS).write_text('pub static ref APP_NAME: RwLock<String> = RwLock::new("RustDesk");\n', encoding="utf-8")
        try:
            patch_config(root, load_manifest(manifest_path))
        except PatchError:
            pass
        else:
            fail("self-test: missing RENDEZVOUS_SERVERS anchor was not rejected")

        (root / CONFIG_RS).write_text(
            'pub static ref RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];\n'
            'pub static ref RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];\n'
            'pub const RS_PUB_KEY: &str = "OLDKEY";\n'
            'pub static ref APP_NAME: RwLock<String> = RwLock::new("RustDesk");\n',
            encoding="utf-8",
        )
        try:
            patch_config(root, load_manifest(manifest_path))
        except PatchError:
            pass
        else:
            fail("self-test: duplicated RENDEZVOUS_SERVERS anchor was not rejected")
    print("prepare_source.py self-test: PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="RustDesk source root")
    parser.add_argument("--manifest", type=Path, help="manifest.json from the panel bundle")
    parser.add_argument("--logo", type=Path, default=None, help="optional logo.png from the bundle")
    parser.add_argument("--self-test", action="store_true", help="run the built-in fixture test")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        if args.source is None or args.manifest is None:
            parser.error("--source and --manifest are required")
        prepare(args.source, args.manifest, args.logo)
    except PatchError as exc:
        print(f"prepare_source.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
