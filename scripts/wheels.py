"""Package each release binary as a binary-only wheel, so `uv tool install` and pip can install the CLI."""

import base64
import hashlib
import os
import sys
import zipfile

PLATFORMS = {
    "kveritas-linux-amd64": "manylinux_2_17_x86_64.manylinux2014_x86_64.musllinux_1_1_x86_64",
    "kveritas-linux-arm64": "manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64",
    "kveritas-darwin-amd64": "macosx_10_12_x86_64",
    "kveritas-darwin-arm64": "macosx_11_0_arm64",
    "kveritas-windows-amd64.exe": "win_amd64",
}


def record_line(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def build(version: str, dist: str) -> None:
    for binary, tag in PLATFORMS.items():
        exe = "kveritas.exe" if binary.endswith(".exe") else "kveritas"
        info = f"kveritas-{version}.dist-info"
        files = {
            f"kveritas-{version}.data/scripts/{exe}": open(os.path.join(dist, binary), "rb").read(),
            f"{info}/METADATA": (
                "Metadata-Version: 2.1\nName: kveritas\n"
                f"Version: {version}\n"
                "Summary: K-Veritas CLI: cryptographic verification for computational experiments\n"
                "Home-page: https://kveritas.org\nLicense: AGPL-3.0-only\n"
            ).encode(),
            f"{info}/WHEEL": f"Wheel-Version: 1.0\nGenerator: kveritas\nRoot-Is-Purelib: false\nTag: py3-none-{tag}\n".encode(),
        }
        record = [record_line(n, d) for n, d in files.items()] + [f"{info}/RECORD,,"]
        files[f"{info}/RECORD"] = ("\n".join(record) + "\n").encode()
        out = os.path.join(dist, f"kveritas-{version}-py3-none-{tag}.whl")
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                zi.external_attr = (0o755 if "/scripts/" in name else 0o644) << 16
                z.writestr(zi, data, zipfile.ZIP_DEFLATED)
        print(out)


if __name__ == "__main__":
    build(sys.argv[1].lstrip("v").split("-")[0], sys.argv[2])
