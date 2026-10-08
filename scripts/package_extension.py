"""Deterministically zip /extension into app/static/downloads/, with SHA-256 and version.json.
Set SPACE_HOST (e.g. myname-scamlens.hf.space) to bake the real backend into the package."""
import hashlib, json, os, pathlib, zipfile, datetime

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXT = ROOT / "extension"
OUT = ROOT / "app" / "static" / "downloads"
EXCLUDE_SUFFIX = {".map", ".pem", ".key", ".env"}
host = os.getenv("SPACE_HOST", "").strip()

manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
version = manifest["version"]
OUT.mkdir(parents=True, exist_ok=True)
name = f"scamlens-extension-v{version}.zip"
for old in OUT.glob("scamlens-extension-v*.zip"):
    old.unlink()

def content(path: pathlib.Path) -> bytes:
    data = path.read_bytes()
    if host and path.name in ("manifest.json", "config.js"):
        t = data.decode("utf-8").replace("__SPACE_HOST__", host)
        if path.name == "manifest.json":
            m = json.loads(t); m["host_permissions"] = [f"https://{host}/*"]; t = json.dumps(m, indent=2)
        data = t.encode("utf-8")
    return data

files = sorted(p for p in EXT.rglob("*") if p.is_file() and p.suffix not in EXCLUDE_SUFFIX and not p.name.startswith("."))
with zipfile.ZipFile(OUT / name, "w", zipfile.ZIP_DEFLATED) as z:
    for p in files:
        zi = zipfile.ZipInfo(str(p.relative_to(EXT)), date_time=(2026, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED; zi.external_attr = 0o644 << 16
        z.writestr(zi, content(p))
sha = hashlib.sha256((OUT / name).read_bytes()).hexdigest()
(OUT / (name + ".sha256")).write_text(f"{sha}  {name}\n")
(OUT / "version.json").write_text(json.dumps({"version": version, "file": name, "sha256": sha, "size": (OUT / name).stat().st_size,
                                              "built": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")}))
print(name, sha)
