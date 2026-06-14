from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pypdf import PdfReader


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
CV_DIR = ROOT / "cv"
CV_PRIVATE_DIR = ROOT / "cv_private"
AGENT_MEMORY_DIR = ROOT / "agent-memory"
BUILD_DIR = ROOT / "build" / "latex"
DEFAULT_PASSWORD_ENV = "RESUME_PASSWORD"
PASSWORD_ENC_FORMAT = "resume-password-fernet-v1"
DEFAULT_KDF_ITERATIONS = 1_200_000
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s().-]*){10,16}(?!\d)")
TEXT_SKIP_SUFFIXES = {
    ".7z",
    ".bin",
    ".bmp",
    ".enc",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".webp",
    ".zip",
}
TEXT_SKIP_NAMES = {"uv.lock"}
PASSWORD_CACHE: dict[tuple[str, bool], str] = {}


@dataclass(frozen=True)
class Variant:
    visibility: str
    lang: str
    tex_path: Path
    pdf_path: Path


VARIANTS = (
    Variant(
        "public",
        "en",
        SRC_DIR / "CV_Andrey_Urakov_AI_Engineer_public_en.tex",
        CV_DIR / "CV_Andrey_Urakov_AI_Engineer_en.pdf",
    ),
    Variant(
        "public",
        "ru",
        SRC_DIR / "CV_Andrey_Urakov_AI_Engineer_public_ru.tex",
        CV_DIR / "CV_Andrey_Urakov_AI_Engineer_ru.pdf",
    ),
    Variant(
        "private",
        "en",
        SRC_DIR / "CV_Andrey_Urakov_AI_Engineer_private_en.tex",
        CV_PRIVATE_DIR / "CV_Andrey_Urakov_AI_Engineer_private_en.pdf",
    ),
    Variant(
        "private",
        "ru",
        SRC_DIR / "CV_Andrey_Urakov_AI_Engineer_private_ru.tex",
        CV_PRIVATE_DIR / "CV_Andrey_Urakov_AI_Engineer_private_ru.pdf",
    ),
)


PRIVATE_FILE_PAIRS = (
    (
        SRC_DIR / "CV_Andrey_Urakov_AI_Engineer_private_en.tex",
        SRC_DIR / "CV_Andrey_Urakov_AI_Engineer_private_en.tex.enc",
    ),
    (
        SRC_DIR / "CV_Andrey_Urakov_AI_Engineer_private_ru.tex",
        SRC_DIR / "CV_Andrey_Urakov_AI_Engineer_private_ru.tex.enc",
    ),
    (
        CV_PRIVATE_DIR / "CV_Andrey_Urakov_AI_Engineer_private_en.pdf",
        CV_PRIVATE_DIR / "CV_Andrey_Urakov_AI_Engineer_private_en.pdf.enc",
    ),
    (
        CV_PRIVATE_DIR / "CV_Andrey_Urakov_AI_Engineer_private_ru.pdf",
        CV_PRIVATE_DIR / "CV_Andrey_Urakov_AI_Engineer_private_ru.pdf.enc",
    ),
    (AGENT_MEMORY_DIR / "MEMORY.md", AGENT_MEMORY_DIR / "MEMORY.md.enc"),
    (
        AGENT_MEMORY_DIR / "privacy-patterns.txt",
        AGENT_MEMORY_DIR / "privacy-patterns.txt.enc",
    ),
)


REQUIRED_GITIGNORE_PATTERNS = (
    "cv_private/*.pdf",
    "src/*private*.tex",
    "agent-memory/MEMORY.md",
    "agent-memory/privacy-patterns.txt",
)


class WorkflowError(RuntimeError):
    """User-facing workflow error."""


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def password_from_env_or_prompt(password_env: str, confirm: bool) -> str:
    env_password = os.environ.get(password_env)
    if env_password:
        return env_password
    cache_key = (password_env, confirm)
    if cache_key in PASSWORD_CACHE:
        return PASSWORD_CACHE[cache_key]
    password = getpass.getpass("Resume encryption password: ")
    if not password:
        raise WorkflowError("Password cannot be empty.")
    if confirm:
        repeated = getpass.getpass("Repeat resume encryption password: ")
        if password != repeated:
            raise WorkflowError("Passwords do not match.")
    PASSWORD_CACHE[cache_key] = password
    return password


def derive_password_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(
    source: Path,
    target: Path,
    password_env: str,
    iterations: int,
    force: bool,
) -> Path:
    if not source.exists():
        raise WorkflowError(f"Private source file not found: {rel(source)}")
    if target.exists() and not force:
        raise WorkflowError(f"Refusing to overwrite existing encrypted file: {rel(target)}")
    password = password_from_env_or_prompt(password_env, confirm=True)
    salt = os.urandom(16)
    token = Fernet(derive_password_key(password, salt, iterations)).encrypt(source.read_bytes())
    payload = {
        "format": PASSWORD_ENC_FORMAT,
        "kdf": {
            "name": "pbkdf2-hmac-sha256",
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode("ascii"),
        },
        "cipher": "fernet",
        "token": token.decode("ascii"),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and force:
        target.unlink()
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def decrypt_file(source: Path, target: Path, password_env: str, force: bool) -> Path:
    if not source.exists():
        raise WorkflowError(f"Encrypted file not found: {rel(source)}")
    if target.exists() and not force:
        raise WorkflowError(f"Refusing to overwrite existing plaintext file: {rel(target)}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"Encrypted file is not a password JSON envelope: {rel(source)}") from exc
    if not isinstance(payload, dict) or payload.get("format") != PASSWORD_ENC_FORMAT:
        raise WorkflowError(f"Unsupported encrypted file format: {rel(source)}")
    kdf = payload.get("kdf") or {}
    if kdf.get("name") != "pbkdf2-hmac-sha256":
        raise WorkflowError(f"Unsupported KDF in encrypted file: {rel(source)}")
    try:
        iterations = int(kdf["iterations"])
        salt = base64.b64decode(kdf["salt"])
        token = str(payload["token"]).encode("ascii")
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkflowError(f"Malformed encrypted file: {rel(source)}") from exc
    password = password_from_env_or_prompt(password_env, confirm=False)
    try:
        plaintext = Fernet(derive_password_key(password, salt, iterations)).decrypt(token)
    except InvalidToken as exc:
        raise WorkflowError(f"Could not decrypt {rel(source)} with the provided password.") from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and force:
        target.unlink()
    target.write_bytes(plaintext)
    return target


def ensure_gitignore_patterns() -> None:
    gitignore = ROOT / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    missing = [pattern for pattern in REQUIRED_GITIGNORE_PATTERNS if pattern not in existing.splitlines()]
    if not missing:
        return
    with gitignore.open("a", encoding="utf-8", newline="\n") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write("\n# Local private CV files.\n")
        for pattern in missing:
            handle.write(f"{pattern}\n")


def find_engine(requested: str) -> str:
    extra_paths = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "MiKTeX" / "miktex" / "bin" / "x64",
        Path(os.environ.get("ProgramFiles", "")) / "MiKTeX" / "miktex" / "bin" / "x64",
    ]
    for path in extra_paths:
        if path.exists():
            os.environ["PATH"] = f"{path}{os.pathsep}{os.environ.get('PATH', '')}"
    if requested != "auto":
        if shutil.which(requested):
            return requested
        raise WorkflowError(f"LaTeX engine '{requested}' was not found in PATH.")
    for candidate in ("xelatex", "lualatex", "pdflatex", "tectonic", "latexmk"):
        if shutil.which(candidate):
            return candidate
    raise WorkflowError("No LaTeX engine was found in PATH.")


def run_checked(command: list[str], cwd: Path) -> None:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no compiler output"
        raise WorkflowError(f"Command failed: {' '.join(command)}\n{detail}")


def compile_variant(variant: Variant, engine_request: str) -> Path:
    if not variant.tex_path.exists():
        raise WorkflowError(f"TeX source not found: {rel(variant.tex_path)}")
    engine = find_engine(engine_request)
    work_dir = BUILD_DIR / f"{variant.visibility}_{variant.lang}"
    work_dir.mkdir(parents=True, exist_ok=True)
    source = variant.tex_path.resolve()
    if engine == "tectonic":
        run_checked(["tectonic", str(source), "--outdir", str(work_dir)], cwd=ROOT)
    elif engine == "latexmk":
        run_checked(
            [
                "latexmk",
                "-xelatex",
                "-interaction=nonstopmode",
                "-halt-on-error",
                f"-outdir={work_dir}",
                str(source),
            ],
            cwd=ROOT,
        )
    else:
        for _ in range(2):
            run_checked(
                [
                    engine,
                    "-interaction=nonstopmode",
                    "-halt-on-error",
                    "-output-directory",
                    str(work_dir),
                    str(source),
                ],
                cwd=ROOT,
            )
    compiled = work_dir / source.with_suffix(".pdf").name
    if not compiled.exists():
        raise WorkflowError(f"LaTeX finished but did not create {rel(compiled)}")
    variant.pdf_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(compiled, variant.pdf_path)
    return variant.pdf_path


def save_private(args: argparse.Namespace) -> None:
    ensure_gitignore_patterns()
    saved: list[Path] = []
    for source, target in PRIVATE_FILE_PAIRS:
        if source.exists():
            saved.append(encrypt_file(source, target, args.password_env, args.kdf_iterations, args.force))
    if not saved:
        raise WorkflowError("No local private files were found to encrypt.")
    for path in saved:
        print(f"Encrypted: {rel(path)}")


def restore_private(args: argparse.Namespace) -> None:
    ensure_gitignore_patterns()
    restored: list[Path] = []
    for target, source in PRIVATE_FILE_PAIRS:
        if source.exists():
            restored.append(decrypt_file(source, target, args.password_env, args.force))
    if not restored:
        raise WorkflowError("No encrypted private files were found to restore.")
    for path in restored:
        print(f"Restored: {rel(path)}")


def build_all(args: argparse.Namespace) -> None:
    ensure_gitignore_patterns()
    built: list[Path] = []
    for variant in VARIANTS:
        built.append(compile_variant(variant, args.engine))
    for path in built:
        print(f"Built: {rel(path)}")
    if args.encrypt_private:
        save_args = argparse.Namespace(
            password_env=args.password_env,
            kdf_iterations=args.kdf_iterations,
            force=args.force,
        )
        save_private(save_args)


def git_files(include_untracked: bool) -> list[Path]:
    commands = [["git", "ls-files", "-z"]]
    if include_untracked:
        commands.append(["git", "ls-files", "--others", "--exclude-standard", "-z"])
    paths: list[Path] = []
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, capture_output=True)
        if completed.returncode != 0:
            raise WorkflowError("Unable to list git files for privacy validation.")
        for raw in completed.stdout.split(b"\0"):
            if raw:
                paths.append(ROOT / raw.decode("utf-8", errors="replace"))
    return sorted(set(paths))


def load_patterns(path: Path) -> list[str]:
    if not path.exists():
        return []
    patterns: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped)
    return patterns


def likely_text(path: Path) -> bool:
    if path.name in TEXT_SKIP_NAMES or path.suffix.lower() in TEXT_SKIP_SUFFIXES:
        return False
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\0" not in sample


def validate_privacy(args: argparse.Namespace) -> None:
    ensure_gitignore_patterns()
    patterns = load_patterns(Path(args.patterns_file))
    violations: list[str] = []
    for path in git_files(args.include_untracked):
        if not path.exists():
            continue
        relative = rel(path)
        normalized = relative.replace("\\", "/")
        lower = normalized.lower()
        if lower.startswith(".private/"):
            violations.append(f"{relative}: obsolete .private/ file must not be tracked")
        if lower.startswith("cv_private/") and lower.endswith(".pdf"):
            violations.append(f"{relative}: private PDF must be encrypted or ignored")
        if lower.startswith("src/") and "private" in lower and lower.endswith(".tex"):
            violations.append(f"{relative}: private TeX source must be encrypted or ignored")
        if lower.startswith("agent-memory/") and not lower.endswith(".enc"):
            violations.append(f"{relative}: local agent memory must be encrypted or ignored")
        if lower.endswith(".pdf"):
            try:
                text = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
            except Exception as exc:
                violations.append(f"{relative}: could not extract PDF text ({exc})")
                continue
        elif not likely_text(path):
            continue
        else:
            text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in patterns:
            if pattern in text:
                violations.append(f"{relative}: contains a configured private marker")
        if PHONE_RE.search(text):
            violations.append(f"{relative}: contains a phone-number-shaped value")
    if violations:
        joined = "\n".join(f"- {violation}" for violation in violations)
        raise WorkflowError(f"Privacy validation failed:\n{joined}")
    if not patterns:
        print(f"No local privacy marker file found at {rel(Path(args.patterns_file))}; generic checks only.")
    print("Privacy validation passed.")


def add_crypto_parsers(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt one local file.")
    encrypt_parser.add_argument("source")
    encrypt_parser.add_argument("target")
    encrypt_parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)
    encrypt_parser.add_argument("--kdf-iterations", type=int, default=DEFAULT_KDF_ITERATIONS)
    encrypt_parser.add_argument("--force", action="store_true")
    encrypt_parser.set_defaults(
        func=lambda args: print(
            f"Encrypted: {rel(encrypt_file(Path(args.source), Path(args.target), args.password_env, args.kdf_iterations, args.force))}"
        )
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt one encrypted file.")
    decrypt_parser.add_argument("source")
    decrypt_parser.add_argument("target")
    decrypt_parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)
    decrypt_parser.add_argument("--force", action="store_true")
    decrypt_parser.set_defaults(
        func=lambda args: print(
            f"Restored: {rel(decrypt_file(Path(args.source), Path(args.target), args.password_env, args.force))}"
        )
    )

    save_parser = subparsers.add_parser("save-private", help="Encrypt all local private CV and memory files.")
    save_parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)
    save_parser.add_argument("--kdf-iterations", type=int, default=DEFAULT_KDF_ITERATIONS)
    save_parser.add_argument("--force", action="store_true")
    save_parser.set_defaults(func=save_private)

    restore_parser = subparsers.add_parser("restore-private", help="Decrypt all private CV and memory files.")
    restore_parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)
    restore_parser.add_argument("--force", action="store_true")
    restore_parser.set_defaults(func=restore_private)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Minimal CV repository workflow.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_all_parser = subparsers.add_parser("build-all", help="Compile all four TeX CV files to PDF.")
    build_all_parser.add_argument("--engine", default="auto")
    build_all_parser.add_argument("--encrypt-private", action=argparse.BooleanOptionalAction, default=True)
    build_all_parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV)
    build_all_parser.add_argument("--kdf-iterations", type=int, default=DEFAULT_KDF_ITERATIONS)
    build_all_parser.add_argument("--force", action="store_true")
    build_all_parser.set_defaults(func=build_all)

    validate_parser = subparsers.add_parser("validate-privacy", help="Scan git-visible files for private plaintext.")
    validate_parser.add_argument("--patterns-file", default=str(AGENT_MEMORY_DIR / "privacy-patterns.txt"))
    validate_parser.add_argument("--include-untracked", action="store_true")
    validate_parser.set_defaults(func=validate_privacy)

    add_crypto_parsers(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except WorkflowError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
