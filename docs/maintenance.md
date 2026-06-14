# CV Maintenance

This repository keeps a small, explicit CV layout:

- `cv/` contains public PDFs tracked by Git.
- `cv_private/` contains local private PDFs ignored by Git, plus encrypted `.pdf.enc` copies that may be tracked.
- `src/` contains four TeX sources: public/private and English/Russian.
- `agent-memory/` contains local ignored agent memory/privacy markers, plus encrypted `.enc` copies that may be tracked.

## New Machine Setup

Install `uv` and a TeX distribution with `xelatex` available. On Windows, MiKTeX works.

```powershell
uv sync
uv run resume-workflow restore-private --force
uv run resume-workflow build-all --force
uv run resume-workflow validate-privacy --include-untracked
```

`restore-private` asks for the resume encryption password unless `RESUME_PASSWORD` is set.

## Editing

Edit the TeX files directly:

- `src/CV_Andrey_Urakov_AI_Engineer_public_en.tex`
- `src/CV_Andrey_Urakov_AI_Engineer_public_ru.tex`
- `src/CV_Andrey_Urakov_AI_Engineer_private_en.tex`
- `src/CV_Andrey_Urakov_AI_Engineer_private_ru.tex`

Keep Russian and English content equivalent. The only intended public/private difference is private contact information.

After editing, run:

```powershell
uv run resume-workflow build-all --force
uv run resume-workflow validate-privacy --include-untracked
```

`build-all` compiles all four PDFs and refreshes encrypted private TeX/PDF/memory files.

## Password Handling

For interactive use, let the workflow prompt for the password.

For repeated commands in one trusted terminal session:

```powershell
$env:RESUME_PASSWORD = "<password from password manager>"
uv run resume-workflow build-all --force
uv run resume-workflow save-private --force
Remove-Item Env:\RESUME_PASSWORD
```

Use a long unique password. The encrypted files use PBKDF2-HMAC-SHA256 plus Fernet with per-file salts.

## Privacy Check

Before committing:

```powershell
uv run resume-workflow validate-privacy --include-untracked
git status --short --untracked-files=all
```

Expected private plaintext files should be ignored:

- `cv_private/*.pdf`
- `src/*private*.tex`
- `agent-memory/MEMORY.md`
- `agent-memory/privacy-patterns.txt`

Only public PDFs, public TeX files, encrypted private files, scripts, docs, and repository metadata should be tracked.
