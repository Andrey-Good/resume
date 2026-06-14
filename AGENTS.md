# Agent Instructions

This repository is Andrey Urakov's public resume repository. Treat it as a public-facing professional artifact.

## Public Surface

- Keep `README.md` minimal and visitor-facing.
- Do not put maintenance runbooks, private workflow details, raw agent notes, or private contact details in `README.md`.
- Public PDFs are:
  - `cv/CV_Andrey_Urakov_AI_Engineer_en.pdf`
  - `cv/CV_Andrey_Urakov_AI_Engineer_ru.pdf`
- Private artifacts may be tracked only when encrypted.

## Repository Shape

- `cv/`: tracked public PDFs.
- `cv_private/`: ignored private PDFs and tracked encrypted private PDFs.
- `src/`: four TeX sources.
  - Public TeX sources are tracked.
  - Private TeX sources are local ignored files.
  - Private TeX `.enc` files are tracked.
- `agent-memory/`: local ignored memory and privacy markers, plus tracked encrypted copies.
- `scripts/`: workflow tooling.
- `docs/maintenance.md`: maintainer workflow.

## Resume Workflow

- The TeX files in `src/` are the source of truth.
- Russian and English resumes must stay content-equivalent except for private-only contact fields.
- Every completed resume change cycle must rebuild all four variants: public RU, public EN, private RU, private EN.
- Use a real TeX engine, preferably MiKTeX/XeLaTeX on Windows.
- Do not silently publish fallback PDFs when TeX compilation fails.
- Encrypted artifacts are password-based. The password is never stored in Git; use interactive prompts or `RESUME_PASSWORD` on trusted machines.
- Use English for agent-facing instructions and memory.

## Commands

```powershell
uv sync
uv run resume-workflow restore-private --force
uv run resume-workflow build-all --force
uv run resume-workflow validate-privacy --include-untracked
```

When private TeX files, private PDFs, memory, or privacy markers change:

```powershell
uv run resume-workflow save-private --force
```

## Privacy Rules

- Never commit plaintext private contact details.
- Never track `cv_private/*.pdf`.
- Never track `src/*private*.tex`.
- Never track plaintext files under `agent-memory/`.
- Public PDFs must pass text-extraction privacy validation.
- If Google Drive write tooling is unavailable, say so clearly instead of claiming an upload happened.

## Task Handling

If the user explicitly authorizes subagents, use the orchestration cycle for large work:

1. Create a plan under ignored `.agents/global-plans/`.
2. Create task documents under ignored `.agents/subagent_tasks/`.
3. Delegate independent work to subagents with non-overlapping write scopes.
4. Review substantial work with fresh reviewers.
5. Run a final end-to-end review before considering the task complete.
