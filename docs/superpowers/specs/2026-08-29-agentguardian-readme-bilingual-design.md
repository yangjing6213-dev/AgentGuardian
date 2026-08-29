# AgentGuardian Bilingual README and Brand Asset Design

## Status

Approved by the project owner for local implementation and later GitHub
branch publication. This document covers repository description updates only.
It does not change application behavior, release assets, the default branch,
or the published Public Preview.

## Goal

Make the GitHub repository understandable to a Chinese-first audience while
providing a complete English counterpart. A visitor should be able to learn
what AgentGuardian is, whether it fits their use case, what it produces, how
to install it, and where its boundaries are without reading implementation
files first.

## Information architecture

`README.md` is the default Chinese page. `README.en.md` is the English page.
Both pages use the same thirteen-section order:

1. What the repository is
2. Who it is for
3. What it produces
4. Its value
5. Usage results
6. Installation
7. How to use it
8. Project workflow
9. Project directory structure
10. Important notes
11. Related projects
12. About the author
13. Continue exploring

The Chinese page is the default language. Each page contains a small language
switch near the top. Section 5 remains intentionally empty and contains no
invented metrics, testimonials, screenshots-as-results, or performance claim.
Section 11 says `无` in Chinese and `None` in English when no related project
is established.

## Visual assets

Copy the three owner-supplied PNG files into `assets/brand/` with stable ASCII
names:

- `agentguardian-readme-zh.png`: first visible image in `README.md`
- `agentguardian-readme-en.png`: first visible image in `README.en.md`
- `author-avatar.png`: image in section 12 of both pages

The source files remain outside Git. The repository receives only the copied
assets. README image references use relative paths and descriptive alt text.
The author avatar is displayed at a constrained width; the two header images
remain responsive to the GitHub content column.

## Product and safety claims

Copy must reflect the current verified product boundary: local audit core,
desktop GUI, standalone Codex Skill, local STDIO MCP entry point, and the four
bounded audit operations `files`, `browser`, `clipboard`, and `public_share`.
OpenAI Provider behavior is described as local adaptation, detection, and
manual guidance; the runtime does not call a Provider API by default.

The pages must state that the current installer is an unsigned Windows 11 x64
Public Preview for personal, non-regulated configuration data. They must not
claim production safety, high-sensitivity real-data support, enterprise
controls, signed authenticity, automatic remediation, telemetry, or a general
security guarantee. Promotional image text is visual context, not evidence.

## Installation section

Section 6 uses the stable public asset URL:

`https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe`

It also links to the Release page and optional portable/Skill assets when
useful. The section explains SHA-256 verification and the expected unsigned
Windows warning without making installation depend on Python.

## Author section

Section 12 includes the supplied author avatar and the owner-approved profile:

- Enhe (恩禾), product designer, one-person-company practitioner, AI Builder
- GitHub: `yangjing6213-dev`
- X/Twitter: `Amenenhe_ai`
- Website: `https://www.enhe-tech.com.cn/`
- WeChat: `Hu-Amen`
- Email: `amen.enhe@gmail.com`

## Validation and delivery

Only the README files, the three named PNG assets, and this design record are
in scope. Before publication, validate image readability, relative links,
download links, section order, UTF-8 text, `git diff --check`, sensitive-content
scan, and the exact staged manifest. Use a new `codex/readme-bilingual-refresh`
branch based on the verified remote `main`; publish through a normal branch
Push and Draft PR, never direct Push to `main` or Force Push.

The GitHub publication is a separate authorization-gated action. Local
preparation does not imply that the branch has been pushed or merged.

## Acceptance criteria

- Chinese README is the default repository description.
- English README is independently readable and structurally parallel.
- The requested three images appear in the requested locations.
- The installer link appears in section 6 and resolves to the named Release
  asset.
- Section 5 is visibly empty.
- No unsupported capability or production-safety claim is introduced.
- No unrelated source, release, workflow, or configuration file changes occur.
