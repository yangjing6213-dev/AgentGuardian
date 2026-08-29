# AgentGuardian Bilingual README Refresh Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Replace the default repository description with a Chinese-first, English-parallel README that explains the current AgentGuardian product, links the public unsigned Windows installer, and uses the three owner-supplied images without introducing unsupported claims.

**Architecture:** Keep README.md as the Chinese default and add README.en.md as a parallel English page. Store the two header images and author avatar under assets/brand/ with stable ASCII names, and use relative links from both README files. Keep application code, release assets, workflows, and the published Release unchanged.

**Tech Stack:** GitHub-flavored Markdown, PNG assets, PowerShell, Python project tooling, Git, GitHub CLI.

---

## Scope and fixed facts

- Base is remote main at 3f9436b411e4d794b9d0af4dfba79674a4b744ba.
- Work is isolated in branch codex/readme-bilingual-refresh at C:\Users\HU\Documents\AI智能体数据安全审计\.worktrees\readme-bilingual-refresh.
- The existing design record is already committed as 31634be7ab668ffde689705de1a099be7c8b70e0.
- Public installer URL is https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe.
- The release described by the README is an unsigned Windows 11 x64 Public Preview for personal, non-regulated configuration data only.
- Current capabilities to describe are one local audit core, desktop GUI, standalone Codex Skill, local STDIO MCP, and bounded files, browser, clipboard, and public-share checks.
- OpenAI Provider wording is local adaptation, detection, and manual guidance; it does not call a Provider API by default.
- Do not claim production safety, high-sensitivity real-data support, enterprise controls, signed authenticity, automatic remediation, telemetry, or a general security guarantee.
- Section 5 is intentionally empty. Section 11 says 无 in Chinese and None in English.
- The implementation manifest after the design commit contains exactly README.md, README.en.md, assets/brand/agentguardian-readme-zh.png, assets/brand/agentguardian-readme-en.png, and assets/brand/author-avatar.png.
- No application source, workflow, release asset, Tag, Release, main branch, or repository setting is in scope.

### Task 1: Add the owner-supplied README assets

**Files:**
- Create: assets/brand/agentguardian-readme-zh.png
- Create: assets/brand/agentguardian-readme-en.png
- Create: assets/brand/author-avatar.png

- [ ] Step 1: Copy each supplied image to its stable destination

From the readme-bilingual-refresh worktree root, run:

~~~powershell
Copy-Item -LiteralPath 'C:\Users\HU\Desktop\ChatGPT Image 2026年8月29日 14_26_22 (2).png' -Destination 'assets\brand\agentguardian-readme-zh.png'
Copy-Item -LiteralPath 'C:\Users\HU\Desktop\ChatGPT Image 2026年8月29日 14_22_13 (2).png' -Destination 'assets\brand\agentguardian-readme-en.png'
Copy-Item -LiteralPath 'C:\Users\HU\Desktop\项目视觉素材生成项目\ChatGPT Image 2026年8月29日 14_53_05.png' -Destination 'assets\brand\author-avatar.png'
Test-Path -LiteralPath 'assets\brand\agentguardian-readme-zh.png'
Test-Path -LiteralPath 'assets\brand\agentguardian-readme-en.png'
Test-Path -LiteralPath 'assets\brand\author-avatar.png'
~~~

Expected result: all three tests print True and each destination has non-zero length. Do not alter the source downloads.

- [ ] Step 2: Verify PNG readability and dimensions

Run:

~~~powershell
python -c "from PIL import Image; from pathlib import Path; names=['assets/brand/agentguardian-readme-zh.png','assets/brand/agentguardian-readme-en.png','assets/brand/author-avatar.png']; [print(p, Image.open(p).format, Image.open(p).size) for p in map(Path,names)]"
~~~

Expected result: all three files open as PNG and report positive width and height.

### Task 2: Write the Chinese default README

**Files:**
- Modify: README.md

- [ ] Step 1: Replace the existing page with the approved Chinese-first structure

The first two visible elements must be:

~~~markdown
![智能体守护宣传图](assets/brand/agentguardian-readme-zh.png)

[English version](README.en.md)
~~~

Use these thirteen visible headings in this exact order:

~~~text
一、这个仓库是什么？
二、适合谁用？
三、它会产出什么？
四、具有什么价值？
五、使用效果
六、安装方法
七、如何使用
八、项目工作流程
九、项目目录结构
十、注意事项
十一、相关项目
十二、关于作者
十三、继续探索
~~~

Section 二 must include the subsections 1、特别适合 and 2、不适合. Section 五 must have no visible text between its heading and Section 六. Section 十一 must explicitly say 无.

- [ ] Step 2: Bind the Chinese page to verified product facts

Include, in the relevant sections:

- The local-first audit core and its three entry points: desktop GUI, standalone Codex Skill, and local STDIO MCP.
- The four bounded audit areas: local files, browser data, clipboard content when explicitly requested, and public-share exposure checks.
- Read-only behavior, redacted human-readable reports, and a user confirmation boundary before an audit.
- The unsigned Windows 11 x64 Public Preview status, personal non-regulated configuration-data scope, and prohibition on high-sensitivity real data.
- The Unknown Publisher or SmartScreen warning possibility and SHA-256 verification link.
- The fixed installer link first in Section 六, followed by the Release page, portable ZIP, Skill ZIP, and SHA256SUMS links.
- OpenAI Provider local adaptation, detection, and manual guidance only, with no default API call.
- The absence of automatic remediation, enterprise console, signed authenticity, production-safety guarantee, and compliance guarantee.
- The actual high-level paths src/agentguardian, skills/agentguardian, packaging/windows, release_profiles, scripts, tests, docs, and assets/brand in Section 九.
- The supplied author image at assets/brand/author-avatar.png in Section 十二 and the exact approved author identity and links.
- Section 十三 wording that this is a tool in the author's AI-built personal generation system and a link to https://www.enhe-tech.com.cn/.

### Task 3: Write the English parallel README

**Files:**
- Create: README.en.md

- [ ] Step 1: Add the English header and language switch

The first two visible elements must be:

~~~markdown
![AgentGuardian Codex Skill](assets/brand/agentguardian-readme-en.png)

[中文版](README.md)
~~~

Use these thirteen headings in the same order:

~~~text
1. What is this repository?
2. Who is it for?
3. What does it produce?
4. What value does it provide?
5. Usage Results
6. Installation
7. How to Use
8. Project Workflow
9. Project Directory Structure
10. Important Notes
11. Related Projects
12. About the Author
13. Continue Exploring
~~~

Keep Section 5 visibly empty and Section 11 explicitly set to None.

- [ ] Step 2: Mirror the Chinese facts without expanding product claims

Mirror the three entry points, four bounded audit areas, read-only and confirmation behavior, redacted reports, Windows 11 x64 unsigned preview status, personal non-regulated scope, high-sensitivity prohibition, warning and checksum guidance, fixed download URLs, Provider behavior, limitations, directory paths, author avatar, and author links. Use natural English and keep the asset filenames and download filenames identical to the Chinese page.

### Task 4: Validate documentation and asset boundaries

**Files:**
- Test: README.md
- Test: README.en.md
- Test: the three new PNG files

- [ ] Step 1: Check whitespace, required references, and the existing brand validator

Run:

~~~powershell
git diff --check
Select-String -LiteralPath README.md -Pattern 'assets/brand/agentguardian-readme-zh.png','README.en.md','releases/latest/download/AgentGuardian-Setup-Windows-x64.exe','五、使用效果','六、安装方法','十二、关于作者','十三、继续探索'
Select-String -LiteralPath README.en.md -Pattern 'assets/brand/agentguardian-readme-en.png','README.md','releases/latest/download/AgentGuardian-Setup-Windows-x64.exe','5. Usage Results','6. Installation','12. About the Author','13. Continue Exploring'
python scripts/check_brand_assets.py
~~~

Expected result: diff check succeeds, every selector finds a match, and the existing asset checker exits 0.

- [ ] Step 2: Assert empty results sections and required boundary wording

Run a one-off Python assertion from the worktree root. It must locate the Section 5 and Section 6 headings in each README, strip Markdown whitespace and HTML comments from the intervening text, and assert that the result is empty. It must also assert that both pages contain the unsigned-preview, personal-scope, high-sensitivity prohibition, and production-safety limitation wording. A failed assertion stops the task; no assertion may be weakened.

- [ ] Step 3: Inspect the exact diff and scan only changed documentation assets

Run:

~~~powershell
git status --short
git diff --stat
git diff -- README.md README.en.md
git diff --check
gitleaks dir --redact --no-banner --exit-code 1 README.md README.en.md assets/brand
~~~

Expected result: only the planned five implementation paths plus the already committed design record appear; no credential, token, private data, temporary report, cache, or unrelated source change is present.

### Task 5: Commit the local implementation

**Files:**
- Stage only: README.md
- Stage only: README.en.md
- Stage only: assets/brand/agentguardian-readme-zh.png
- Stage only: assets/brand/agentguardian-readme-en.png
- Stage only: assets/brand/author-avatar.png

- [ ] Step 1: Stage the explicit manifest and inspect the index

Run:

~~~powershell
git add -- README.md README.en.md assets/brand/agentguardian-readme-zh.png assets/brand/agentguardian-readme-en.png assets/brand/author-avatar.png
git diff --cached --check
git diff --cached --name-only
~~~

Expected staged names are exactly the five paths above. Do not stage by repository-wide wildcard.

- [ ] Step 2: Create one local documentation commit

Run:

~~~powershell
git commit -m "docs: refresh bilingual repository README"
~~~

Expected result: one new commit on codex/readme-bilingual-refresh; no remote ref, main branch, Tag, Release, PR, or repository setting changes.

### Task 6: Prepare a gated GitHub update

- [ ] Step 1: Recheck the local state and remote facts after the commit

Run:

~~~powershell
git status --short --branch
git rev-parse HEAD
git ls-remote origin refs/heads/main refs/heads/codex/readme-bilingual-refresh
gh api user --jq .login
~~~

Expected result: clean worktree, account yangjing6213-dev, main still at the previously verified remote SHA, and the local branch contains the new commit.

- [ ] Step 2: Produce a precise authorization request and stop before remote writes

Report the full local HEAD, current remote main SHA, whether the source branch exists, and the proposed Draft PR direction codex/readme-bilingual-refresh -> main. Request a fresh BRANCH_AND_PR_UPDATE authorization naming those exact values. Do not reuse the earlier public-preview Release authorization and do not write main directly.

---

## Plan self-review

- Spec coverage: the bilingual structure, image placement, author profile, empty usage-results section, download links, product boundaries, local validation, explicit staging, local commit, and gated GitHub handoff each have a dedicated task.
- Scope coverage: only five documentation/asset paths are implementation paths; the design record is already committed and all application/release files remain out of scope.
- Consistency check: README.md is the Chinese default, README.en.md is its English parallel, and both reference the same stable asset and release filenames.
- Completion evidence: implementation is complete only after the local commit and all applicable checks report success. A remote update remains a separate authorization gate.
