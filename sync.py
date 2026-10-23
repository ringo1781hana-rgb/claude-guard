#!/usr/bin/env python3
"""claude-guard を対象リポジトリに取り込む（何度実行しても同じ結果になる）。

  python3 sync.py --guard <claude-guard の場所> --target <対象リポジトリの場所>

やること
  1. template/.claude/guard/ を対象の .claude/guard/ に丸ごと置き換え（logs/ は残す）
  2. .claude/guard/VERSION を書く
  3. .claude/settings.json に、ガードのフックと deny ルールを足す（既存の設定は残す）
  4. CLAUDE.md に安全ルールの読み込み行を足す
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

GUARD_MARK = ".claude/guard/guard.py"
CLAUDE_MD_LINE = "@.claude/guard/RULES.md"
CLAUDE_MD_BLOCK = (
    "\n## 安全ルール（claude-guard が自動で追加。消さないでください）\n\n"
    f"{CLAUDE_MD_LINE}\n"
)


def copy_guard_dir(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for child in dst.iterdir():
        if child.name == "logs":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    for child in src.iterdir():
        if child.name == "logs" or child.name == "__pycache__":
            continue
        if child.is_dir():
            shutil.copytree(child, dst / child.name)
        else:
            shutil.copy2(child, dst / child.name)


def merge_settings(path: Path, fragment: dict) -> None:
    settings = {}
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        settings = json.loads(text) if text else {}

    perms = settings.setdefault("permissions", {})
    deny = perms.setdefault("deny", [])
    for rule in fragment["permissions"]["deny"]:
        if rule not in deny:
            deny.append(rule)

    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    pre[:] = [
        entry for entry in pre
        if not any(GUARD_MARK in str(h.get("command", "")) for h in entry.get("hooks", []))
    ]
    # ガードは一番先に動かす
    for entry in reversed(fragment["hooks"]["PreToolUse"]):
        pre.insert(0, entry)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def ensure_claude_md(path: Path) -> None:
    if path.exists():
        text = path.read_text(encoding="utf-8")
        if CLAUDE_MD_LINE in text:
            return
        if not text.endswith("\n"):
            text += "\n"
        path.write_text(text + CLAUDE_MD_BLOCK, encoding="utf-8")
    else:
        path.write_text("# CLAUDE.md\n" + CLAUDE_MD_BLOCK, encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--guard", required=True, type=Path)
    ap.add_argument("--target", required=True, type=Path)
    a = ap.parse_args()

    guard, target = a.guard.resolve(), a.target.resolve()
    version = (guard / "VERSION").read_text(encoding="utf-8").strip()

    copy_guard_dir(guard / "template/.claude/guard", target / ".claude/guard")
    (target / ".claude/guard/VERSION").write_text(version + "\n", encoding="utf-8")

    fragment = json.loads((guard / "template/settings.guard.json").read_text(encoding="utf-8"))
    merge_settings(target / ".claude/settings.json", fragment)

    ensure_claude_md(target / "CLAUDE.md")
    print(f"claude-guard v{version} を {target} に反映しました")


if __name__ == "__main__":
    main()
