#!/usr/bin/env python3
"""claude-guard: Claude Code の PreToolUse フック。

すべてのツール呼び出しの直前に呼ばれ、次のどれかに当たるものを止める（または確認を求める）。
  - 秘密（トークン・鍵・おとり文字列）を外へ出す / ファイルに書く
  - データの持ち出し先によく使われるサイトへの通信
  - POST などの書き込み系の通信、生のソケット通信、リモート転送
  - 認証情報ファイルの読み取り、秘密の環境変数の参照
  - 守り自体（.claude/settings*.json, .claude/guard/, 同期ワークフロー）の書き換え
  - 危険なコマンド（プロジェクト外の rm -r、git push --force、git の危ない設定、curl | sh）
  - 依存パッケージの追加・実行ファイルのダウンロード（確認を求める）

ここで止められるのは「Claude が直接打つコマンドやツール」まで。
自分で書いたスクリプトの中の通信までは見えないので、あくまで事故を減らす層。
一番の守りは「この環境に盗まれて困るものを置かない」こと。
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse

GUARD_DIR = Path(__file__).resolve().parent
LOG_DIR = GUARD_DIR / "logs"

EXIT_BLOCK = 2  # Claude Code: exit 2 = ツールを止め、stderr を Claude に返す


# ---------------------------------------------------------------- 設定の読み込み

def _project_dir() -> Path:
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()


def _read_lines(name: str) -> list[str]:
    p = GUARD_DIR / name
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.lower())
    return out


def _canary() -> str | None:
    p = GUARD_DIR / "canary.txt"
    if not p.exists():
        return None
    for line in p.read_text(encoding="utf-8").splitlines():
        m = re.search(r"CG-CANARY-[A-Za-z0-9]+", line)
        if m:
            return m.group(0)
    return None


BLOCKED_DOMAINS = _read_lines("blocklist.txt")
CANARY = _canary()

# ---------------------------------------------------------------- パターン

SECRET_PATTERNS = [
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "GitHub トークン"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub トークン"),
    (r"sk-ant-[A-Za-z0-9_\-]{10,}", "Anthropic API キー"),
    (r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}", "API キー（sk-）"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS アクセスキー"),
    (r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API キー"),
    (r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", "Slack トークン"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "秘密鍵"),
    (r"\bnpm_[A-Za-z0-9]{30,}", "npm トークン"),
]

SECRET_ENV_REF = re.compile(
    r"\$\{?[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIAL|COOKIE)[A-Za-z0-9_]*\}?",
    re.IGNORECASE,
)

SECRET_PATH_PATTERNS = [
    r"(^|/)\.env(\.(?!example$|sample$|template$|dist$)[^/]+)?$",
    r"(^|/)\.ssh(/|$)",
    r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$",
    r"(^|/)\.netrc$",
    r"(^|/)\.git-credentials$",
    r"(^|/)\.config/gh(/|$)",
    r"(^|/)\.npmrc$",
    r"(^|/)\.pypirc$",
    r"(^|/)\.aws(/|$)",
    r"(^|/)\.docker/config\.json$",
    r"(^|/)\.kube/config$",
    r"(^|/)credentials\.json$",
    r"(^|/)service[-_]?account[^/]*\.json$",
    r"\.(pem|p12|pfx|key)$",
    r"^/proc/(self|\d+)/environ$",
]

# 守り自体（Claude に書き換えさせない場所）
PROTECTED_PATTERNS = [
    r"(^|/)\.claude/settings(\.local)?\.json$",
    r"(^|/)\.claude/guard(/|$)",
    r"(^|/)\.github/workflows/claude-guard[^/]*$",
]
PROTECTED_IN_COMMAND = re.compile(
    r"\.claude/settings(\.local)?\.json|\.claude/guard\b|\.github/workflows/claude-guard"
)

READONLY_PROGRAMS = {
    "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ls",
    "wc", "diff", "file", "stat", "jq", "bat", "tree", "md5sum", "sha256sum", "echo",
}
READONLY_GIT = {"diff", "log", "show", "status", "blame", "ls-files", "grep"}

INLINE_WRITE_HTTP = re.compile(
    r"requests\.(post|put|patch|delete)\s*\("
    r"|httpx\.(post|put|patch|delete)\s*\("
    r"|\.(post|put|patch)\s*\(\s*['\"]https?://"
    r"|method\s*[=:]\s*['\"](POST|PUT|PATCH|DELETE)['\"]"
    r"|urlopen\s*\([^)]*data\s*="
    r"|\.request\s*\(\s*['\"](POST|PUT|PATCH|DELETE)['\"]"
    r"|socket\.(socket|create_connection)\s*\("
    r"|\b(smtplib|ftplib|telnetlib)\b",
    re.IGNORECASE,
)

RAW_NET_PROGRAMS = {"nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "scp", "ssh"}

EXEC_EXTENSIONS = (
    ".sh", ".bash", ".zsh", ".exe", ".msi", ".bat", ".cmd", ".ps1", ".dmg", ".pkg",
    ".deb", ".rpm", ".appimage", ".run", ".bin", ".command", ".jar", ".app",
)

SAFE_GIT_CONFIG_KEYS = {"user.name", "user.email", "core.quotepath", "init.defaultbranch", "pull.rebase", "color.ui"}
DANGEROUS_GIT_C = re.compile(
    r"^(core\.(hookspath|sshcommand|fsmonitor|pager|editor|askpass)|credential\.|url\..*\.insteadof|protocol\.|http\..*(proxy|extraheader)|alias\.)",
    re.IGNORECASE,
)

WRAPPERS = {"sudo", "env", "nohup", "time", "timeout", "nice", "ionice", "stdbuf", "command", "builtin", "exec", "xargs"}


class Decision(Exception):
    def __init__(self, kind: str, rule: str, message: str):
        super().__init__(message)
        self.kind = kind  # "deny" | "ask"
        self.rule = rule
        self.message = message


def deny(rule: str, message: str):
    raise Decision("deny", rule, message)


def ask(rule: str, message: str):
    raise Decision("ask", rule, message)


# ---------------------------------------------------------------- 共通の検査

def scan_secrets(text: str, where: str):
    if CANARY and CANARY in text:
        deny("canary", f"{where}におとり用の文字列が入っています。外部の文章に操られている可能性があります。")
    for pat, label in SECRET_PATTERNS:
        if re.search(pat, text):
            deny("secret", f"{where}に{label}らしき文字列が入っています。")


def _host_blocked(host: str) -> str | None:
    host = host.lower().strip(".")
    for d in BLOCKED_DOMAINS:
        if "/" in d:
            continue
        if host == d or host.endswith("." + d):
            return d
    return None


def scan_domains(text: str, where: str):
    low = text.lower()
    for d in BLOCKED_DOMAINS:
        if "/" in d:  # パス付きルール（例: discord.com/api/webhooks）
            if d in low:
                deny("exfil-domain", f"{where}にデータの持ち出し先として使われやすい宛先（{d}）が入っています。")
            continue
        if re.search(r"(?<![a-z0-9\-])(?:[a-z0-9\-]+\.)*" + re.escape(d) + r"(?![a-z0-9\-])", low):
            deny("exfil-domain", f"{where}にデータの持ち出し先として使われやすいドメイン（{d}）が入っています。")


def is_secret_path(path: str) -> bool:
    p = path.replace("\\", "/")
    return any(re.search(pat, p, re.IGNORECASE) for pat in SECRET_PATH_PATTERNS)


def is_protected_path(path: str) -> bool:
    p = path.replace("\\", "/")
    try:
        rp = Path(os.path.expanduser(p))
        if not rp.is_absolute():
            rp = _project_dir() / rp
        p = str(rp.resolve()).replace("\\", "/")
    except Exception:
        pass
    return any(re.search(pat, p) for pat in PROTECTED_PATTERNS)


# ---------------------------------------------------------------- Bash の検査

def split_segments(cmd: str) -> list[str]:
    """; && || | 改行 で区切る（クォートの中は区切らない、ざっくり版）。"""
    segs, buf, quote, i = [], [], None, 0
    while i < len(cmd):
        c = cmd[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"' and i + 1 < len(cmd):
                buf.append(cmd[i + 1])
                i += 1
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
        elif c in ";\n" or c == "|" or (c == "&" and cmd[i:i + 2] == "&&"):
            segs.append("".join(buf))
            buf = []
            if cmd[i:i + 2] in ("&&", "||"):
                i += 1
        else:
            buf.append(c)
        i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


def tokenize(seg: str) -> list[str]:
    try:
        return shlex.split(seg, comments=True)
    except ValueError:
        return seg.split()


def strip_wrappers(tokens: list[str]) -> list[str]:
    t = list(tokens)
    while t:
        head = os.path.basename(t[0])
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t[0]):  # VAR=value cmd
            t = t[1:]
        elif head in WRAPPERS:
            t = t[1:]
            while t and (t[0].startswith("-") or re.match(r"^\d+[smhd]?$", t[0])):
                t = t[1:]
        else:
            break
    return t


def check_curl(args: list[str]):
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-X", "--request"):
            m = args[i + 1].upper() if i + 1 < len(args) else ""
            if m not in ("GET", "HEAD", "OPTIONS"):
                deny("http-write", f"curl で {m or '書き込み系'} を送ろうとしています。このガードでは GET/HEAD だけ許可しています。")
            i += 2
            continue
        if a.startswith("--request="):
            if a.split("=", 1)[1].upper() not in ("GET", "HEAD", "OPTIONS"):
                deny("http-write", "curl で書き込み系のメソッドを送ろうとしています。")
        if a in ("-d", "-F", "-T", "--json", "--form", "--upload-file") or a.startswith(("--data", "--form", "--json", "--upload-file")):
            deny("http-write", "curl でデータを送信（POST・アップロード）しようとしています。")
        if re.match(r"^-[A-Za-z]+$", a) and not a.startswith("--"):
            flags = a[1:]
            if any(f in flags for f in "dFT"):
                deny("http-write", "curl でデータを送信（POST・アップロード）しようとしています。")
            if "X" in flags:
                m = args[i + 1].upper() if flags.endswith("X") and i + 1 < len(args) else ""
                if m not in ("GET", "HEAD", "OPTIONS"):
                    deny("http-write", "curl で書き込み系のメソッドを送ろうとしています。")
        i += 1


def check_wget(args: list[str]):
    for i, a in enumerate(args):
        if a.startswith(("--post-data", "--post-file", "--body-data", "--body-file")):
            deny("http-write", "wget でデータを送信しようとしています。")
        if a.startswith("--method"):
            m = a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else "")
            if m.upper() not in ("GET", "HEAD", "OPTIONS"):
                deny("http-write", "wget で書き込み系のメソッドを送ろうとしています。")


def download_target(prog: str, args: list[str]) -> str | None:
    for i, a in enumerate(args):
        if prog == "curl" and a in ("-o", "--output") and i + 1 < len(args):
            return args[i + 1]
        if prog == "curl" and a.startswith("--output="):
            return a.split("=", 1)[1]
        if prog == "wget" and a in ("-O", "--output-document") and i + 1 < len(args):
            return args[i + 1]
        if prog == "wget" and a.startswith("--output-document="):
            return a.split("=", 1)[1]
    if prog == "curl" and any(re.match(r"^-[A-Za-z]*O[A-Za-z]*$", a) or a == "--remote-name" for a in args):
        urls = [a for a in args if re.match(r"^https?://", a)]
        return urls[-1] if urls else None
    if prog == "wget":
        urls = [a for a in args if re.match(r"^(https?|ftp)://", a)]
        return urls[-1] if urls else None
    return None


def check_rm(args: list[str], project: Path):
    recursive = any(a in ("-r", "-R", "--recursive") or (re.match(r"^-[A-Za-z]+$", a) and re.search(r"[rR]", a)) for a in args)
    if not recursive:
        return
    targets = [a for a in args if not a.startswith("-")]
    for t in targets:
        if "$" in t or "`" in t:
            deny("rm-outside", f"rm -r の対象（{t}）に変数が入っていて、消す場所を確認できません。パスをそのまま書いてください。")
        p = Path(os.path.expanduser(t))
        if not p.is_absolute():
            p = Path(os.getcwd()) / p
        p = Path(os.path.normpath(str(p)))
        sp = str(p)
        inside_project = sp.startswith(str(project) + os.sep)
        inside_tmp = sp.startswith("/tmp/") or sp.startswith(os.environ.get("TMPDIR", "/tmp/").rstrip("/") + "/")
        if not (inside_project or inside_tmp):
            deny("rm-outside", f"作業フォルダの外（{sp}）を rm -r で消そうとしています。")


def check_git(args: list[str]):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        if a == "-c" and i + 1 < len(args):
            key = args[i + 1].split("=", 1)[0]
            if DANGEROUS_GIT_C.match(key):
                deny("git-config", f"git -c {key} は認証・フック・接続先を変えられる設定なので止めています。")
            i += 2
            continue
        if a in ("-C", "--git-dir", "--work-tree", "--namespace"):
            i += 2
            continue
        i += 1
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1:]
    if sub == "push":
        for a in rest:
            if a in ("-f", "--force", "--force-with-lease", "--force-if-includes", "--mirror", "--delete", "-d") or a.startswith("--force") or (a.startswith("+") and len(a) > 1):
                deny("git-force", "git push の強制・削除系は止めています。")
            if "://" in a or re.match(r"^[^/\s]+@[^:\s]+:", a) or a.endswith(".git"):
                deny("git-push-url", "git push の宛先に URL が直接書かれています。登録済みのリモート（origin）以外へは送れません。")
    elif sub == "remote" and rest and rest[0] in ("add", "set-url", "rename"):
        deny("git-remote", "git のリモート（送り先）の追加・変更は止めています。")
    elif sub == "config":
        reading = any(a in ("--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "--show-scope") for a in rest)
        keys = [a for a in rest if not a.startswith("-")]
        if not reading and keys:
            key = keys[0].lower()
            if key not in SAFE_GIT_CONFIG_KEYS:
                deny("git-config", f"git config {key} の変更は止めています（変えてよいのは user.name / user.email など）。")


DEP_RULES = [
    (r"^(pip|pip3)$", "install"),
    (r"^(npm|pnpm)$", ("install", "i", "add")),
    (r"^yarn$", "add"),
    (r"^(gem|brew|cargo)$", ("install", "add")),
    (r"^go$", ("install", "get")),
    (r"^(apt|apt-get|dnf|yum|apk)$", ("install", "add")),
    (r"^(poetry|uv|pipx)$", ("add", "install")),
]


def check_dependency(prog: str, args: list[str]):
    if prog in ("python", "python3") and args[:2] == ["-m", "pip"]:
        prog, args = "pip", args[2:]
    if prog == "uv" and args[:1] == ["pip"]:
        prog, args = "pip", args[1:]
    for pat, subs in DEP_RULES:
        if not re.match(pat, prog):
            continue
        subs = (subs,) if isinstance(subs, str) else subs
        if not args or args[0] not in subs:
            return
        rest = args[1:]
        if prog in ("pip", "pip3"):
            names = []
            skip = False
            for a in rest:
                if skip:
                    skip = False
                    continue
                if a in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "--index-url", "-i"):
                    skip = True
                    continue
                if a.startswith("-") or a == ".":
                    continue
                names.append(a)
            if not names:
                return
        elif prog in ("npm", "pnpm", "yarn"):
            if not [a for a in rest if not a.startswith("-")]:
                return  # npm install（ロックファイルどおり）は OK
        ask("dependency", f"新しいパッケージを入れようとしています（{prog} {' '.join(args)[:120]}）。追加してよいか確認してください。")


def check_bash(cmd: str):
    project = _project_dir()
    scan_secrets(cmd, "コマンド")
    scan_domains(cmd, "コマンド")

    if SECRET_ENV_REF.search(cmd):
        deny("secret-env", "コマンドがトークン・パスワード系の環境変数を参照しています。")
    if re.search(r"(^|[;&|]\s*)(printenv|export\s+-p|declare\s+-x|env)\s*($|[;&|>])", cmd):
        deny("secret-env", "環境変数をまとめて表示しようとしています（トークンが含まれる可能性）。")

    low = cmd.lower()
    if re.search(r"\b(curl|wget|fetch)\b", low) and (
        re.search(r"\|\s*(sudo\s+)?(ba|z|da|k|fi)?sh\b", low)
        or re.search(r"\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b", low)
        or re.search(r"<\(\s*(curl|wget)", low)
        or re.search(r"\b(ba|z)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)", low)
    ):
        deny("pipe-to-shell", "ダウンロードしたものをそのまま実行しようとしています（curl | sh など）。")

    if INLINE_WRITE_HTTP.search(cmd):
        deny("http-write", "インラインのコードで POST などの送信や生のソケット通信をしようとしています。")

    # 守り自体へのリダイレクト書き込み
    if re.search(r">>?\s*['\"]?[^\s'\"]*(\.claude/settings(\.local)?\.json|\.claude/guard/|\.github/workflows/claude-guard)", cmd):
        deny("protected", "守りのファイル（.claude/settings*.json・.claude/guard/・同期ワークフロー）は書き換えられません。")

    for seg in split_segments(cmd):
        tokens = strip_wrappers(tokenize(seg))
        if not tokens:
            continue
        prog = os.path.basename(tokens[0])
        args = tokens[1:]

        for t in tokens:
            if is_secret_path(t):
                deny("secret-file", f"認証情報が入っているファイル（{t}）に触ろうとしています。")

        if PROTECTED_IN_COMMAND.search(seg):
            ok = prog in READONLY_PROGRAMS or (prog == "git" and args[:1] and args[0] in READONLY_GIT)
            if prog == "sed" and not any(a.startswith("-i") or a == "--in-place" for a in args):
                ok = True
            if not ok:
                deny("protected", "守りのファイル（.claude/settings*.json・.claude/guard/・同期ワークフロー）は書き換えられません。")

        if prog == "curl":
            check_curl(args)
        elif prog == "wget":
            check_wget(args)
        elif prog in ("http", "https", "xh"):
            if args and args[0].upper() in ("POST", "PUT", "PATCH", "DELETE"):
                deny("http-write", f"{prog} で {args[0].upper()} を送ろうとしています。")
            if any(re.search(r"[^=]:?=[^=]|:=", a) and not a.startswith("-") and "://" not in a for a in args[1:]):
                deny("http-write", f"{prog} でデータを送ろうとしています。")
        elif prog in RAW_NET_PROGRAMS:
            deny("raw-net", f"{prog} は任意の相手に直接データを送れるので止めています。")
        elif prog == "rsync" and any(re.match(r"^[^/\s:]+:", a) for a in args if not a.startswith("-")):
            deny("raw-net", "rsync でリモートへ転送しようとしています。")
        elif prog == "rm":
            check_rm(args, project)
        elif prog == "git":
            check_git(args)
        elif prog == "gh":
            if args[:1] == ["gist"] and len(args) > 1 and args[1] in ("create", "edit", "new"):
                deny("exfil-gist", "gh gist は誰でも見られる場所にファイルを上げられるので止めています。")
            if args[:1] == ["api"] and any(a in ("-X", "--method") for a in args):
                idx = max(i for i, a in enumerate(args) if a in ("-X", "--method"))
                m = args[idx + 1].upper() if idx + 1 < len(args) else ""
                if m not in ("GET", "HEAD"):
                    ask("gh-api-write", f"gh api で {m} を送ろうとしています。実行してよいか確認してください。")

        if prog in ("curl", "wget"):
            target = download_target(prog, args)
            if target and target.lower().split("?")[0].endswith(EXEC_EXTENSIONS):
                ask("exec-download", f"実行ファイル（{os.path.basename(target)}）をダウンロードしようとしています。落としてよいか確認してください（落としても実行はしません）。")

        check_dependency(prog, args)


# ---------------------------------------------------------------- ツールごとの振り分け

def check(tool: str, ti: dict):
    raw = json.dumps(ti, ensure_ascii=False)

    if tool == "Bash":
        check_bash(str(ti.get("command", "")))
        return

    if tool in ("Read", "NotebookRead"):
        p = str(ti.get("file_path") or ti.get("notebook_path") or "")
        if is_secret_path(p):
            deny("secret-file", f"認証情報が入っているファイル（{p}）は読めません。")
        return

    if tool in ("Grep", "Glob"):
        for key in ("path", "pattern", "glob"):
            v = str(ti.get(key) or "")
            if v and tool == "Grep" and key != "pattern" and is_secret_path(v):
                deny("secret-file", f"認証情報が入っているファイル（{v}）は検索できません。")
        return

    if tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        p = str(ti.get("file_path") or ti.get("notebook_path") or "")
        if is_protected_path(p):
            deny("protected", "守りのファイル（.claude/settings*.json・.claude/guard/・同期ワークフロー）は書き換えられません。")
        if is_secret_path(p):
            deny("secret-file", f"認証情報用のファイル（{p}）には書き込めません。")
        scan_secrets(raw, "書き込む内容")
        return

    if tool == "WebFetch":
        url = str(ti.get("url", ""))
        scan_secrets(url, "URL")
        host = urlparse(url).hostname or ""
        hit = _host_blocked(host)
        if hit:
            deny("exfil-domain", f"データの持ち出し先として使われやすいドメイン（{hit}）には接続しません。")
        scan_domains(url, "URL")
        scan_secrets(str(ti.get("prompt", "")), "WebFetch の指示")
        return

    if tool == "WebSearch":
        scan_secrets(raw, "検索語")
        return

    # MCP ツールやその他すべて: 中身に秘密・持ち出し先が入っていないか
    scan_secrets(raw, f"{tool} への入力")
    scan_domains(raw, f"{tool} への入力")


# ---------------------------------------------------------------- ログ

def redact(text: str) -> str:
    for pat, _ in SECRET_PATTERNS:
        text = re.sub(pat, "[REDACTED]", text)
    if CANARY:
        text = text.replace(CANARY, "[CANARY]")
    return text


def summarize(tool: str, ti: dict) -> str:
    for key in ("command", "url", "file_path", "notebook_path", "query", "path", "pattern"):
        if ti.get(key):
            return redact(str(ti[key]))[:300]
    return redact(json.dumps(ti, ensure_ascii=False))[:300]


def log(tool: str, ti: dict, decision: str, rule: str = "", message: str = ""):
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        now = _dt.datetime.now().astimezone()
        rec = {
            "ts": now.isoformat(timespec="seconds"),
            "tool": tool,
            "decision": decision,
            "rule": rule,
            "summary": summarize(tool, ti),
        }
        if message:
            rec["message"] = message
        with open(LOG_DIR / f"audit-{now:%Y-%m-%d}.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass  # ログが書けなくても判定は続ける


# ---------------------------------------------------------------- 入口

def main() -> int:
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except Exception:
        print("[claude-guard] フックへの入力を読めなかったので、念のため止めました。", file=sys.stderr)
        return EXIT_BLOCK

    tool = str(data.get("tool_name", ""))
    ti = data.get("tool_input") or {}
    if not isinstance(ti, dict):
        ti = {"value": ti}

    try:
        check(tool, ti)
    except Decision as d:
        log(tool, ti, d.kind, d.rule, d.message)
        if d.kind == "ask":
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": f"[claude-guard] {d.message}",
                }
            }, ensure_ascii=False))
            return 0
        print(
            f"[claude-guard] 止めました（{d.rule}）: {d.message}\n"
            "別のコマンド・スクリプト・エンコードなどで同じことを試さないでください。"
            "必要な作業なら、何をしようとしたかをユーザーに伝えて判断を仰いでください。",
            file=sys.stderr,
        )
        return EXIT_BLOCK
    except Exception as e:  # ガード自体の不具合は安全側（止める）に倒す
        log(tool, ti, "error", "guard-error", repr(e)[:300])
        print(f"[claude-guard] ガードの内部エラーのため止めました: {e!r}。ユーザーに伝えてください。", file=sys.stderr)
        return EXIT_BLOCK

    log(tool, ti, "allow")
    return 0


if __name__ == "__main__":
    sys.exit(main())
