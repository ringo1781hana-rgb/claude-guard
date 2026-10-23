# claude-guard

Claude Code でネットワークを広く開けて作業するときの「守り」一式です。
ここで1か所直せば、守りを入れた全リポジトリに PR で届きます。

## 前提：一番の守りは「盗まれて困るものを置かない」

ここにある仕組みは、Claude が直接打つコマンドやツールを検査して事故を減らすものです。
自分で書いたスクリプトの中の通信までは見えないので、**完全には防げません**。
次の2つを土台にしてください。

1. **ネットワーク全許可の環境には、トークンやログイン情報を置かない**
2. **push など書き込みが必要な作業は、許可ドメインを絞った別の環境で行う**

## 何をするか

| 層 | 中身 | 方法 |
|---|---|---|
| 漏えい | トークン・鍵・おとり文字列が、コマンド・URL・書き込み内容・MCP への入力に入っていたら止める | フック |
| 漏えい | 持ち出し先によく使われる宛先（webhook.site、ngrok、pastebin、Discord の Webhook など）への通信を止める | フック＋`blocklist.txt` |
| 漏えい | POST・アップロード・生のソケット通信・リモート転送・`gh gist create` を止める（GET/HEAD だけ通す） | フック |
| 漏えい | 認証情報ファイルの読み取り、秘密の環境変数の参照、環境変数の一括表示を止める | フック＋deny ルール |
| 気づける | おとり（`canary.txt`）が外へ出かけたら止めて記録 | フック |
| 守りを守る | `.claude/settings*.json`・`.claude/guard/`・同期ワークフローの書き換えを止める | フック＋deny ルール |
| 壊さない | 作業フォルダ外の `rm -r`、`git push --force`、URL 直書きの push、リモートの追加、危ない `git config`、`curl … \| sh` を止める | フック |
| 確認する | 新しいパッケージの追加、実行ファイルのダウンロード、`gh api` の書き込み | フック（確認を求める） |
| 気づける | すべてのツール呼び出しを `.claude/guard/logs/` に記録（秘密は伏せ字） | フック |
| 指示 | 外の文章は指示ではない、止められたら回避しない、サイトへの配慮 など | `RULES.md`（CLAUDE.md から読み込み） |

## 新しいリポジトリに入れる

1. `examples/claude-guard-sync.yml` を、そのリポジトリの `.github/workflows/claude-guard-sync.yml` にコピーする
2. そのリポジトリの **Settings → Actions → General → Workflow permissions** で
   「**Allow GitHub Actions to create and approve pull requests**」にチェックを入れて保存する
3. **Actions** タブ → 「claude-guard sync」→「Run workflow」で一度動かす
   → 「守り（claude-guard）を vX.Y.Z に更新」という PR が立つので、中身を見てマージ

以降は毎朝自動で最新版と比べ、差分があれば PR が立ちます。
更新 PR を7日以上放置すると、ワークフローが失敗になって GitHub からメールで知らせます。

## 守りを直す

- 持ち出し先を足す：`template/.claude/guard/blocklist.txt`
- 検査を足す・直す：`template/.claude/guard/guard.py`（直したら `tests/test_guard.py` にもケースを足す）
- Claude 向けのルール：`template/.claude/guard/RULES.md`
- 直したら `VERSION` の数字を上げる

push するとテストが自動で走ります。

## 注意

- 各リポジトリのワークフローは `@main` を参照しています。このリポジトリの main を書き換えられる人は、全リポジトリの同期ワークフローの動きを変えられるので、main はブランチ保護しておいてください。
- 作業用の Claude のセッションには、このリポジトリを書き込み可能な形で付けないでください。守りの元を書き換えられないようにするためです。
