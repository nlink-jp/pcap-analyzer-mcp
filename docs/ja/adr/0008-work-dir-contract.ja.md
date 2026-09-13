# ADR-0008: work dir は呼び出しごとの `work_dir` で受け取り、`allowed_paths` を廃止する

- Status: Accepted
- Date: 2026-09-13
- Amends: [ADR-0004](0004-workspace-per-capture.ja.md) の `allowed_paths` 条項

## Context

組織 ADR-021（ファイル渡し MCP サーバーの work dir 契約）を本サーバーに適用する。
参照実装は voice-scribe（同 ADR-0010）で、ここはフリートで 2 番目、かつ
**入力に絶対パスを常用する最初のサーバー**である。ブラックリストの形はここで決まる。

2 つの事実が動機である。

**1. 引数名がフリートで割れている。** 同じ意味の引数が `workspace_root` /
`workspaceRoot` / `workspace_dir` の 3 綴りで存在し、モデルはサーバーごとに別の名前を
覚える必要がある。本サーバーの綴りは `workspace_dir`。

**2. `allowed_paths` は Claude Code から本サーバーを使えなくしている。** このマシンの
設定は 2 つのエージェント state root と `~/Downloads` を並べているが、Claude Code は
`/private/tmp/claude-<uid>/…` にファイルを置くため、**エージェントが直前に stage した
capture が拒否される**。ADR-0004 はこれを「guardrail であって sandbox 境界ではない、
既定は無制限」と位置づけていた。その位置づけは正しかったが、機構としては表現力が
足りない —— 照合は解決後パスの前方一致で、リポジトリ単位の粒度が無い。1 つの work root
の下に約 105 リポがある環境で共通に賄うには `~/works` か `~` を挙げるしかなく、`~` を
開けた瞬間に `.ssh` も `.aws` も通ってリストは意味を失う。運用者が実際に書けるのは
狭い非プロジェクト root の列挙だけで、その結果が上の閉塞である。

さらに 4 ランタイム（Claude Code / ChatGPT Codex / gem-agent / lagent）の実測
（2026-09-13）で、MCP の `roots` は Codex が capability を宣言せず空配列を返し、
Claude Code は scratchpad を含まないプロジェクト dir しか返さず、環境変数は Codex が
剥がすことが分かっている。**呼び出しごとの引数だけが 4 ランタイム共通の経路**である。

## Decision

### 1. 引数は `work_dir`、全ツールで必須のまま

`workspace_dir` を `work_dir` に改名する。意味は
**「呼び出し側が読み戻せる絶対パス」**。ワークスペースは `<work_dir>/<workspace_id>/`。
毎回渡す点は変えない —— `(work_dir, workspace_id)` の対がワークスペースの住所であり、
サーバーは再起動をまたいで状態を持たない。

**名前の衝突に注意**: `work_dir`（呼び出し側の root）と `Workspace.WorkDir()`
（`<ws>/work`、コンテナの `/work` にマウントされる書込領域）は**別の層**である。
Go 側で呼び出し側の root を指す識別子は `root` を使い、`WorkDir()` は触らない。

### 2. 解決順は 引数 → `_meta` → エラー

`params._meta["jp.nlink/work_dir"]` を第 2 経路として読む。自前ランタイムが全
`tools/call` に付けられる、スキーマ非依存の経路である。どちらも無ければ
`work_dir_required`。**サーバー既定は持たない。**

### 3. 検証は閉じた一覧

絶対パス / `~` 無し / `..` 無し / 存在する dir / 書込可 / システム位置でない。
コードは `work_dir_invalid`・`work_dir_not_found`・`work_dir_not_writable`・
`work_dir_denied`。**dir は作らない** —— 呼び出し側の dir は必ず存在するので、
無いパスは打ち間違いである。

### 4. `allowed_paths` を削除し、入力はブラックリストで床を張る

- `pcap_path` は `work_dir` の外の絶対パスでよい。**capture はコピーせず ro マウント**
  する設計（ADR-0004）なので、GB 級の capture を stage させる方が有害である
- 拒否するのは、資格情報とエージェント制御ファイルの位置を並べた**コード内固定**の
  ブラックリストだけ: `~/.ssh`、`~/.aws`、`~/.config/gcloud`、`~/.gnupg`、
  `~/Library/Keychains`、`~/.claude`、`~/.codex`、`~/.config/{gem-agent,lagent}`、
  および任意の `.env`。判定前に symlink を解決する（ADR-0004 の symlink 再検査は維持）
- 設定キー `workspace.allowed_paths` は消す。**キーが残った config は大声で落とす**
  （BurntSushi の `Undecoded()` で未知キーを検出）。黙って無視すれば、運用者が
  書いたつもりのガードが無言で消える
- ブラックリストは**床であって境界ではない**。プロセスが何に触れうるかを縛るのは
  サンドボックス MCP プロキシの仕事で、そちらは意図的に後回しにしている

### 5. 書き込みは `work_dir` 配下だけ

既に成立している（ワークスペースは root 配下、capture は ro）。明文化して固定する。

### 6. 結果は行き先を反響する

ワークスペースを指す結果に、解決済み絶対パスの `work_dir` を載せる。`_meta` 経由で
work dir を注入された呼び出し側は、結果からしか行き先を知れない。

## Consequences

- **破壊的**。`workspace_dir` を送る呼び出しは拒否され、新しい名前を告げる
  `work_dir_required` が返る。`allowed_paths` を持つ config は起動時に落ちる
- **Claude Code から使えるようになる。** stage 先が scratchpad でも capture が通る
- **サーバー設定がランタイムを名指すのをやめる。** config から 2 ランタイムの
  state root が消え、5 つ目の呼び出し元が増えてもこのリポは触らない
- `doctor` の mount 検査は `allowed_paths` 分岐を失い、既定共有
  （`/Users`・`/private/tmp`・`/var/folders`）の検査に一本化される
- 運用者は「このサーバーだけ読める範囲を狭める」ノブを失う。取り戻す場所は
  将来のサンドボックスプロキシで、そこでは全サーバーに一度に効く

## References

- 組織 ADR-021（work dir 契約）と voice-scribe ADR-0010（参照実装）
- [ADR-0004](0004-workspace-per-capture.ja.md) —— 1 pcap : 1 workspace、ro マウント。本 ADR はその `allowed_paths` 条項のみを置き換える
