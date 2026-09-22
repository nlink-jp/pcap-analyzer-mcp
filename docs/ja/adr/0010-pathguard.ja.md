# ADR-0010: パスの判定は nlink-jp/pathguard に任せる — 写しを持たない

- Status: Accepted
- Date: 2026-09-22

## Context

ADR-0008 以来、`work_dir` の検証と、読み取りのブラックリスト（`workdir.Sensitive`）は
`internal/mcp/workdir` にあった。voice-scribe（組織 ADR-021 の参照実装）からの写しで、同じ写しが
ほかの 7 サーバーにもあった。どの写しも場所を**名前で**比べていた。APFS は既定で大文字小文字を区別しないので、
`~/.SSH`、`.ENV`、`/USR/local` が同じ場所を指しながら検査を通った。ホームディレクトリが分からない
ときは `Sensitive` が "" を返し、すべてを通した。

組織はこの判定を 1 つのモジュールにまとめた（`nlink-jp/pathguard`、lib-series）。場所を
ファイルの実体と、ディスクと同じやり方で同一視した名前の両方で比べ、まだ存在しない場所も
その親の実体で捕まえる。一覧は gem-agent・lagent と同じものを 1 つ持つ。

## Decision

- `github.com/nlink-jp/pathguard` v0.1.0 を依存に加える。この org の外のコードは入らない。
- `internal/mcp/workdir` は**薄いアダプタ**にする。持つのは次だけ:
  - リクエストの `_meta` を文脈から取り出して `pathguard/workdir` の `Resolve` に渡すこと、
  - その `*workdir.Error` を `toolerr` の同じ code・message・details に移すこと、
  - `NewResolver(serverDirs...)` —— このサーバー自身の設定ディレクトリ
    （`~/.config/pcap-analyzer-mcp` と、使っている設定ファイルを置いたディレクトリ）を守る場所（`pathguard.ServerDir`）として渡し、`work_dir_required` の
    1 文を `RequiredHint` で添える。空のパスは何も守らないのではなく、すべての呼び出しを拒ませる
    （設定ディレクトリが決まらないのはホームが分からないときで、そのときは pathguard もすべてを拒む）、
  - `Sensitive` —— `pathguard/workdir.Sensitive`（Local の方針）をそのまま出す。
- 呼び出し箇所（`Resolve`・`Validate`・`Sensitive`）は変えない。変わるのは組み立ての 1 行
  （`cmd/tools_wiring.go` の `workDirResolver`）と、ゼロ値で組み立てていたテストだけである。
- 判定そのもののテストは pathguard にある。ここに残すのはアダプタのテスト（`_meta` の取り出し、
  エラーの写し、守る場所、ゼロ値が拒むこと）と、既存の契約テストである。

## Consequences

`create_workspace` と `work_dir` の検査が変わる（CHANGELOG に書く）:

- **新たに拒む**: ランタイムと同じ一覧のうち、自分のホームにある本物の場所
  （`~/.kube`、`~/.config/gh`、`~/.azure`、`~/.terraform.d`、`~/.gemini`、`~/.config/mcp-bridge`、
  `~/.netrc`、`~/.npmrc`、`~/.pypirc`、`~/.git-credentials`、`~/.vault-token`、`~/.docker/config.json`、
  `~/.claude.json`、`~/.bash_history`、`~/.zsh_history`）。床のどの場所についても、大文字小文字の違い・
  リンク・ファームリンクなど、あらゆる綴り。それらのディレクトリの直下にあるリンクの指す先（同期フォルダへの
  リンクになった `~/.ssh/config` なら、その指す先のファイル）。`$HOME` がアカウントのホームと違うときは、
  両方を守る。Linux の `/etc` を `work_dir` にすること。
- **新たに通す**: `.env.example`、`.env.sample`、`.env.template`、`.env.dist`（ひな形であって秘密ではない）。
- **ホームが分からなければ、キャプチャのパスもどの `work_dir` も拒む**。以前はすべてを通していた。
- `work_dir_denied` の `details` に `reason` が加わる。
- 1 回の検査は約 2 ms（pathguard の実測）。解析の時間に比べて無視できる。

写しを持たないので、判定の修正は pathguard のリリースと、ここでの依存の更新 1 行になる。

## Amendment (2026-09-22): 実際に使うディレクトリも判定する

`work_dir` だけを検査していたので、`work_dir=~/.config` と `workspace_id=gh` で `~/.config/gh` に届いた（ワークスペースを
作り、その `work/` をコンテナにマウントできた）。ADR-0008 の頃からの穴で、image-forge の独立レビューで見つかった。
`workspace.NewManager(cfg, runner, check)` は判定を必須の引数として受け取り、`Create` と `Load`（`PreviewDelete`・
`Delete` はこれを通る）は、ワークスペースのディレクトリを最初に `workdir.Resolver.CheckBeneath`（pathguard v0.2.0）で
判定する。配線は `newToolDeps`。判定の無い Manager はすべてのワークスペースを拒む。pathguard v0.2.0 は NUL バイトを
含むパスも拒む。

## Amendment (2026-09-22, v0.6.1): ファイルの有無で答えを変えない

`pcap_path` は `filepath.EvalSymlinks` で解決してから床に掛けていた。そのため資格情報の位置にあるファイルは、
あれば `path_not_allowed`、無ければ `pcap_unreadable` になり、答えがどの秘密が存在するかを呼び出し側に教えて
いた。`..` で遡るリンクも、途中がディレクトリならその先で判定され、ファイルなら「not a directory」、存在しなければ
「no such file」と、答えが 3 通りに割れた。slack-mcp-extender と chrome-pilot-mcp の独立レビューで見つかった型で、
ここでは HOME を一時ディレクトリにしたテストで実測した（7 組すべてで答えが違った）。

- `ResolveInput` はまず置き場所を決め（`workdir.Where` = pathguard の `Forms` の末尾。リンクはすべて辿り、
  宙に浮いたリンクはその先で。存在するパスなら `EvalSymlinks` と同じ）、渡された綴りと置き場所の両方で床に
  掛けてから（`refused`）、置き場所に対して存在を問う（`EvalSymlinks(where)`）。解決先が置き場所と違えば
  （その間に変わった）、そこでもう一度判定する。拒否の details の `resolved` は置き場所で、存在に左右されない。
- 終わらないリンクの連鎖は `pcap_unreadable` ではなく `path_not_allowed`（pathguard の unresolvable）になる。
- 解決できないパスに専用の分岐を作らない。
- `TestExistenceIsNotRevealed`（internal/tools）は、同じパスをファイルがある状態と消した状態で `create_workspace`
  を呼び、答え全体を比べる。`TestPlacementCorners` は `..` で遡るリンクとリンクの輪を固定する。4 つの変異
  （判定の順序を戻す・床を外す・綴りから辿り直す・置き場所を決めない）はすべてアサーションで落ちた。
- 既知の例外: 資格情報ファイルへのハードリンクを別の場所に作れば、同一性で拒むのはそれが存在するときだけに
  なる。作れる者はすでにそのファイルに届いている。

## References

- 組織 ADR-021（ファイル渡し MCP サーバーの work dir 契約）
- ADR-0008（work dir 契約）: 検証の閉じた一覧と、読み取りのブラックリスト —— その実装をここで置き換える
- nlink-jp/pathguard の RFP（`docs/ja/pathguard-rfp.ja.md`）
