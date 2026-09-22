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
  （その間に変わった）、そこでもう一度判定する。
- 拒否が名指すのは渡されたとおりのパスだけで、details から `resolved` を外した。置き場所は途中の項目がリンクなら
  変わる（同期フォルダへの `~/.ssh/config`、dotfiles へリンクした `~/.aws`）ので、宙に浮いたリンクと項目なしで
  値が違い、どの項目があってどこを指すかを示していた。輪では、渡していない途中の段を名指していた（この変更の
  独立レビューが見つけた）。
- 拒否以外で答えが変わるものが 2 つ。リンクを通って入った作業ディレクトリでの相対の `pcap_path` は、絶対パスの
  綴りと同じく最後まで解決されるようになり、ワークスペース ID が変わる。ファイルや存在しない名前の後に `..` がある
  パスは、pathguard が置く場所（存在する部分に `..` を適用した場所）で開かれ、カーネルのように「not a directory」
  「no such file」とは答えない。
- 終わらないリンクの連鎖は `pcap_unreadable` ではなく `path_not_allowed`（pathguard の unresolvable）になる。
- 解決できないパスに専用の分岐を作らない。
- `TestExistenceIsNotRevealed`（internal/tools）は、同じパスをファイルがある状態と消した状態で `create_workspace`
  を呼び、答え全体を比べる（リンクである資格情報の項目と、リンクである資格情報ディレクトリを含む）。
  `TestPlacementCorners` は `..` で遡るリンクとリンクの輪を固定する。5 つの変異（判定の順序を戻す・床を外す・
  綴りから辿り直す・置き場所を決めない・拒否に置き場所を戻す）はすべてアサーションで落ちた。
- pathguard 側の既知の限界（次のリリースに向けて記録）:
  - 資格情報ディレクトリの項目を通って `..` で抜けるパス（パス自体でも、仕掛けたリンクの行き先でも）は、通った場所
    ではなく行き着く場所で判定されるので、その項目がリンクか・行き先がどこかが答えに出うる。pathguard が判定するのは
    Clean した形で、歩いた途中のディレクトリではない。
  - 置き場所は pathguard の形の末尾。リンクの連鎖が既に出た綴りに戻ると、それは終点ではなく途中の段になる。どの段も
    判定済みなので判定していないものは開かないが、その経路のファイルは見つからないと答えるか、途中の段から読まれうる。
    pathguard は終点を返さない。
  - `work_dir` は pathguard/workdir が組織 ADR-022 §4 の順序（not found が denied より先）で検証するので、資格情報の
    ディレクトリを指す `work_dir` は、存在するかどうかで答えが変わる。
  - 非 ASCII 名のリンク先を別の Unicode 正規化で綴ると、同一性で拒むのはそれが存在するときだけになる（pathguard は
    正規化しない）。別の場所に作ったハードリンクを拒むのは、床の場所そのものであるファイル（`~/.netrc`、
    `~/.docker/config.json` など）へのものだけで、それも存在するときだけ。資格情報ディレクトリの中のファイル
    （`~/.ssh/id_rsa`）や `.env` へのハードリンクは拒まない —— ディレクトリはそれ自身の同一性で比べ、中のファイルでは比べない。
- 判定と読み取りは 2 段で、その間にすり替えたリンクは辿られる（check-to-use の競合。ここでは閉じていない。閉じるには、
  開いたものを記述子から判定する必要がある）。

## Amendment (2026-09-22, v0.6.2): 置き場所は pathguard の `Where`

置き場所を pathguard の形（`Forms`）の末尾で決めていたが、形は重複を除くので、リンクの連鎖が既に出た綴りに戻ると
末尾は終点ではなく途中の段になる（既知の限界として記録していたもの）。pathguard v0.3.0 の `Where` が歩いた終点を
返すので、置き場所はそれにした。行き先が決まらないパス（終わらないリンクの連鎖）は渡されたパスのままで、床がそれを
拒む。そのほかの限界は pathguard の README の「限界」にまとめて記録し、受け入れた。

## References

- 組織 ADR-021（ファイル渡し MCP サーバーの work dir 契約）
- ADR-0008（work dir 契約）: 検証の閉じた一覧と、読み取りのブラックリスト —— その実装をここで置き換える
- nlink-jp/pathguard の RFP（`docs/ja/pathguard-rfp.ja.md`）
