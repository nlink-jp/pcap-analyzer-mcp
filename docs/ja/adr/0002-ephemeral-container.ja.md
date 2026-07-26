# ADR-0002: 呼び出しごとの ephemeral コンテナを採用する

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Generalises to: 組織 ADR 候補（`.github/adr/`）— 「コンテナを永続化すべきか」の判断基準として一般化できる

---

## Context

本プロジェクトは data-toolbox-mcp のコンテナ実行基盤を移植する。移植元は **workspace ごとに永続コンテナ**を持ち、`Ensure(ctx, workspace_id)` で冪等に起動・再利用し、orphan 検出のためにラベル走査を行い、`list_workspaces` で `container_state` を開示する。

そのまま踏襲すべきかを検討した結果、**移植元が永続コンテナを必要とする理由が本プロジェクトには存在しない**ことが判明した。

data-toolbox-mcp が永続化する理由は **DuckDB がコンテナ内に状態を持つ**ことにある。`load_data` で作ったテーブルはコンテナが死ぬと失われるため、`workspace_id` は「生きたセッション」でなければ意味を成さない。

対して **tshark は完全にステートレス**である。

- どの呼び出しも pcap をファイル先頭から読み直す
- 呼び出し間で引き継ぐべきメモリ上の状態が存在しない
- 保持したい状態（pcap 本体、メタ情報キャッシュ、出力ファイル）はすべてホストのファイルシステム上にある

したがって永続コンテナが提供する価値は「起動レイテンシの節約」のみに縮退する。macOS + Podman Machine 環境での `podman run --rm` は概ね 0.3〜1.0 秒。一方 tshark のフルパスは数秒から数分を要する。節約されるのは全体の数パーセントに満たない。

## Decision

**コンテナは MCP ツール呼び出しごとに `podman run --rm` で起動し、処理終了とともに破棄する。**

- 永続コンテナ、`Ensure` による再利用、`podman exec` は採用しない
- ワークスペースの実体は **ホストのディレクトリ + メタデータ JSON** であり、コンテナはその上を走る使い捨ての計算資源にすぎない
- マウントは呼び出しごとに決定する（ADR-0004）
- コンテナ実行時制限は毎回付与する: `--network=none` / `--cap-drop=ALL` / `--userns=keep-id` / `--cpus` / `--memory`

移植元 `internal/workspace/podman.go` からは `Run` / `Exec` ではなく、**単発実行に特化した `RunOnce`** を新設する。`Mount` 構造体（`ReadOnly` フィールドと `:ro` 付与が実装済み）はそのまま流用する。`RunOpts` には `--cap-drop=ALL` に対応するフィールドを追加する。

## Consequences

**Positive:**

- **orphan コンテナ検出のラベル走査一式が不要になる。** `--rm` により、プロセスが異常終了しない限りコンテナは残らない
- **`Release` / teardown / `delete_workspace` でのコンテナ停止処理が不要になる**
- **`list_workspaces` から `container_state` が消える。** ワークスペースの状態は「ディスク上に存在するか」だけになる
- **サーバー再起動を跨いでワークスペースが生き残るのが無料になる。** in-memory のコンテナ参照を持たないため、in-memory ⇄ disk の同期問題自体が発生しない。`list_workspaces` は単なるディレクトリ走査で実装できる
- **マウントを呼び出しごとに決められる。** これにより、config で固定の evidence root を宣言させる必要がなくなった（ADR-0004）
- 1 回の呼び出しが失敗しても、汚染された状態が次の呼び出しに引き継がれない

**Negative:**

- **1 呼び出しあたり 0.3〜1.0 秒のコンテナ起動コストが常に乗る。** 小さな `query_packets` を数十回連発するようなワークロードでは累積が体感できる可能性がある。ただし `describe_workspace`（キャッシュ読み・コンテナ不要）を用意したことで、最も高頻度になる「メタ情報の確認」はこのコストを回避できる
- **並行実行の上限を自前で持つ必要がある。** 非同期ジョブ（ADR-0006）を無制限に並行させると、`podman run` が同時に何十本も立ち上がりホストを圧迫する。ジョブの同時実行数に上限を設ける
- `podman run` の引数組み立てが毎回発生するため、マウント指定のロジックが呼び出しパスに常駐する。パストラバーサル防御はこのロジックの中で二重に行う

## See also

- ADR-0004: 1 pcap : 1 workspace と read-only マウント
- ADR-0006: 非同期ジョブ
- 移植元: data-toolbox-mcp `internal/workspace/{manager.go,podman.go}`
