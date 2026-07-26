# ADR-0006: 重いツールのみ非同期ジョブとする

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Generalises to: なし

---

## Context

ADR-0005 は結果の**サイズ**の問題を解いたが、それとは直交する**時間**の軸が残る。

- 20GB の pcap に対する `tshark` のフルパスは分単位を要する
- `create_workspace` の `capinfos` もパケット数を数えるためにファイル全体を走査する
- MCP クライアントにはリクエストタイムアウトがあり、長時間の同期応答は途中で切断される

同期のまま放置すると、大きなキャプチャで「タイムアウトしたのか処理中なのか分からない」状態になり、エージェントが同じ重い呼び出しを再試行してホストを圧迫する最悪の挙動を招く。

video-studio-mcp は同じ問題を ADR-0003 で解決済みである（`internal/job` によるインメモリ非永続ジョブ、`JobCtx` はサーバー寿命の context、`job_not_found` なら再実行）。この実装は本プロジェクトにそのまま移植できる。

## Decision

**`internal/job`（video-studio-mcp ADR-0003）を移植し、重いツールにのみ `async: true` オプションを設ける。**

| ツール | async | 理由 |
|---|---|---|
| `create_workspace` | ○ | `capinfos` のフルパス + SHA-256 計算 |
| `protocol_hierarchy` | ○ | `-z io,phs` のフルパス |
| `list_conversations` | ○ | 全パケット走査 + 集約 |
| `query_packets` | ○ | フィルタ次第でフルパス |
| `extract_objects` | ○ | 全パケット走査 + 再構成 |
| `follow_stream` | × | 単一ストリームに限定されるため相対的に軽い |
| `describe_workspace` / `describe_runtime` / `list_workspaces` / `delete_workspace` / `get_usage` | × | コンテナ不要またはメタ操作のみ |

設計方針:

- **バリデーションは同期のまま行う。** 引数不正・ワークスペース不在・パス違反は `async` でも即座にエラーを返す。ジョブが走り始めてから失敗するのは引数エラーではなく実行時エラーに限る
- ジョブの実行 context は**リクエスト context ではなくサーバー寿命の context** を使う。リクエストが返った時点でリクエスト context はキャンセルされるため
- ジョブはインメモリ・非永続。サーバー再起動で失われる。`check_job` が `job_not_found` を返したら、エージェントは元のツールを再実行すればよい（結果は冪等）
- **ジョブの同時実行数に上限を設ける**（ADR-0002 の Negative への対処）。`podman run` が無制限に並行するとホストが飽和するため
- `check_job` は進捗（現在のフェーズ）と、完了時は ADR-0005 の統一形状をそのまま返す
- **進捗にパーセンテージは持たせない。** tshark はキャプチャのどこまで読んだかを報告しないため、算出できない数字を出せば「待てば終わる」と誤解させるだけになる。返すのはフェーズ（`queued` / `reading` / `counting` / `done`）と、実際に分かっている生成行数のみ

## Consequences

**Positive:**

- 大きなキャプチャでもクライアントのタイムアウトに阻まれない
- エージェントが「処理中である」ことを明示的に知れるため、無駄な再試行が起きない
- 実装は video-studio-mcp からの移植であり、新規設計のリスクが小さい
- 同時実行数の上限が ephemeral コンテナのリソース問題を同じ場所で解決する

**Negative:**

- **エージェントに `async` を使うかどうかの判断が要求される。** 判断材料として `describe_workspace` の `packet_count` / `file_size` を使えるよう、`get_usage` に目安を書く必要がある。あるいは「サーバー側で閾値を超えたら自動的に非同期に切り替え、`job_id` を返す」設計も考えられるが、レスポンス形状が実行時に変わることになるため v1 では採らない
- ジョブが非永続であるため、サーバー再起動を跨いだ長時間ジョブは失われる。重いフルパスをやり直すコストが発生する
- 同期パスと非同期パスの 2 系統をテストする必要があり、E2E の組み合わせが増える

## See also

- ADR-0002: 呼び出しごとの ephemeral コンテナ（同時実行数の上限）
- ADR-0005: 出力契約（サイズの軸）
- 移植元: video-studio-mcp ADR-0003（`internal/job`）
