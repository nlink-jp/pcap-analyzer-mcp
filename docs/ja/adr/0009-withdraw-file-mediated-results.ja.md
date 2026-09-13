# ADR-0009: ファイル媒介返却を撤回し、上限と計上で返す

- Status: Accepted
- Date: 2026-09-13
- Amends: [ADR-0005](0005-output-contract.ja.md)（出力契約）

## Context

ADR-0005 は出力契約を 4 点で定めた —— (1) 閾値は行数ではなくバイト、(2) インラインと
ファイルで応答の形は同一、(3) `matched` は常に返す、(4) 大きい出力は JSON 配列ではなく
JSONL。このうち **(2) と (4) が前提にしているファイル媒介返却そのもの**を撤回する。

組織方針（利用者決定 2026-09-06、bigquery-mcp RFP Item 2、フリート横断）:

> MCP サーバーが閾値超過を自分で選んだファイルへ書いてパスを返す方式は廃止する。
> サーバーは呼び出し側のコンテキスト窓を知り得ず、閾値・退避先・読み戻しをサーバーごとに
> 持つとフリート全体が同じ機構を重複実装する。大きなレスポンスのファイル化は
> エージェントランタイムの仕事（gem-agent ADR-0058 の intake）。サーバーに残るのは
> **明示キャップと省略の計上**だけ。

本サーバーでは splunk-mcp と同じ形で適用する（同サーバーは同日にスピルを撤去した）。

## Decision

1. **`query_packets` は行をレスポンスで返す。** `result_file` / `sample` / `delivery` /
   `format`（jsonl・csv）を削除し、CSV エンコーダも削除する。
2. **上限は 2 つ**: `limit`（行数、呼び出し引数 + config `default_row_limit`）と
   **`max_bytes`**（バイト予算、config。旧 `inline_max_bytes` を改名して意味を変更）。
   ADR-0005 の「バイトで測る」判断は**維持する** —— payload 列を持つ 100 行は
   アドレスだけの 1 万行より重い、という理由はそのまま生きている。
3. **落とした分は必ず計上する。** `truncated` に加えて `omitted_rows`
   （= `matched` − `returned`）と、どちらの上限で止まったかを述べる `note` を返す。
   `matched` は従来どおり**常に正確**で、打ち切られた結果も「キャプチャ全体についての
   答え」であり続ける。
4. **応答の形の不変性（ADR-0005 (2)）は維持する。** 上限に当たったかどうかで
   キーは変わらない。`truncated` で分岐する。
5. 削除した config キー（`output.inline_max_bytes`・`output.sample_rows`）は、
   残っている config を**名指しで起動時に落とす**。黙って無視すれば、運用者が
   書いたつもりの上限が無言で消える。
6. **`work_dir` は残る。** `extract_objects` の抽出物はファイルが産物そのものであり、
   ワークスペース（`meta.json`）も要る。撤回したのは「データをサーバー判断で
   ファイルにする」ことだけである（組織 ADR-021 の区別: 産物がファイルか、データか）。

## Consequences

- **破壊的。** `query_packets` の `format` 引数は消え、応答から `result_file` /
  `sample` / `delivery` が消える。`limit: 0` は「無制限エクスポート」ではなく
  「バイト予算だけで制限」の意味になる
- 全件が要る調査は、フィルタを絞る / フィールドを減らす / `limit` を上げる、の
  いずれかになる。ランタイムが大きなレスポンスを退避する場合はそれで足りる
- `internal/output` から `csv.go` とファイル書き出し経路が消え、パッケージは
  「行を貯めて上限で止め、計上する」だけになった

## References

- 組織方針 2026-09-06（bigquery-mcp RFP Item 2）、gem-agent ADR-0058（ランタイム側 intake）
- splunk-mcp の同日の同種変更（`inline_row_threshold` → `max_rows`）
- [ADR-0005](0005-output-contract.ja.md)（出力契約）、[ADR-0004](0004-workspace-per-capture.ja.md)、
  組織 ADR-021（work dir 契約 —— `work_dir` はこの変更後も残る）
