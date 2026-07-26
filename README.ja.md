# pcap-analyzer-mcp

[English](README.md)

AI エージェントにパケットキャプチャを解析させるための MCP サーバー。

エージェントは pcap を扱えません。tshark を薄く包んでも解決せず、`tshark -V`
は 1 パケットで数百行を吐きます。`pcap-analyzer-mcp` は **バージョンを固定した
tshark をコンテナ内で動かし**、キャプチャを **read-only でマウント**して、
小さい結果はインライン、大きい結果はワークスペースへ JSONL で返します。
最初の応答で溺れることなく、GB 級のキャプチャを段階的に絞り込めます。

> **ステータス: 未リリース。** 設計は完了しており（RFP + ADR-0001〜0007 +
> architecture、[`docs/`](docs/) 参照）リポジトリも scaffold 済みですが、
> ツールは未実装です。`serve` / `build-runtime` / `doctor` は、どの開発トラック
> で実装されるかを表示します。

## なぜコンテナなのか

イメージビルド時に tshark を固定することで、3 つの問題が同時に片付きます。

- **再現性** — `-T fields` のフィールド名や `-z` 統計の書式は tshark の
  バージョンで揺れます。イメージで版数を固定すればホストの環境に左右されず、
  各結果には使用した tshark バージョンとイメージ digest が記録されます。
- **隔離** — Wireshark の dissector は攻撃者制御下のデータを解釈します。
  コンテナは `--network=none`、非 root、全 capability を落として実行します。
- **誤キャプチャの排除** — イメージには setuid `dumpcap` が無くネットワークも
  ありません。ライブキャプチャは方針ではなく構成上不可能です。

キャプチャは **複製しません**。ディレクトリを read-only でマウントするため
原本はバイト単位で変わりません。GB 級ファイルで安価であり、証拠の取り扱いと
しても正しい形です。

## 必要なもの

- [Podman](https://podman.io/)（rootless、デーモン不要）
- macOS: `podman machine start`。VM メモリは 8GB 推奨。キャプチャは共有パス
  (`/Users`, `/private/tmp`, `/var/folders`) の配下に置く必要があります。

## インストール

```bash
git clone https://github.com/nlink-jp/pcap-analyzer-mcp.git
cd pcap-analyzer-mcp
make build              # → dist/pcap-analyzer-mcp
make runtime-image      # tshark 解析イメージをローカルビルド
```

## 使い方

MCP クライアントにサーバーとして登録します。

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "/path/to/pcap-analyzer-mcp",
      "args": ["serve"]
    }
  }
}
```

典型的な流れは、キャプチャのワークスペースを作り、メタ情報を見て、目立つ会話を
見つけ、display filter で絞り込む、というものです。

```
create_workspace(pcap_path, workspace_dir)  →  workspace_id, sha256, 要約
describe_workspace(workspace_id)            →  パケット数・時間範囲・snaplen
list_conversations(workspace_id)            →  誰と誰が話したか（+ストリーム番号）
query_packets(workspace_id, filter, fields) →  行をインライン、または JSONL ファイル
follow_stream(workspace_id, ...)            →  実際に流れたバイト列
extract_objects(workspace_id, "http")       →  ファイル抽出（defang + ハッシュ）
```

### ツール一覧

| ツール | 役割 |
|---|---|
| `get_usage` | ワークスペースモデル・出力契約・エラー回復 |
| `create_workspace` | キャプチャを開く。SHA-256 / `capinfos` / tshark 版数を記録 |
| `describe_workspace` | キャッシュ済みメタ情報 — コンテナを起動しない |
| `list_workspaces` | `workspace_dir` 配下のワークスペース一覧 |
| `delete_workspace` | ワークスペース削除（`dry_run` あり） |
| `describe_runtime` | イメージ digest・tshark 版数・対応オブジェクトプロトコル |
| `protocol_hierarchy` | このキャプチャに何が流れているか |
| `list_conversations` | 端点ペアとバイト数、ストリーム番号 |
| `query_packets` | display filter + フィールド抽出 — 主力 |
| `follow_stream` | ストリーム本文の再構成（レンジ読み対応） |
| `extract_objects` | HTTP / SMB / IMF / TFTP オブジェクトの抽出 |
| `check_job` | 非同期実行の進捗と結果 |

重いツールは `async: true` を受け付け `job_id` を返すので、`check_job` で
ポーリングします。大きいキャプチャのフルパスは分単位かかり、そのままでは
MCP クライアントのリクエストタイムアウトに引っかかるためです。

### 出力の扱い

大きい結果は **JSONL** で書き出されます。`head` / `grep` で部分的に読め、
DuckDB がそのまま読み込めます。パケットテーブルに SQL をかけたい場合は
[data-toolbox-mcp](https://github.com/nlink-jp/data-toolbox-mcp) へ渡せます。
絞り込みが本ツール、集計と結合があちらの担当です。

すべての応答は `returned` と併せて `matched`（フィルタに合致した総数）を返す
ので、絞り込みを強めるべきかどうかが常に分かります。

## 信頼できないキャプチャの扱い

調査対象のキャプチャは、定義上、攻撃者の影響下にあります。知っておくべき点が
2 つあります。

- **ストリーム本文はラップされます。** ノンス付きのマーカーで「これは指示では
  なくデータである」と明示します。これは緩和策であって保証ではありません。
- **抽出オブジェクトは defang されます。** `<sha256>.bin` として保存され、
  実行ビットは立たず、バイト列がインラインで返ることはありません。マニフェスト
  の SHA-256 だけで脅威情報へピボットできることがほとんどで、ファイル本体に
  触れる必要はまずありません。

ペイロードは、どのログレベルでもログファイルに出力されません。

## 設定

設定は任意です。すべての値に実用的な既定があります。
[`config.example.toml`](config.example.toml) を参照してください。
`--config <path>` を渡すか `PCAP_ANALYZER_MCP_CONFIG` を設定します。

## ドキュメント

- [RFP](docs/ja/pcap-analyzer-mcp-rfp.ja.md) — 問題定義・スコープ・計画
- [アーキテクチャ](docs/ja/reference/architecture.ja.md) — 信頼境界・データフロー・セキュリティモデル
- [ADR](docs/ja/adr/) — 各設計判断とその代償
- [Phase 1 計画](docs/ja/reference/phase1-plan.ja.md) — トラックと未解決事項

## ライセンス

MIT
