# pcap-analyzer-mcp

[English](README.md)

AI エージェントにパケットキャプチャを解析させるための MCP サーバー。

エージェントは pcap を扱えません。tshark を薄く包んでも解決せず、`tshark -V`
は 1 パケットで数百行を吐きます。`pcap-analyzer-mcp` は **バージョンを固定した
tshark をコンテナ内で動かし**、キャプチャを **read-only でマウント**して、
結果は明示した上限の範囲でレスポンスに載せ、上限で落とした分は必ず計上します。
最初の応答で溺れることなく、GB 級のキャプチャを段階的に絞り込めます。

> **ステータス: v0.1.0。** 12 ツールを実コンテナで端から端まで動作確認し、実 MCP
> クライアントからの検証も済んでいます。独立したセキュリティレビューも一巡しました。
> [既知の制限](CHANGELOG.md#known-limitations) を参照してください。

## なぜコンテナなのか

イメージビルド時に tshark を固定することで、3 つの問題が同時に片付きます。

- **再現性** — `-T fields` のフィールド名や `-z` 統計の書式は tshark の
  バージョンで揺れます。イメージで版数を固定すればホストの環境に左右されず、
  各結果には使用した tshark バージョンとイメージ digest が記録されます。
- **隔離** — Wireshark の dissector は攻撃者制御下のデータを解釈します。
  コンテナは `--network=none`、非 root、全 capability を落として実行します。
- **誤キャプチャの排除** — イメージから `dumpcap` バイナリを削除しており、
  ネットワークもありません。ライブキャプチャは方針ではなく構成上不可能です。

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
create_workspace(pcap_path, work_dir)  →  workspace_id, sha256, 要約
describe_workspace(workspace_id)            →  パケット数・時間範囲・snaplen
list_conversations(workspace_id)            →  誰と誰が話したか（+ストリーム番号）
query_packets(workspace_id, filter, fields) →  行（上限つき・落とした分は計上）
follow_stream(workspace_id, ...)            →  実際に流れたバイト列
extract_objects(workspace_id, "http")       →  ファイル抽出（defang + ハッシュ）
```

呼び出しには必ず `work_dir` —— **自分が読み戻せる**ディレクトリの絶対パス、通常は
セッションや作業用のディレクトリ —— も渡します。ワークスペースは
`<work_dir>/<workspace_id>/` で、インラインに収まらない結果もそこに書かれます。
`(work_dir, workspace_id)` の対がワークスペースの住所そのもの（このサーバーは再起動を
またいで何も覚えません）。必須で、既定値はありません。

システム領域、ホームディレクトリそのもの、資格情報・エージェント制御ファイルの
位置、および**このサーバー自身の設定ディレクトリ**を `work_dir` に指定した
呼び出しは、サブディレクトリを含め、どんな綴りで渡しても `work_dir_denied` で拒否します
（判定は [nlink-jp/pathguard](https://github.com/nlink-jp/pathguard) が行います）。対象は
`~/.config/pcap-analyzer-mcp` と、`--config` / `PCAP_ANALYZER_MCP_CONFIG` で
設定ファイルを指している場合はそれを置いたディレクトリです —— 設定ファイルは
作業にも使うディレクトリではなく、専用のディレクトリに置いてください。

キャプチャ自体は読める場所ならどこにあっても構いません —— read-only でマウントされ、
コピーもされません。拒否されるのは `~/.ssh` や `~/.aws` のような資格情報・エージェント
制御ファイルの位置だけです。

### ツール一覧

| ツール | 役割 |
|---|---|
| `get_usage` | ワークスペースモデル・出力契約・エラー回復 |
| `create_workspace` | キャプチャを開く。SHA-256 / `capinfos` / tshark 版数を記録 |
| `describe_workspace` | キャッシュ済みメタ情報 — コンテナを起動しない |
| `list_workspaces` | `work_dir` 配下のワークスペース一覧 |
| `delete_workspace` | ワークスペース削除（`dry_run` あり） |
| `describe_runtime` | イメージ digest・tshark 版数・対応オブジェクトプロトコル |
| `protocol_hierarchy` | このキャプチャに何が流れているか |
| `list_conversations` | 端点ペアとバイト数、ストリーム番号 |
| `query_packets` | display filter + フィールド抽出 — 主力 |
| `follow_stream` | ストリーム本文の再構成（レンジ読み対応） |
| `extract_objects` | HTTP / SMB / IMF / TFTP / FTP-DATA / DICOM オブジェクトの抽出 |
| `check_job` | 非同期実行の進捗と結果 |

重いツールは `async: true` を受け付け `job_id` を返すので、`check_job` で
ポーリングします。大きいキャプチャのフルパスは分単位かかり、そのままでは
MCP クライアントのリクエストタイムアウトに引っかかるためです。

### 出力の扱い

行はレスポンスで返します。上限は `limit`（行数）と `max_bytes`（バイト予算）の
2 つで、上限で落とした分は `truncated`・`omitted_rows`・どちらの上限で止まったかを
述べる `note` として返ります。`matched` は常に正確なので、打ち切られた結果も
「キャプチャ全体についての答え」であり続けます。

**このサーバーは結果をファイルに書きません。** 呼び出し側のコンテキスト窓を
サーバーは知り得ないためで、大きなレスポンスをディスクへ退避するのはエージェント
ランタイムの仕事です。絞り込みが本ツールの担当で、パケットテーブルに SQL を
かけたいなら、絞ってから
[data-toolbox-mcp](https://github.com/nlink-jp/data-toolbox-mcp) へ渡してください。

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

設定ファイルは次の順に探し、最初に見つかったものを使います:

1. `--config <path>`
2. `PCAP_ANALYZER_MCP_CONFIG`
3. `~/.config/pcap-analyzer-mcp/config.toml`

(1) (2) で**名指ししたパス**が読めない場合はエラーです（打ち間違いが「既定を使う」と
解釈されてはならない）。(3) は「あれば読む」もので、無ければ組み込みの既定になります。
カレントディレクトリは**探しません** —— このサーバーはエージェントランタイムが起動し、
cwd はランタイムが決めるため、`./config.toml` を見ると「誰が起動したか」で設定が
変わってしまいます。

## ドキュメント

- [RFP](docs/ja/pcap-analyzer-mcp-rfp.ja.md) — 問題定義・スコープ・計画
- [アーキテクチャ](docs/ja/reference/architecture.ja.md) — 信頼境界・データフロー・セキュリティモデル
- [ADR](docs/ja/adr/) — 各設計判断とその代償
- [クライアント設定](docs/ja/reference/client-setup.ja.md) — サーバー登録とトラブルシューティング
- [実践 Tips](docs/ja/reference/tips.ja.md) — 調査の進め方: 調査の型、プロトコル別フィルタレシピ、ハマりどころ
- [実地ノート](docs/ja/reference/field-notes.ja.md) — 実マルウェアを含むキャプチャの解析: AV の干渉、除外設定に伴う危険、`ftp-data` の制約
- [サンプルキャプチャ](samples/README.md) — 合成キャプチャ 4 件と graded ウォークスルー
- [Phase 1 計画](docs/ja/reference/phase1-plan.ja.md) — トラックと未解決事項

## ライセンス

MIT
