# Architecture: pcap-analyzer-mcp

> Date: 2026-07-26
> Status: Phase 0 (設計)

対応する設計判断は ADR-0001〜0007 に記録されている。本文書はそれらを 1 つの動作モデルとして統合したものである。

---

## 0. Binary layout — 単一バイナリ + サブコマンド

`feedback_single_binary_subcommand` に従い、1 バイナリに 4 サブコマンドを同居させる。

| サブコマンド | 役割 |
|---|---|
| `serve` | MCP stdio サーバーを起動する（既定の運用形態） |
| `build-runtime` | `go:embed` した Dockerfile から解析イメージをローカルビルドする |
| `doctor` | podman / イメージ / config / virtiofs 共有パスを検査する |
| `version` | `git describe` 由来のバージョンを表示する |

## 1. Overview

```
┌─────────────────────┐
│  MCP クライアント    │  Claude Code / Cowork / Claude Desktop
│  （エージェント）    │
└──────────┬──────────┘
           │ stdio (JSON-RPC 2.0 / MCP 2024-11-05)
┌──────────▼──────────────────────────────────────────┐
│  pcap-analyzer-mcp (Go, ホストプロセス)              │
│                                                      │
│  internal/transport   stdio 読み書き                 │
│  internal/jsonrpc     JSON-RPC 2.0                   │
│  internal/mcpserver   ツールルーティング              │
│  internal/toolerr     構造化エラー                    │
│  internal/job         非同期ジョブ (ADR-0006)         │
│  internal/workspace   ws 生成・meta.json・podman 起動 │
│  internal/tshark      引数組立・出力パース            │
│  internal/output      出力契約 (ADR-0005)             │
│  internal/payload     隔離・defang (ADR-0007)         │
│  internal/tools       ツールハンドラ                  │
└──────────┬───────────────────────────────────────────┘
           │ exec: podman run --rm ...  （呼び出しごと / ADR-0002）
┌──────────▼──────────────────────────────────────────┐
│  解析コンテナ (debian:12-slim + tshark, digest pin)  │
│    network=none / 非root / --cap-drop=ALL            │
│                                                      │
│    /evidence/capture ro ← pcap ファイルそのもの      │
│    /work      rw  ← <workspace>/work                 │
└──────────────────────────────────────────────────────┘
```

**状態はホストのファイルシステムにしかない。** コンテナは使い捨ての計算資源であり、サーバープロセスもワークスペースの実体を in-memory に持たない（非同期ジョブの一時状態を除く）。

## 2. Process boundaries（信頼境界）

| 境界 | 内容 |
|---|---|
| エージェント → サーバー | ツール引数。`workspace_id` の構文検査、パスの symlink 解決と `allowed_paths` 検査を行う |
| サーバー → コンテナ | `podman run` の引数。マウント指定はサーバーが組み立てる。エージェントが任意のマウントを指定する経路は存在しない |
| **pcap のバイト列 → tshark** | **最も危険な境界。** 攻撃者制御下のデータを dissector が解釈する。`network=none` / 非 root / `--cap-drop=ALL` / ro マウントで封じ込める |
| **tshark 出力 → エージェント** | **2 番目に危険な境界。** ペイロードは攻撃者が制御するテキストであり、ノンス XML で隔離する（ADR-0007） |

`/evidence/capture` が ro であることにより、dissector の脆弱性を突かれても**証拠原本は改変されない**。書き込み可能なのは `/work` のみで、これはワークスペース内に閉じている。

## 3. Data flow（正常系シーケンス）

### 3.1 create_workspace(pcap_path, workspace_dir, async?)

1. `workspace_dir` の書き込み可否を確認、`pcap_path` を symlink 解決し `allowed_paths` を検査
2. `workspace_id` を生成（pcap のベース名 + 短いハッシュ）、`<workspace_dir>/<id>/work/{tmp,out,out/objects}` を作成
3. ホスト側で pcap の **SHA-256** を計算
4. `podman run --rm -v <pcap>:/evidence/capture:ro -v <ws>/work:/work <image> sh -c 'tshark --version; echo <区切り>; capinfos -T -m -Q <選択フィールド> /evidence/capture'` を実行（tshark 版数と capinfos を **1 回のコンテナ起動**で取る）
5. イメージ ID を `podman image inspect` で取得（コンテナ不要）
6. 3〜5 を `<ws>/meta.json` に書き込む
7. `workspace_id` と要約を返す

### 3.2 describe_workspace(workspace_id)

`<ws>/meta.json` を読み、`work/out/` を走査して `outputs[]` を付けて返す。**コンテナを起動しない。**

### 3.3 query_packets(workspace_id, filter, fields, limit, format, async?)

1. `meta.json` を読み、pcap パスとマウント情報を得る
2. `podman run --rm ... tshark -r /evidence/capture -Y <filter> -T fields -e <field>... -E header=y -E separator=/t`
3. stdout を行単位で読みながら JSON 行に変換し、**バイト数を数えながら**積む
4. `inline_max_bytes` を超えた時点で `work/out/<n>.jsonl` へ切り替え、以降はストリーム書き出し
5. `truncated` になった場合のみ、件数取得のための追加パス（`-Y <filter> -T fields -e frame.number` を数える）を実行して `matched` を得る
6. ADR-0005 の統一形状で返す

### 3.4 protocol_hierarchy(workspace_id, async?)

`tshark -r ... -q -z io,phs` の出力を階層構造の JSON に変換して返す。

### 3.5 list_conversations(workspace_id, type, sort_by, top_n, async?)

`-T fields -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e frame.len` を取得し、**サーバー側で集約**する。`-z conv,tcp` を使わないのは、その出力に `tcp.stream` が含まれず、`follow_stream` への導線が作れないためである（Phase 1 Open Question Q1 で実測確認）。

### 3.6 follow_stream(workspace_id, protocol, stream_index, offset, length)

1. `tshark -r ... -q -z follow,<proto>,raw,<index>` を実行
2. 方向ごとのチャンクに構造化し、`offset` / `length` で窓を切る
3. **ノンス付き XML でラップ**して返す（ADR-0007）

### 3.7 extract_objects(workspace_id, protocol, async?)

1. `tshark -r /evidence/capture --export-objects <proto>,/work/out/objects/_raw` を実行
2. 出力された各ファイルについて SHA-256 を計算し、`<sha256>.bin`（0600）にリネーム
3. 元の名前 / Content-Type / URI / フレーム番号を `manifest.json` に記録（攻撃者由来文字列はノンス XML でラップ）
4. `_raw` を削除し、マニフェストとパスのみ返す。**バイト列は返さない**

### 3.8 delete_workspace(workspace_id, dry_run?)

ディレクトリを削除する。`dry_run` では削除対象のパスと容量のみ返す。コンテナの停止処理は不要（ADR-0002）。

## 4. State model

### 4.1 in-memory（サーバープロセス内）

- **非同期ジョブのみ**（`internal/job`）。インメモリ・非永続。サーバー再起動で失われる
- ワークスペースの一覧・状態は in-memory に持たない

### 4.2 ディスク（永続）

```
<workspace_dir>/<workspace_id>/
├── meta.json     # pcap パス / sha256 / capinfos / tshark 版数 / image digest
└── work/
    ├── tmp/            # tshark の TMPDIR
    ├── out/            # クエリ結果 (JSONL/CSV)
    └── out/objects/    # 抽出オブジェクト（untrusted, 0600, <sha256>.bin）
```

### 4.3 in-memory ⇄ disk sync

**同期ポイントは存在しない。** ADR-0002 で永続コンテナを廃したことにより、`feedback_in_memory_disk_sync` が指摘する類の同期問題が原理的に発生しない。`list_workspaces` はディレクトリ走査、`describe_workspace` は `meta.json` の読み取りである。

## 5. Error & lifecycle

### 5.1 MCP プロトコル原則

ツールエラーは JSON-RPC のエラーではなく、`isError: true` + 構造化 JSON（`{code, message, details}`）を content に載せて返す（data-toolbox-mcp `internal/toolerr` を移植）。

sentinel code 案: `invalid_arguments` / `missing_argument` / `invalid_workspace_id` / `workspace_not_found` / `path_not_allowed` / `pcap_unreadable` / `invalid_display_filter` / `container_failed` / `tshark_failed` / `job_not_found` / `payload_unavailable_truncated_capture` / `object_too_large`

### 5.2 自己修復ヒント

`invalid_display_filter` の `details` には、tshark が返した構文エラー位置と候補フィールド名を載せる。これが無いとエージェントは同じ誤りを繰り返す（data-toolbox v0.4.0 の `CatalogException` ヒントと同じ発想）。

`payload_unavailable_truncated_capture` は、`meta.json` の `truncated` が真のときに `follow_stream` / `extract_objects` を**実行する前に**返す。切り詰めキャプチャで空振りしたことを「一時的な失敗」と誤解させないため。

### 5.3 タイムアウト

各 `podman run` に個別のタイムアウトを設ける。同期呼び出しではクライアントのタイムアウトより短く設定し、非同期ではジョブ全体のタイムアウトに従う。

### 5.4 コンテナ失敗

`--rm` により失敗したコンテナは残らない。exit code と stderr を `container_failed` / `tshark_failed` の `details` に載せる（`feedback_child_process_exit_status`）。

### 5.5 MCP 切断

ワークスペースはディスク上に残る。次回接続時に `list_workspaces` で発見でき、`describe_workspace` でそのまま作業を再開できる。走行中の非同期ジョブはサーバー寿命の context で走り続ける（ADR-0006）。

## 6. Security model

### 6.1 ホストファイルアクセス

- `pcap_path` は symlink 解決後に `allowed_paths` を検査（既定は空 = 無制限、ADR-0004）
- `workspace_dir` は書き込み可否のみ検査
- マウント対象はサーバーが決定し、エージェントは指定できない

### 6.2 workspace_id 検証

`^[a-zA-Z0-9_-]{1,64}$`。パストラバーサル防御は「構文検査」と「結合後パスが `workspace_dir` 配下に収まるかの再検査」の二重で行う。

### 6.3 コンテナ実行時制限

`--network=none` / `--cap-drop=ALL` / 非 root（`USER 1000`）/ `--userns=keep-id` / `--cpus` / `--memory` / `--rm`。イメージからは dumpcap バイナリ自体を削除しているため、キャプチャ能力が無い。

### 6.4 ペイロードの扱い

ADR-0007 の 4 点（ノンス XML 隔離 / defang / ログ除外 / レンジ読み）。ペイロードを保持する型はログ出力経路に渡せない構造とする。

### 6.5 証跡

`meta.json` の SHA-256 / tshark バージョン / イメージ digest が chain of custody の基点になる。ro マウントにより原本は改変されない。

## 7. Testability

### 7.1 Unit tests

`internal/tshark`（引数組立・出力パース）、`internal/output`（バイト閾値・形状）、`internal/payload`（ノンス生成・エスケープ・defang）、`internal/workspace`（パス検証）。podman 呼び出しは `runner` インタフェースで差し替える（移植元の seam をそのまま利用）。

### 7.2 Integration tests

実際の podman + イメージを用いる。`-tags integration`。

### 7.3 自動 E2E テストハーネス

ダミー MCP クライアントで stdio 越しに全ツールを叩く（`feedback_dummy_mcp_client_harness`）。`-tags e2e`。

### 7.4 pcap フィクスチャ

**gopacket で合成生成する。** 外部由来のバイナリをリポジトリに置かず、決定論的で小さい。生成スクリプトをリポジトリに含め、生成物も commit する。HTTP フローを組み立てて `extract_objects` のテストまで賄う。**実マルウェア検体は置かない。**

切り詰めキャプチャ（`snaplen` 小）のフィクスチャも用意し、`payload_unavailable_truncated_capture` の経路を検証する。

## 8. Out of scope (Phase 1)

- ライブキャプチャ（構成上不可能。ADR-0003）
- IDS / シグネチャ検知（Suricata / Zeek スクリプト）
- pcap の編集・匿名化
- parquet 出力（ADR-0003）
- HTTP / SSE トランスポート（stdio のみ）
- 分割キャプチャの `mergecap` 結合（ADR-0004、additive に後付け）
- ワークスペースの TTL GC
- Zeek 第 2 バックエンド（ADR-0001）

## See also

- ADR-0001 〜 ADR-0007
- `pcap-analyzer-mcp-rfp.ja.md`
- `phase1-plan.ja.md`
