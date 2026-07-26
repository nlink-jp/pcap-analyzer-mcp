# Phase 1 開発計画: pcap-analyzer-mcp

> Date: 2026-07-26
> Status: Draft

---

## 1. Goals (Phase 1 完成条件)

- `serve` / `build-runtime` / `doctor` / `version` の 4 サブコマンドが動作する
- MCP stdio で 12 エントリ（実作業ツール 11 本 + `get_usage`）が公開され、すべて仕様どおり応答する
- 解析イメージがローカルビルドでき、`describe_runtime` が digest と tshark バージョンを開示する
- 出力契約（ADR-0005）が全ツールで統一的に守られている
- ペイロード安全機構 4 点（ADR-0007）が実装されている
- unit / integration / E2E テストがすべて green
- `make build` で `dist/` に出力される（`feedback_make_build`）

## 2. Work breakdown (Track 別)

### Track A: Repository scaffold + サブコマンド骨格

- CONVENTIONS.md テンプレートに沿った構造作成、`check-org.sh` で検証
- `main.go` + `cmd/`、`Makefile`（バージョンは `git describe`、`feedback_makefile_version`）
- `.gitignore` は `dist/` のみ（`feedback_gitignore_binary_pattern`）+ `.claude/`
- `LICENSE`(MIT) / `AGENTS.md`（他プロジェクトからのコピー禁止）
- `internal/config`（sectioned TOML、`config.example.toml`）
- 4 サブコマンドの骨格

### Track B: MCP stdio framework

data-toolbox-mcp から移植（`feedback_data_toolbox_mcp_skeleton`）。

- `internal/transport/stdio.go`、`internal/jsonrpc/{types.go,codes.go}`
- `internal/mcpserver/{server.go,tools.go,initialize.go}`
- `internal/toolerr/toolerr.go` — sentinel code を本プロジェクト用に差し替え（architecture §5.1）

### Track C: Runtime container image + build-runtime + doctor

- `runtime/Dockerfile`（ADR-0003）+ `runtime/embed.go`
- debconf 非対話化と setuid dumpcap 無効化、非 root、`TMPDIR=/work/tmp`
- ベースイメージの digest pin
- `build-runtime` サブコマンド
- `doctor`: podman 有無 / machine 状態(macOS) / イメージ有無 / config parse / **virtiofs 共有パス検査**
- `internal/runtime/manifest.go` + Dockerfile とのドリフトテスト

### Track D: Workspace 層

- `internal/workspace`: `Create` / `List` / `Delete` / `Load`
- `meta.json` スキーマと読み書き
- SHA-256 計算（ホスト側）
- `podman.go` を移植し **`RunOnce`**（`--rm` 単発実行）を新設、`RunOpts` に `--cap-drop=ALL` を追加
- パス検証（`ResolveAndCheck` 相当 + `workspace_id` 構文 + 結合後パスの再検査）

### Track E: 読み取り系ツール + 出力契約

- `internal/tshark`: 引数組立と出力パース
- `internal/output`: バイト数を数えながら積み、閾値超過でファイルへ切り替える書き出し器。`matched` / `truncated` / `sample` の付与
- ツール: `get_usage` / `create_workspace` / `describe_workspace` / `list_workspaces` / `delete_workspace` / `describe_runtime` / `protocol_hierarchy` / `list_conversations` / `query_packets`
- **この Track の完了時点で、ペイロード無しの読み取り専用版として実用最小に到達する**

### Track F: 非同期ジョブ

- video-studio-mcp `internal/job` を移植（ADR-0006）
- 対象 5 ツールへの `async` 引数追加、`check_job`
- ジョブ同時実行数の上限
- バリデーションは同期のまま行うことの担保

### Track G: ペイロード系 + 安全機構

- `internal/payload`: ノンス生成・XML ラップ・ペイロード中のノンス衝突エスケープ
- `follow_stream`（方向別チャンク化、`offset`/`length`）
- `extract_objects`（`<sha256>.bin` へのリネーム、0600、manifest.json、`_raw` 削除）
- `meta.json.truncated` を見て `payload_unavailable_truncated_capture` を事前に返す経路
- **ペイロード保持型をログ出力に渡せない型構造**
- 完了時に virtual-reviewer / `/security-review` を投入

### Track H: テストハーネス + フィクスチャ

- gopacket による合成 pcap 生成スクリプト（`testdata/gen/`）と生成物の commit
  - 基本 TCP/UDP/DNS フロー
  - HTTP フロー（`extract_objects` 用、良性のダミーファイル）
  - 切り詰めキャプチャ（`snaplen` 小）
  - pcapng（SHB/ISB オプション付き）
- ダミー MCP クライアント E2E ハーネス（`e2e/`、`-tags e2e`）

## 3. Dependencies between tracks

```
A ──┬── B ──┬── E ── F
    │       │
    ├── C ──┤
    │       │
    └── D ──┴── G
            │
            └── H （E 以降、各 Track と並行）
```

- A は全 Track の前提
- E は B / C / D の完了を待つ
- G は D（workspace）と E（出力契約）に依存
- F は E に依存、G とは独立に進められる
- H は E の着手後から並行して積み上げる

## 4. Definition of Done per track

各 Track は以下をすべて満たして完了とする。

- unit テストが green
- 該当する README.md / README.ja.md の記述が更新されている
- `make build` が通り `dist/` に出力される
- 型付きコミットに分割されている（`feedback_commit_discipline`）
- ADR に書かれた決定から逸脱していない（逸脱する場合は ADR を先に改定する）

## 5. Open questions

Phase 0 時点で未解決。Track 着手前または着手中に実測で解決する。

### Q5-1. `-z conv,tcp` にストリーム番号は本当に含まれないか

`list_conversations` を `follow_stream` の入口にするには `tcp.stream` が必要。含まれない前提で `-T fields` の自前集約を設計しているが、**実出力で確認する**。含まれていれば実装が簡素化する。（Track E 着手前）

### Q5-2. 単一ファイル bind mount の virtiofs 挙動

親ディレクトリ ro より blast radius が小さいが、macOS の Podman Machine 越しの挙動が未検証。動作するなら既定を単一ファイルに寄せる。（Track D）

### Q5-3. `create_workspace` のフルパス所要時間

`capinfos` + SHA-256 が pcap サイズに対してどれだけかかるか。`async` の要否をエージェントに案内する閾値の根拠になる。（Track D、実 pcap で計測）

### Q5-4. 非同期ジョブの同時実行数上限

`podman run` を何本まで並行させてよいか。macOS Podman Machine のメモリ（既定 4GB、8GB 推奨）との兼ね合いで決める。（Track F）

### Q5-5. `--export-objects` の対応プロトコル一覧の取得方法

`describe_runtime` で動的に開示したい。`tshark --export-objects help` 相当が使えるか、イメージ内の tshark で確認する。（Track C）

### Q5-6. `capinfos` は pcapng ISB の drop 数を出すか

`dropped_packets` の開示可否がこれに依存する。出ない場合は `tshark` 側から取得する代替手段を検討する。（Track D）

## 6. Reference reuse map

| 移植元 | 対象 | 変更点 |
|---|---|---|
| data-toolbox-mcp `internal/transport` | そのまま | import path のみ |
| data-toolbox-mcp `internal/jsonrpc` | そのまま | import path のみ |
| data-toolbox-mcp `internal/mcpserver` | ほぼそのまま | `RawResult` は不要（バイト列を返さないため） |
| data-toolbox-mcp `internal/toolerr` | 構造は流用 | sentinel code を全面差し替え |
| data-toolbox-mcp `internal/workspace/podman.go` | 流用 | `Run`/`Exec` → `RunOnce`、`--cap-drop=ALL` 追加。`Mount.ReadOnly` は実装済みでそのまま使える |
| data-toolbox-mcp `runtime/embed.go` + `build-runtime` | そのまま | Dockerfile を差し替え |
| data-toolbox-mcp `internal/logging` | そのまま | **ペイロードを渡さない型設計を追加** |
| video-studio-mcp `internal/job` | そのまま | ジョブ種別を差し替え |
| json-to-table | — | 今回は不使用（描画なし） |

## 7. Estimated effort（粗見積もり）

| Track | 規模感 | 備考 |
|---|---|---|
| A | 小 | テンプレート適用が中心 |
| B | 小 | ほぼ機械的な移植 |
| C | 中 | Dockerfile の debconf / setuid 周りに実測が要る |
| D | 中 | パス検証と meta.json が要点 |
| E | **大** | tshark 出力パースと出力契約が本体 |
| F | 小〜中 | 移植 + 同時実行制御 |
| G | **大** | 安全機構が実装の主対象。レビューも込み |
| H | 中 | gopacket でのフィクスチャ合成に手数がかかる |

E と G が全体の重心。**Track E 完了時点で一度リリース判断ができる**構成にしてあるため、G が難航しても読み取り専用版で着地できる。

## See also

- ADR-0001 〜 ADR-0007
- `architecture.ja.md`
- `pcap-analyzer-mcp-rfp.ja.md`
