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
- debconf 非対話化、**dumpcap バイナリの削除**、非 root、`TMPDIR=/work/tmp`
- ベースイメージの digest pin
- `internal/podman`: podman CLI ラッパ（build / image exists / image inspect / machine state / マウントプローブ）
- `build-runtime` サブコマンド（`--force` 付き）
- `doctor`: podman 有無 / machine 状態(macOS) / イメージ有無 / config parse / **実マウントによる到達性検査**
- `runtime/manifest.go` + Dockerfile とのドリフトテスト（`internal/runtime` に分けず `runtime` に同居させた。埋め込み Dockerfile をテストから直接読めるため）

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

- 合成 pcap 生成スクリプト（`samples/generate.sh`）と生成物 4 件の commit
  - `web-session.pcapng` — 素の HTTP 往復
  - `suspicious-download.pcapng` — 本文がインジェクションを試みる HTTP 応答
  - `mixed.pcapng` — 上記 2 本を結合、会話が 2 つ
  - `truncated.pcapng` — `editcap -s 40` で切り詰め
- ダミー MCP クライアント E2E ハーネス（`e2e/`、`-tags e2e`）+ 11 ステージのシナリオ
- `samples/README.md` に同じ 11 ステージを人間向け graded ウォークスルーとして記載

**gopacket は使わなかった。** 計画では gopacket で生成する想定だったが、解析
イメージに既に Wireshark 一式が入っており、`text2pcap` / `mergecap` / `editcap`
で生成できる。Go の依存を増やさず、しかも**読み戻すのと同じ tshark ビルドで
生成する**ことになるため、こちらを採った。

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

### Q5-1. `-z conv,tcp` にストリーム番号は本当に含まれないか — **Resolved（Track C, tshark 4.0.17）**

含まれない。出力はアドレス / ポート / フレーム数 / バイト数 / 相対開始 / 継続時間のみ。さらに**行順が `tcp.stream` の順とも一致しない**（2 ストリームの合成キャプチャで stream 0 が 2 行目に出た）ため、行位置からの推定もできない。設計どおり `-T fields -e tcp.stream ...` の自前集約で実装する。

### Q5-2. 単一ファイル bind mount の virtiofs 挙動 — **Resolved（Track D）**

**動作する。** macOS / applehv の virtiofs 越しに `-v <file>:/evidence/capture:ro` が通り、コンテナ内から見えるのは当該ファイルのみで**兄弟ファイルは一切見えない**。0600 のファイルも `--userns=keep-id:uid=1000,gid=1000` の有無にかかわらず読めた（macOS では virtiofs が所有権を写像するため。native Linux rootless では keep-id が必要になるので指定は維持する）。よって既定を単一ファイルマウントに変更した（ADR-0004 改定）。コンテナ側パスが `/evidence/capture` 固定になる副次効果もある。

関連する実測（Track C）: `podman machine inspect` は共有パスの一覧を**公開していない**（podman 6.0.2 / applehv には `.Mounts` フィールドが無い）。そのため `doctor` は一覧を引くのではなく、実際に ro マウントを試みて到達性を判定する方式にした。同じ手法が単一ファイルマウントの検証にも使える。

### Q5-3. `create_workspace` のフルパス所要時間

`capinfos` + SHA-256 が pcap サイズに対してどれだけかかるか。`async` の要否をエージェントに案内する閾値の根拠になる。

**部分的に判明（Track D）**: 504 バイトのキャプチャで `Create` 全体が **394ms**。これは実質コンテナ起動 1 回分の下限であり、ADR-0002 で見積もった 0.3〜1.0 秒と整合する。**サイズ依存の傾きは未計測** — 大きい実 pcap が要るため、判断閾値は引き続き Track F までに詰める。

なお `capinfos` はファイル全体の SHA-256 を自前で算出して返す。ホスト側 Go の計算と独立した 2 経路になるため、証跡としてはクロスチェックに使える。

### Q5-4. 非同期ジョブの同時実行数上限 — **暫定決着（Track F）**

`[jobs] max_concurrent` として設定可能にし、**既定 2** とした。macOS Podman Machine のメモリ（既定 4GB、8GB 推奨）に対し、フルパス 2 本が同時に走る程度なら余裕がある。大きい実 pcap での実測は未実施のため、必要なら利用者が上げ下げできる形にしてある。

### Q5-5. `--export-objects` の対応プロトコル一覧の取得方法 — **Resolved（Track C）**

`tshark --export-objects help` がそのまま使え、**6 種**を返す: `dicom` / `ftp-data` / `http` / `imf` / `smb` / `tftp`。RFP 段階では 4 種と見込んでいた（`ftp-data` と `dicom` を落としていた）。`describe_runtime` は静的マニフェスト（`runtime/manifest.go`）でこの一覧を返し、base digest を変えたときは再確認する。

### Q5-6. `capinfos` は pcapng ISB の drop 数を出すか — **Resolved（否定, Track C）**

出さない。`capinfos --help` に drop 系のオプションは無く、`-T -m` の列にも drop は現れない（long report の `Number of stat entries` で ISB の**個数**が分かるだけ）。よって **`dropped_packets` は v1 スコープから外す**。代替経路（tshark 側からの取得可否）は Track D で改めて検討する。

**副産物**: 出力形式そのものが当初想定と違った。`-M` は long report 専用で表形式には効かない。実用になるのは `capinfos -T -m -Q <選択フィールド>` で、`-Q` により引用符付き CSV になり `encoding/csv` で読める。ただしコメント欄（`-k`）は改行を含みうるので**選択しない**こと。

もう 1 点、**切り詰め判定はファイルヘッダの snaplen だけでは足りない**。`editcap -s 40` で切り詰めたファイルはヘッダが `(not set)` のまま、推定値の列に `40` が出る。`Packet size limit min/max (inferred)` と併せて判定する必要がある。

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
