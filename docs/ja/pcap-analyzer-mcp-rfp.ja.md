# RFP: pcap-analyzer-mcp

> Generated: 2026-07-26
> Status: Draft

## 1. Problem Statement

エージェントは pcap / pcapng を扱えない。tshark を薄く包んだだけの MCP サーバーを作っても、`tshark -V` は1パケットで数百行、`-T json` は1000パケットで数 MB になり、出力がコンテキストを焼き切って実用にならない。

`pcap-analyzer-mcp` は、バージョンを固定した tshark をコンテナに閉じ込め、解析対象の pcap を read-only でマウントして解析し、**結果が小さければインライン JSON、大きければワークスペースへ JSONL ファイル**という統一契約で返す MCP サーバーである。これによりエージェントは、セキュリティインシデント調査やネットワーク障害解析において、GB 級のパケットキャプチャを段階的に絞り込みながら分析できるようになる。

対象利用者は、Claude Code / Cowork でインシデント対応・障害解析を行う開発者本人。

## 2. Functional Specification

### Commands / API Surface

#### CLI サブコマンド（単一バイナリ）

| サブコマンド | 役割 |
|---|---|
| `serve` | MCP stdio サーバーを起動 |
| `build-runtime` | 解析コンテナイメージをローカルビルド（Dockerfile は `go:embed` で同梱） |
| `doctor` | podman / イメージ / config / virtiofs 共有パスの健全性検査 |
| `version` | バージョン表示 |

#### MCP ツール（11本）

| ツール | 役割 | コンテナ起動 | async |
|---|---|---|---|
| `get_usage` | ワークスペースモデル・出力契約・エラー回復表の自己開示 | なし | — |
| `create_workspace` | pcap 指定 → ワークスペース生成。sha256 / capinfos / tshark 版数 / イメージ digest を記録 | あり | ○ |
| `describe_workspace` | キャッシュ済みメタ情報を返す（**無料**） | **なし** | — |
| `list_workspaces` | `workspace_dir` を走査してワークスペース一覧 | なし | — |
| `delete_workspace` | ワークスペース削除（`dry_run` 付き） | なし | — |
| `describe_runtime` | イメージ digest / tshark 版数 / 対応 export-object プロトコルの静的開示 | なし | — |
| `protocol_hierarchy` | プロトコル階層統計（`-z io,phs`。フルパス） | あり | ○ |
| `list_conversations` | 会話一覧（`tcp.stream` / `udp.stream` 番号込み）。バイト数降順が top talkers | あり | ○ |
| `query_packets` | **主力**。display filter + 抽出フィールド + limit + format | あり | ○ |
| `follow_stream` | ストリーム本文の再構成。`offset` / `length` によるレンジ読み | あり | — |
| `extract_objects` | HTTP / SMB / IMF / TFTP / FTP-DATA / DICOM オブジェクトを defang 保存 + マニフェスト返却 | あり | ○ |
| `check_job` | 非同期ジョブの進捗と結果 | なし | — |

（`check_job` を含めて12エントリだが、`get_usage` を除いた実作業ツールは11本）

`describe_workspace` は `create_workspace` 時に一度だけ実行した `capinfos` の結果をワークスペースに JSON キャッシュしたものを読むだけで、コンテナを起動しない。ワークスペースが過去のセッションで作られていても、作り直さずにメタ情報を取得できる。

### Input / Output

#### 入力

- **pcap は複製しない。** `create_workspace` に渡されたパスの親ディレクトリを `/evidence` に **read-only** マウントする。GB 級ファイルのコピーを避けると同時に、証拠原本の完全性を保つ
- ワークスペースの書き込み領域は `<workspace_dir>/<workspace_id>/work` を `/work` に rw マウント。tshark の `TMPDIR` もここに向ける
- **1 pcap : 1 workspace** を厳守。リングバッファ分割キャプチャは将来 `mergecap` で1つの論理キャプチャに束ねて同ルールを維持する（v1 は単一ファイルのみ）
- `workspace_dir` は config ではなく**呼び出しごとにエージェントが指定**する。エージェントは自分の書き込み可能領域を知っているが、config は知らないため

#### 出力契約

すべての結果返却ツールが以下の統一形状に従う。インライン返却でもファイル出力でも**形状を変えない**（エージェントに分岐を書かせない）。

```json
{
  "workspace_id": "...",
  "filter": "tcp.flags.reset == 1",
  "matched": 48213,
  "returned": 200,
  "truncated": true,
  "rows": [ "... インライン時のみ ..." ],
  "result_file": "<workspace>/out/q3.jsonl",
  "result_bytes": 48231904,
  "sample": [ "... ファイル出力時も先頭数行を必ず添える ..." ]
}
```

- **閾値は行数ではなくシリアライズ後のバイト数**（既定 65536）。pcap ではペイロード列付き100行がフィールド10000行より大きくなることがざらにあるため、行数では制御できない
- **`matched`（フィルタ合致総数）は常時返す。** これが無いとエージェントは「絞り込みが効いたのか、そもそも該当が無いのか」を判断できない
- **ファイル出力時も `sample` に先頭数行を添える。** 中身の形を知るためだけの往復を防ぐ
- **大きい出力は単一 JSON 配列ではなく JSONL。** `head` / `grep` で部分読みでき、DuckDB が `read_json_auto` でそのまま読む。500MB の JSON 配列は誰にとっても扱えない
- 出力ファイルは「エージェントが全部読むもの」ではなく、**(a) 次のツールへの入力 (b) 部分読み** の前提で設計する
- 時刻は **epoch + UTC ISO-8601 の両方**を返し、ローカル時刻整形は返さない

#### `describe_workspace` の返却内容

```
pcap_path, sha256, file_size, format (pcap/pcapng), encapsulation
packet_count, first_packet, last_packet, duration_sec
avg_packet_size, max_packet_size, avg_bytes_per_sec
snaplen_header, snaplen_inferred_min, snaplen_inferred_max, truncated
capture_os, capture_app   (pcapng SHB に記録されていれば)
tshark_version, image_digest
outputs[]                 (これまでに生成した出力ファイル一覧)
```

snaplen 系フィールドと `truncated` の開示は必須。切り詰め判定はファイルヘッダの snaplen だけでは足りず、ヘッダ未設定でも実パケットが切り詰められていることがあるため、`capinfos` が返す推定値（inferred min/max）と併せて判定する。`-s 96` などで切り詰められたキャプチャではペイロードが存在せず、`follow_stream` も `extract_objects` も空振りする。これを**試す前に**エージェントへ伝えないと、失敗したと誤解して無駄なリトライを繰り返す。

「SYN が無い」のが通信が無かったのかキャプチャが取りこぼしたのかでも結論は変わるが、取りこぼし数の開示は v1 では見送る（§7 参照）。

### Configuration

`config.toml`（[lite-series config conventions] のセクション分け規約に従う）:

```toml
[container]
image = "pcap-analyzer-runtime@sha256:..."   # digest pin

[container.limits]
cpu = "2"
memory = "4g"
network = "none"

[workspace]
allowed_paths = []          # 空 = 制限なし（サンドボックス境界ではなく事故防止のガードレール）

[output]
inline_max_bytes = 65536
default_row_limit = 10000

[payload]
follow_inline_max_bytes = 8192
extract_max_object_bytes = 104857600

[log]
level = "info"              # ペイロード本体は決してログに出さない
```

`allowed_paths` はマウント制約ではなく `ResolveAndCheck` 相当のポリシー検査。ephemeral コンテナではマウントを呼び出しごとに決められるため、固定の evidence root を config で宣言する必要がない。Cowork で毎回 config を編集させると摩擦になるため、既定は無制限とする。

### External Dependencies

- **Podman**（rootless、デーモン不要）— 子プロセスとして `podman` バイナリを exec
- **解析コンテナイメージ** — `debian:12-slim`（digest pin）+ `tshark`。`wireshark-common` 依存により `capinfos` / `editcap` / `mergecap` / `text2pcap` も自動同梱される。イメージサイズ実測 274MB
- 外部 API・認証情報・ネットワークアクセスは一切なし（`network = "none"`）

## 3. Design Decisions

### 言語 / フレームワーク

**Go**。org の MCP サーバー（data-toolbox-mcp / voice-studio-mcp / video-studio-mcp / *-lookup 群）と同じ路線。外部依存が軽く、シングルバイナリで配布できる。

### バックエンドに tshark を選択

- **tshark**: display filter（`ip.addr == x && tcp.flags.syn == 1`）が人間にも LLM にも共通語彙になっている。3000 超の dissector。単一パッケージで導入できる
- **Zeek**（却下）: `conn.log` / `dns.log` / `http.log` が最初から表形式で IR の定石に近いが、依存が重い。同一ツール表面の裏で差し替える**将来の第2バックエンド**として deferred

### 呼び出しごとの ephemeral コンテナ（永続コンテナを採らない）

data-toolbox-mcp が workspace ごとに永続コンテナを持つのは、**DuckDB がコンテナ内に状態を持つ**ため。`load_data` で作ったテーブルはコンテナが死ぬと消えるので、`workspace_id` は生きたセッションでなければならない。

**tshark は完全にステートレス**で、毎回 pcap を頭から読み直すだけであり、コンテナ内に保存する価値のある状態がゼロ。状態はすべてホスト FS（ro の pcap と rw の出力）にある。永続コンテナは起動レイテンシを節約する以外に何も生まず、そのレイテンシ（macOS の Podman で 1 回あたり 0.3〜1 秒程度）は tshark のフルパス（数秒〜数分）に対して誤差である。

ephemeral 化で捨てられるもの:

- orphan コンテナ検出のラベル走査一式
- `Release` / コンテナ teardown
- `list_workspaces` の `container_state`
- **サーバー再起動でワークスペースが消える問題** — ワークスペースがホストディレクトリ + メタデータ JSON になるため、再起動を跨いで生き残るのが無料になり、`list_workspaces` はディレクトリ走査で済む

さらに、マウントを呼び出しごとに決められるため、固定の evidence root を config で宣言する必要がなくなる。

### tshark 単独の lean イメージ（DuckDB を同梱しない）

コンテナに DuckDB / Python を入れないため **parquet を書ける主体がいない**。Go 側に parquet writer を足すのは lean の趣旨に反するので、**export は JSONL / CSV** とする。data-toolbox-mcp の `load_data` は DuckDB 経由でどちらもそのまま読むため受け渡しは成立する。

責務分割は「**絞り込み = pcap-analyzer、集計・結合・可視化 = data-toolbox-mcp**」。ただし data-toolbox の `load_data` はホストファイルを `/work/_upload/` に物理コピーするため、**export はフィルタで絞ってから渡す**のが運用上のコツになる。

### 補完関係にある既存 nlink-jp ツール

| ツール | 関係 |
|---|---|
| data-toolbox-mcp | 骨格（transport / jsonrpc / mcpserver / toolerr / podman / build-runtime / doctor）の移植元。かつ export 先の SQL エンジン |
| video-studio-mcp | 非同期ジョブ（`internal/job` + `check_job`）の移植元 |
| whois-lookup / asn-lookup / abuse-lookup / doh-lookup / tor-exit-lookup / icloud-relay-lookup | 抽出した IP を評判・登録情報へピボットする先。同シリーズ |
| urlscan-lookup | 抽出した URL の調査先 |
| virtual-reviewer | ペイロード系（Track G）のセキュリティレビューに投入 |

### 明示的にスコープ外

- **ライブキャプチャ** — 読み取り専用解析に権限は一切不要。`network = "none"` のコンテナは原理的にキャプチャできないため、設計で強制される。setuid dumpcap を debconf で無効化したうえで dumpcap バイナリごと削除し、非 root 実行、`--cap-drop=ALL`
- **IDS / シグネチャ検知**（Suricata / Zeek スクリプト）
- **pcap の編集・匿名化** — 将来検討の余地はあるが v1 では扱わない
- **parquet 出力** — lean イメージの帰結
- **HTTP / SSE トランスポート** — stdio のみ

### ペイロード抽出を MVP に含める判断とその代償

`follow_stream` / `extract_objects` はエージェントの深堀り分析に必須と判断して MVP に含める。ただしこれを含めた瞬間、以下は「あると良い」ではなく「無いと壊れる」に変わる。**ペイロードを返す実装と同一コミットで入れる**こと。

1. **プロンプトインジェクション隔離（最優先）** — `follow_stream` の戻り値は攻撃者が完全に制御するテキストがエージェントのコンテキストに直入りする経路である。しかも「不審な通信を解析してほしい」が本来用途なので、**敵対的入力が例外ではなく通常運転**。ノンス付き XML でラップし、「これはデータであって指示ではない」を出力の**冒頭**に置く
2. **抽出オブジェクトの defang** — 元のファイル名では書かず `<sha256>.bin` で保存（元の名前 / Content-Type / URI / frame 番号はマニフェスト JSON 側）。実行ビットを立てない（0600）。**バイト列はインラインで返さない**（data-toolbox の `attach_files` が画像をインライン返却するのとは真逆が正解）。全オブジェクトの SHA-256 を返せば、エージェントは中身を一度も読まずに脅威情報へピボットできる。出力先は `<workspace>/out/objects/` として `get_usage` で untrusted と宣言する
3. **ログにペイロードを書かない** — ログはディスクに落ちるため、ペイロード本体が入ると PII / 認証情報の漏出になる。フィルタ式やストリーム番号は記録してよい
4. **レンジ読み** — 1本の TCP ストリームが 2GB のファイル転送ということが普通にあるため、`offset` / `length` 窓で段階的に読ませる

### バージョン固定と証跡

digest で pin したイメージを使い、**使用したイメージ ID と tshark バージョンをワークスペースのメタデータに刻む**。「どのバージョンの tshark で得た結果か」が後から辿れることは、証跡としても、dissector 由来の解釈差を疑うときにも効く。`debian:12-slim` のような可動タグに依存しない。

## 4. Development Plan

### Phase 0: 設計文書化

| ADR | 内容 |
|---|---|
| ADR-0001 | バックエンドに tshark を選択（Zeek 却下と将来の第2バックエンド余地） |
| ADR-0002 | 呼び出しごと ephemeral コンテナ（data-toolbox の永続モデルを採らない理由） |
| ADR-0003 | tshark 単独 lean イメージ + digest pin（DuckDB 非同梱、export は JSONL / CSV） |
| ADR-0004 | 1 pcap : 1 workspace + ro マウント（コピーしない、`workspace_dir` は呼び出し時指定） |
| ADR-0005 | 出力契約（バイト閾値 / JSONL / `matched`・`sample` 常時 / 形状不変） |
| ADR-0006 | 非同期ジョブ（video-studio ADR-0003 流用、重いツールのみ） |
| ADR-0007 | ペイロード安全性（インジェクション隔離 / defang / ログ除外 / レンジ読み） |

併せて `architecture.md` と `phase1-plan.md` を docs/{ja,en} 両建てで作成する。

### Phase 1: Core

| Track | 内容 |
|---|---|
| A | scaffold + サブコマンド（`serve` / `build-runtime` / `doctor` / `version`） |
| B | MCP stdio 骨格移植（`internal/{transport,jsonrpc,mcpserver,toolerr}`） |
| C | ランタイムイメージ（`go:embed` Dockerfile、setuid dumpcap 無効、非 root、digest pin）+ `build-runtime` + `doctor` |
| D | workspace 層（create / list / delete、sha256、capinfos キャッシュ、ro マウント、ephemeral exec、`--cap-drop=ALL`） |
| E | 読み取り系ツール（`describe_workspace` / `describe_runtime` / `protocol_hierarchy` / `list_conversations` / `query_packets`）+ 出力契約の実装 |
| F | 非同期ジョブ + `check_job` |
| G | ペイロード系（`follow_stream` / `extract_objects`）+ 安全機構4点 |
| H | dummy MCP client E2E ハーネス + pcap フィクスチャ |

**テスト用 pcap は gopacket で合成生成する。** Wireshark の公開サンプルはライセンス / 帰属の扱いが面倒であり、外部由来のバイナリをリポジトリに置きたくない。gopacket なら決定論的で小さく、HTTP フローも組み立てられるので `extract_objects` のテストまで賄える。**実マルウェア検体はリポジトリに置かない。**

### Phase 2: Features

- **Claude Code / Cowork 実機検証** — data-toolbox-mcp が Claude Desktop で 11 ケースを graded README とともに回した手法を踏襲
- **不正な display filter への自己修復ヒント** — tshark が構文エラーを返したとき、エラー `details` に該当箇所と候補フィールドを載せる。data-toolbox v0.4.0 の `CatalogException` ヒントと同じ発想で、これが無いとエージェントは同じ誤りを繰り返す
- `samples/`（合成 pcap）+ graded README
- `docs/{en,ja}/reference/client-setup.md`
- ログ整備（起動時 rotate、ペイロード除外の徹底）

### Phase 3: Release

LICENSE (MIT) / README.md / README.ja.md / AGENTS.md / CHANGELOG.md 整備 → 署名 + notarize → 4 platform アーカイブ（darwin arm64 zip + linux amd64/arm64 tar.gz + windows amd64 zip）→ `gh release create` → cybersecurity-series submodule 追加 → org profile README 追記 → `check-org.sh` 全緑。

### 独立にレビューできる区切り

| 区切り | レビュー対象 |
|---|---|
| Phase 0 完了 | 設計判断そのもの |
| Track A–D 完了 | コンテナが立ちワークスペースが作れる骨格 |
| **Track E 完了** | **ペイロード無しで既に実用最小**（読み取り専用版として先に着地可能） |
| Track G 完了 | セキュリティレビュー（virtual-reviewer / `/security-review` を投入） |

Track E で一度切れる構成にしてあるため、ペイロード抽出が難航しても読み取り専用版として先にリリースできる。

## 5. Required API Scopes / Permissions

**None。**

外部サービスへのアクセス・認証情報・OAuth スコープ・IAM ロールは一切不要。必要な権限はローカルの以下のみ:

- `podman` バイナリの実行権限（rootless、root 不要）
- 解析対象 pcap への**読み取り**権限
- `workspace_dir` への書き込み権限

コンテナは `network = "none"` / 非 root / `--cap-drop=ALL` で実行され、setuid dumpcap は無効化される。

## 6. Series Placement

Series: **cybersecurity-series**

Reason:

- 主用途がセキュリティインシデント調査であり、シリーズの定義（AI-augmented security tools: threat intel, IR, risk assessment）に合致する
- 同シリーズには既に Go 製 MCP サーバー（whois-lookup / abuse-lookup / doh-lookup / mac-lookup / tor-exit-lookup / icloud-relay-lookup / urlscan-lookup）が揃っており、Go + MCP という実装形態の前例がある
- pcap から抽出した IP / ドメイン / URL を、同シリーズの各 lookup ツールへ直接ピボットできる。同一シリーズに置くことで組み合わせが自然になる
- util-series は「パイプ親和的なデータ変換 CLI」が中心で、ドメイン特化のセキュリティ解析ツールの置き場としては合わない

命名は `pcap-analyzer-mcp`。`-studio`（合成系）でも `-lookup`（単発照会系）でもない解析系ツールであり、util-series の `mail-analyzer` と同系統の命名になる。

## 7. External Platform Constraints

### MCP クライアント

- **リクエストタイムアウト** — 20GB の pcap に対するフルパスは分単位かかり、クライアントのタイムアウトを普通に超える。重いツール（`create_workspace` / `protocol_hierarchy` / `list_conversations` / `query_packets` / `extract_objects`）は `async` + `check_job` で回避する
- **レスポンスサイズ** — 戻り値はすべてコンテキストに載る。出力契約のバイト閾値がこの制約への直接の回答
- **クライアント側 inputSchema 検証** — Claude Desktop は `enum` をクライアント側で事前検証するため、サーバー側チェックには到達しないことがある。サーバー側検証は defense-in-depth として維持する

### macOS + Podman Machine

- **virtiofs 共有パス制約** — 解析対象 pcap が Podman Machine の共有パス配下（既定で `/Users`、`/private/tmp`、`/var/folders`）にないとマウントできない。外付けディスクや `/Volumes` 直下の pcap は素通しできないため、`doctor` で共有パス配下かを検査する
- **VM メモリ** — 既定 4GB では大きい pcap のフルパスで不足する場合がある。8GB 推奨
- **単一ファイル bind mount** — 親ディレクトリ ro マウントより blast radius は小さいが virtiofs での挙動が未検証。既定は親ディレクトリ ro とし、単一ファイルマウントは検証後の絞り込み案とする

### tshark

- **バージョン間の出力差** — `-T fields` / `-T ek` のフィールド名や `-z` 統計の書式はバージョンで揺れる。これがコンテナで版数を固定する第一の動機
- **`-z conv,tcp` にストリーム番号が含まれない** — 出力はアドレス / ポート / フレーム数 / バイト数のみで `tcp.stream` を返さない。4タプルからの逆引きはポート再利用で多対一に崩れる。`list_conversations` を `follow_stream` の入口にするなら `-T fields -e tcp.stream ...` の自前集約で作るほうが堅い（**実装時に実出力で要確認**）
- **root 実行時の警告** — tshark は root で走ると警告を出す。非 root 実行（`USER 1000`）が前提
- **Debian パッケージの debconf 対話** — `wireshark-common` が「非 root にキャプチャさせるか」を対話質問する。`DEBIAN_FRONTEND=noninteractive` + `debconf-set-selections` で setuid を明示的に false にする
- **`capinfos` は `-T -m -Q` の選択フィールド CSV を使う** — `-M` は long report にしか効かない。`-Q` で引用されるため `encoding/csv` で読める。コメント欄（`-k`）は改行を含みうるので選択しない

### 証拠データそのものの制約

- **切り詰めキャプチャ** — `-s <n>` で取得されたキャプチャはペイロードが存在せず、`follow_stream` / `extract_objects` は成立しない。`describe_workspace` の `snaplen` / `truncated` で事前開示する
- **キャプチャ取りこぼし** — 「パケットが無い」が「通信が無かった」なのか「取り逃した」なのかで結論が変わるため開示したいが、**`capinfos` は pcapng ISB の drop 数を出力しない**ことが実測で判明（tshark 4.0.17）。v1 では `dropped_packets` を提供せず、代替経路は Track D で検討する

---

## Discussion Log

### 発端

「tshark のようなパケット解析ツールセットを MCP で提供すればエージェントのインシデント / 障害分析に有用ではないか。Cowork のような強いサンドボックス下でもデータをやり取りするために、video-studio で使った `workspace_dir` 方式が使えるのではないか」という提起から開始。

### 初期の論点整理

- **tshark をそのまま露出してはいけない** ことを確認。ツール設計の本体は「tshark のラッパ」ではなく「アナリストの質問の型」をツールに落とすことだと合意
- workspace 方式には org 内に3つの流儀（`workspace_root` 毎回指定 / `workspace_dir` + manifest / `workspace_id` + `allowed_paths` + `/work`）があることを整理。pcap は「入力が既存かつ巨大、出力も大きい」ため単一の流儀では足りないと判断
- tshark の dissector が歴史的に CVE の温床であること、pcap が PII と認証情報の塊であることを懸念として提起
- バックエンド候補として Zeek を検討したが、display filter の共通語彙性を優先して tshark を選択

### 決定 1: コンテナ化（提起者）

「data-toolbox 方式の分析用コンテナを構成し、pcap のあるディレクトリを ro マウントしてコンテナ内の tshark で分析する。コンテナに取り込む tshark はイメージビルド時に固定化できるので、ローカルのバージョンに依存せずに済む」

この決定が3つの問題を同時に解決することを確認した:

1. tshark のバージョン固定（`-T fields` / `-z` の出力書式の揺れを排除）
2. dissector の CVE リスク（`network=none` + 非 root + cap-drop で隔離）
3. ライブキャプチャ問題の消滅（`network=none` のコンテナは原理的にキャプチャできない）

実コードを確認した結果、data-toolbox の `internal/workspace/podman.go` の `Mount` 構造体には **`ReadOnly` フィールドと `:ro` 付与が既に実装済み**（data-toolbox 本体は未使用）であることが判明。一方 `load_data` は**ホストファイルを `/work/_upload/` に物理コピー**していることも判明し、GB 級 pcap では論外かつ証拠の完全性も損なうため、ro マウントは data-toolbox 方式の単なる移植ではなくこの一点を改善した派生形になると整理した。

### 決定 2: インタラクションモデル（提起者）

「分析コンテナを立ち上げて待ち受けるのではなく、(1) pcap と `workspace_dir` を指定してワークスペースを生成（1 pcap に必ず1ワークスペース）、(2) 分析時はワークスペースとクエリ / フィルタを指定、(3) 結果が小さければ JSON で返却、大きければ `workspace_dir` 経由で JSON ファイル出力。出力の処理方法はエージェント側に任せる」

これを受けて、直前に推奨していた「永続コンテナ + `podman exec`」を**撤回**した。data-toolbox が永続コンテナを持つ理由は DuckDB がコンテナ内に状態を持つためであり、tshark は完全にステートレスなので永続化する価値がない、という分析による。ephemeral 化により orphan 検出 / teardown / `container_state` が不要になり、ワークスペースがサーバー再起動を跨いで生き残るのが無料になる。さらに**マウントを呼び出しごとに決められる**ため、直前に推奨していた「config で `evidence_root` を固定宣言」も不要になった。

出力契約については以下を追加した:

- 閾値は行数ではなく**バイト数**（ペイロード列付き100行 > フィールド10000行になり得るため）
- 大きい出力は単一 JSON 配列ではなく **JSONL**（部分読み可能、DuckDB が直接読む）
- インライン / ファイルで**レスポンス形状を変えない**
- **`matched` を常時返す**、ファイル出力時も **`sample` に先頭数行**を添える
- サイズとは直交する**時間の軸**が未検討であることを指摘し、非同期ジョブ（video-studio ADR-0003 流用）を追加

「1 pcap : 1 workspace」の唯一の穴としてリングバッファ分割キャプチャを挙げ、`mergecap` で1つの論理キャプチャに束ねる案を示したうえで、v1 は単一ファイルに絞り `pcap_paths: []` を additive に後付けする方針とした。

### 決定 3: lean イメージ + ペイロード抽出（提起者）

「tshark 単独イメージにする（DuckDB などは入れない）」「ペイロード抽出までしたほうが、エージェントが深堀り分析できるから必要」

lean イメージの帰結として **parquet 出力は不可能**になるため、前案の parquet を撤回し JSONL / CSV とした（DuckDB がどちらも読むため受け渡しは成立する）。Debian の `tshark` パッケージが `wireshark-common` に依存し `capinfos` / `editcap` / `mergecap` / `text2pcap` を自動同梱することも確認。

ペイロード抽出を MVP に含めたことで、セキュリティ設計が「あると良い」から「無いと壊れる」に変わる点を整理した。特に **`follow_stream` の戻り値は攻撃者が完全に制御するテキストがエージェントのコンテキストに直入りする経路**であり、「不審な通信を解析してほしい」が本来用途である以上、敵対的入力が例外ではなく通常運転になる。ノンス付き XML ラップ + 冒頭配置、抽出オブジェクトの defang、ログからのペイロード除外、レンジ読みの4点を同時実装の必須要件とした。

### 決定 4: メタ情報ツール（提起者）

「pcap のメタ情報を取得するようなものがあるといいかもしれない（パケット数や時間情報）」

当初は `create_workspace` の戻り値に含める設計だったが、ワークスペースが過去のセッションで作られている場合にメタ情報のためだけに作り直させるのは誤りであり、独立ツール `describe_workspace` とした。`create_workspace` 時に `capinfos` を1回実行してキャッシュしておけば、以降は JSON を読むだけで**コンテナを起動しない**（呼び出しコストが実質ゼロ）。

この指摘により、当初の `describe_capture` が**コストの異なる2つを混ぜていた**ことが判明した。分解した結果:

- メタ情報（無料） → 新設の `describe_workspace`
- プロトコル階層（フルパス） → `protocol_hierarchy` に改名（「安そうな名前なのに実はフルパス」という誤解を避けるため）
- top talkers → `list_conversations` が既に担当

ツール本数は増えなかった。併せて `snaplen` / `truncated` の開示（切り詰めキャプチャでペイロード抽出が空振りすることを**試す前に**知らせる）と `dropped_packets` の開示を必須項目とした。※後者は Track C の実測で `capinfos` が ISB drop を出力しないと判明し、v1 スコープから外した。

また、`export_table` は実体が「出力先とフォーマットを指定した `query_packets`」でしかなく、インライン / ファイルの切り替えはどのみちサイズで自動判定するため、`query_packets` に統合した。
