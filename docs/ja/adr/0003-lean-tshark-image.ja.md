# ADR-0003: tshark 単独の lean イメージと digest pin

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Generalises to: なし

---

## Context

解析をコンテナ内の tshark に委譲する（ADR-0001 / ADR-0002）にあたり、ランタイムイメージに何を含めるかを決める必要がある。

第一の動機は **tshark のバージョン固定**である。`-T fields` / `-T ek` のフィールド名、`-z` 統計の書式、`--export-objects` の対応プロトコルはいずれも tshark のバージョンで変わる。ホストにインストールされた tshark に依存すると、利用者のマシンごとに出力が変わり、パーサが壊れる。

第二の動機は **隔離**である。Wireshark の dissector は歴史的に脆弱性の温床であり、攻撃者が制御する pcap を解析する行為そのものにリスクがある。

イメージ構成の選択肢は 2 つあった。

- **A. lean（tshark のみ）** — 解析結果は JSONL / CSV でホストに出し、SQL 集計は data-toolbox-mcp に委ねる
- **B. 同居（tshark + Python + DuckDB）** — 1 コンテナ内で tshark → 表形式 → SQL まで完結させる

B は受け渡しの摩擦がゼロになる代わりに、data-toolbox-mcp と重複する機能を抱え込むことになる。

## Decision

**A（lean）を採用する。イメージには tshark とその依存のみを含め、Python / DuckDB / pyarrow は入れない。**

```dockerfile
FROM debian:12-slim@sha256:...           # digest pin

# wireshark-common は debconf で「非 root にキャプチャさせるか」を対話質問する。
# 非対話化し、setuid dumpcap は明示的に無効化する（キャプチャは一切行わない）。
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
      | debconf-set-selections \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 pcap
USER 1000:1000
ENV TMPDIR=/work/tmp
WORKDIR /work
```

- **ベースイメージは digest で pin する。** `debian:12-slim` のような可動タグには依存しない
- **使用したイメージ digest と tshark バージョンを、ワークスペースのメタデータに記録する**（ADR-0004）。「どのバージョンの tshark で得た結果か」が後から辿れることは、証跡としても、dissector 由来の解釈差を疑うときにも効く
- Dockerfile は `go:embed` でバイナリに同梱し、`build-runtime` サブコマンドでローカルビルドする。レジストリへの push は行わない（data-toolbox-mcp ADR-0005 と同方針）
- `describe_runtime` ツールでイメージ digest / tshark バージョン / 対応 export-object プロトコルを開示し、Dockerfile とのドリフトをテストで検出する

エクスポート形式は **JSONL / CSV** とする。

## Consequences

**Positive:**

- **イメージサイズが 150〜250MB に収まる見込み**（data-toolbox-mcp の 882MB と比べて大幅に軽い）。`build-runtime` の所要時間も短い
- **`capinfos` / `editcap` / `mergecap` / `text2pcap` が自動的に同梱される。** `tshark` パッケージが `wireshark-common` に依存するため、メタ情報取得（`capinfos`）も分割キャプチャ結合（`mergecap`）も追加インストール無しで実現できる
- **setuid dumpcap を無効化し非 root で実行することで、キャプチャ能力を持たないイメージになる。** ライブキャプチャがスコープ外であることが、方針ではなく構成で保証される
- data-toolbox-mcp と機能が重複しない。責務分割が明快になる

**Negative:**

- **parquet を書けない。** コンテナ内に parquet writer が存在せず、Go 側に追加するのは lean の趣旨に反する。エクスポートは JSONL / CSV に限定される。data-toolbox-mcp の `load_data` は DuckDB 経由でどちらも読むため受け渡しは成立するが、大規模データでは parquet より非効率である
- **SQL 集計には別サーバー（data-toolbox-mcp）が必要になる。** 利用者は 2 つの MCP サーバーを設定することになる。さらに data-toolbox の `load_data` はホストファイルを `/work/_upload/` に物理コピーするため、巨大なエクスポートを渡すと複製が走る。運用上は「エクスポートはフィルタで絞ってから渡す」ことが前提になる
- digest pin は tshark のセキュリティ更新を自動では取り込まない。イメージ更新は明示的な作業になる（バージョン固定の代償として受け入れる）
- Debian の tshark バージョンは Wireshark の最新版に追随しない。最新 dissector が必要な場合は別途検討が要る

## See also

- ADR-0001: 解析バックエンドに tshark を選択する
- ADR-0002: 呼び出しごとの ephemeral コンテナ
- 移植元: data-toolbox-mcp ADR-0005（ローカルビルド + `go:embed` Dockerfile）
