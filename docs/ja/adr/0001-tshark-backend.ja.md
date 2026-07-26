# ADR-0001: 解析バックエンドに tshark を選択する

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Generalises to: なし

---

## Context

pcap / pcapng を解析するバックエンドとして、現実的な選択肢は 2 つある。

**tshark**（Wireshark CLI）:

- display filter（`ip.addr == 10.0.0.1 && tcp.flags.syn == 1 && !tcp.analysis.retransmission`）が、ネットワーク解析における事実上の共通語彙になっている
- 3000 を超える dissector を持ち、独自プロトコルまで解釈できる
- Debian では `tshark` パッケージ 1 本で導入でき、依存の `wireshark-common` が `capinfos` / `editcap` / `mergecap` / `text2pcap` も連れてくる
- 出力が非構造的で、`-T fields` / `-T ek` のフィールド名や `-z` 統計の書式がバージョン間で揺れる

**Zeek**:

- `conn.log` / `dns.log` / `http.log` / `ssl.log` が最初から表形式で出るため、そのまま SQL に流せる。IR の現場で標準的に使われるログセットでもある
- 一方でインストールが重く、スクリプトフレームワークまで含めると本プロジェクトの「lean な子プロセス外部依存」という方針から外れる

本プロジェクトの一次利用者は LLM エージェントである。エージェントは display filter の構文を既に知っている（学習データに大量に含まれる）が、Zeek のログスキーマやスクリプト言語には相対的に不慣れである。この非対称性は、ツールの初回成功率に直接効く。

## Decision

**v1 のバックエンドは tshark のみとする。**

- 解析はすべてコンテナ内の tshark / capinfos に委譲する（ADR-0003）
- `query_packets` / `list_conversations` の絞り込み表現として **display filter 文字列をそのままエージェントから受け取り、tshark に渡す**
- Zeek は却下ではなく **deferred** とする。将来必要になった場合は、`protocol_hierarchy` / `list_conversations` のような「集計系」ツールの実装を Zeek ログ由来に差し替える余地を残す

## Consequences

**Positive:**

- エージェントが既に持っている display filter の知識をそのまま活用できる。ツール説明で構文を教え込む必要がない
- 単一パッケージで `capinfos`（メタ情報）/ `mergecap`（分割キャプチャ結合）/ `editcap` まで揃うため、追加の依存を増やさずに機能を広げられる
- Wireshark の dissector カバレッジが、独自プロトコルや暗号化前のアプリ層まで解析できる射程を与える

**Negative:**

- **display filter は tshark 固有の構文であり、これをツールの引数に据えた時点で API が tshark に強く結合する。** 将来 Zeek を第 2 バックエンドとして導入する場合、`query_packets(filter=...)` の引数互換は取れない。現実的には「同一ツールのバックエンド差し替え」ではなく「Zeek 由来の別ツール追加」になる公算が高い。この ADR はその可能性を承知のうえで、いま得られる初回成功率を優先する判断である
- tshark のバージョン差が出力書式に出る問題は残る。これは ADR-0003（コンテナでの版数固定）で別途対処する
- Zeek が提供する「セッション単位の意味づけ済みログ」は自前で組み立てる必要がある。`list_conversations` がその役割を部分的に担う

## See also

- ADR-0003: tshark 単独 lean イメージと digest pin
- RFP §3 Design Decisions
