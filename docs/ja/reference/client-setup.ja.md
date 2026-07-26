# クライアント設定

> Date: 2026-07-26

## 前提

```bash
make build            # → dist/pcap-analyzer-mcp
make runtime-image    # tshark イメージをローカルビルド（初回のみ数分）
./dist/pcap-analyzer-mcp doctor
```

動くかどうかを最短で確かめるには `doctor` を使います。期待される出力:

```
  [ok  ] config                 using defaults (no config file given)
  [ok  ] podman                 podman version 6.0.2
  [ok  ] podman machine         running
  [ok  ] analysis image         localhost/pcap-analyzer-runtime:latest (...), expecting tshark 4.0.17
  [ok  ] mount (default shares) /Users
  ...
```

## サーバーの登録

**絶対パス**で指定してください。MCP クライアントは `~` を展開せず、`PATH` にも依存しません。

### Claude Code

```bash
claude mcp add pcap-analyzer -- /absolute/path/to/dist/pcap-analyzer-mcp serve
```

### Claude Desktop

macOS では `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "/absolute/path/to/dist/pcap-analyzer-mcp",
      "args": ["serve"]
    }
  }
}
```

### 設定ファイルを使う場合

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "/absolute/path/to/dist/pcap-analyzer-mcp",
      "args": ["serve", "--config", "/absolute/path/to/config.toml"]
    }
  }
}
```

`PCAP_ANALYZER_MCP_CONFIG` でも指定できます。設定は任意で、すべての値に実用的な
既定があるので、まずは設定なしで始めてください。

## キャプチャとワークスペースを置ける場所

macOS では podman が VM 内で動くため、**VM が共有しているパスしか読めません**。
既定では `/Users`、`/private/tmp`、`/var/folders` です。外付けディスクや
`/Volumes` 直下のキャプチャは、**到達可能な場所にコピーするまで解析できません**。

`doctor` はこれを推測しません。実際に read-only マウントを試して podman の答えを
そのまま報告します（`podman machine inspect` が共有パス一覧を公開していないため）。

`workspace_dir` も同じ制約を受けます。ホームディレクトリ配下が素直な選択です。

```
~/pcap-workspaces/
```

## 最初の一歩

サンプルを指してエージェントに開かせてみてください。

```
samples/mixed.pcapng を ~/pcap-workspaces の下にワークスペースとして開いて、
どんなプロトコルが流れているか教えて。
```

[`samples/README.md`](../../../samples/README.md) に 11 段階の graded
ウォークスルーがあり、各段階で何が返るべきかまで書いてあります。

## トラブルシューティング

| 症状 | 原因と対処 |
|---|---|
| 全呼び出しが `container_failed` | podman が動いていない。macOS なら `podman machine start` |
| `analysis image ... not built` | `make runtime-image` |
| キャプチャをマウントできない | VM の共有パス外にある。`/Users` や `/private/tmp` 配下へコピーし、`doctor` で確認 |
| 分単位かかりクライアントがタイムアウト | `async: true` を付けて `check_job` でポーリング。判断材料は `describe_workspace` の `packet_count` / `file_size` |
| `payload_unavailable_truncated_capture` | 小さい snaplen で取得されたキャプチャで、ペイロードが記録されていない。`query_packets` と `protocol_hierarchy` は使える。`list_conversations` は snaplen が transport ヘッダまで削っていると 0 件になる（ストリーム番号がそこにあるため）— 素の空リストではなく理由を返す |
| `job_not_found` | サーバーが再起動した。ジョブはインメモリなので、元のツールを再実行すればよい |
| 再ビルドしても反映されない | クライアントは登録時に起動したプロセスを保持し続ける。`make build` はディスク上のファイルを置き換えるだけで走行中のプロセスは変わらない。MCP サーバー（またはクライアント）を再起動する |
| 結果が足りない気がする | `matched` と `returned` を比べる。`matched` のほうが遥かに大きいなら、`limit` を上げるのではなく**フィルタを強める** |
| 呼び出しが長時間返らない | 実行は `[container.limits] timeout`（既定 30m）で打ち切られる。リクエストは直列処理なので、長い同期呼び出しは他をブロックする — 大きいキャプチャには `async` を使う |

### ログ

既定では stderr に出ます（多くのクライアントが拾います）。ファイルに残すには:

```toml
[log]
level = "debug"
file = "~/.local/state/pcap-analyzer-mcp/server.log"
```

起動時に 5 世代までローテートし、`0600` で書かれます。**パケットのペイロードは
どのレベルでもログに出ません。**

stdout には絶対にログを出さないでください。そこは JSON-RPC のチャネルであり、
1 行混ざるだけでプロトコルが壊れます。

## data-toolbox-mcp との併用

`query_packets` に `limit: 0` を渡すと、該当パケット全件をワークスペースへ JSONL
で書き出します。DuckDB がそのまま読める形式です。SQL をかけたい場合は
[data-toolbox-mcp](https://github.com/nlink-jp/data-toolbox-mcp) も登録し、
ワークスペースディレクトリを向こうの `allowed_paths` に加えてください。

**渡す前にフィルタで絞ること。** data-toolbox の `load_data` は渡されたファイルを
コピーするので、大きいキャプチャの無絞りエクスポートを渡すと全部複製されます。

## 関連

- [アーキテクチャ](architecture.ja.md) — 信頼境界・データフロー・セキュリティモデル
- [ADR](../adr/) — 各設計判断とその代償
