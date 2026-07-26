# ADR-0004: 1 pcap : 1 workspace と read-only マウント

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Generalises to: なし

---

## Context

エージェントと MCP サーバーの間で、解析対象 pcap と解析成果物をどう受け渡すかを決める必要がある。org 内には既に 3 つの流儀が存在する。

| 流儀 | 例 | 向き |
|---|---|---|
| `workspace_root` を呼び出しごとに渡す | asn-lookup / abuse-lookup | 大きい結果のファイル出力 |
| `workspace_dir` + manifest | voice-studio-mcp / video-studio-mcp | 入力素材の staging |
| `workspace_id` + `allowed_paths` + `/work` | data-toolbox-mcp | 双方向 |

pcap は他のどれとも条件が異なる。**入力が既存かつ巨大（GB 級）で、出力も大きい。**

移植元 data-toolbox-mcp の `load_data` は、`allowed_paths` 検査を通したホストファイルを **`/work/_upload/` に物理コピー**してからコンテナに読ませる（`internal/tools/load_data.go`）。CSV では妥当だが、GB 級 pcap では次の 2 点で受け入れられない。

- ディスクと時間の無駄が大きい
- **証拠原本を複製する**こと自体が IR の作法として望ましくない

また、複数の pcap を 1 つのワークスペースに同居させると、出力ファイルがどのキャプチャ由来か曖昧になり、証跡としても破綻する。

## Decision

### 1 pcap : 1 workspace

**ワークスペースは 1 つのキャプチャに 1 対 1 で対応する。** `create_workspace(pcap_path, workspace_dir)` がワークスペースを生成し、以後すべての解析ツールは `workspace_id` を指定して呼ぶ。

ディスク配置:

```
<workspace_dir>/
└── <workspace_id>/
    ├── meta.json        # sha256 / capinfos 結果 / tshark 版数 / image digest
    └── work/            # コンテナ /work へ rw マウント
        ├── tmp/         # tshark の TMPDIR
        ├── out/         # クエリ結果 (JSONL/CSV)
        └── out/objects/ # extract_objects の出力（untrusted）
```

`workspace_id` の構文制約は `^[a-zA-Z0-9_-]{1,64}$`（パストラバーサル防御、コンテナ名の安全性）。

### read-only マウント、複製しない

`create_workspace` に渡された pcap の**親ディレクトリを `/evidence` に read-only でマウント**する。pcap をワークスペースにコピーすることはしない。

```
-v <pcap の親ディレクトリ>:/evidence:ro
-v <workspace>/work:/work
```

ADR-0002 でコンテナを呼び出しごとに起動すると決めたため、マウントは呼び出しごとに決定できる。**config で固定の evidence root を宣言する必要はない。**

### `workspace_dir` は呼び出しごとにエージェントが指定する

config ではなくツール引数として受け取る。エージェントは自分の書き込み可能領域を知っているが、config は知らないため。asn-lookup / abuse-lookup の `workspace_root` と同じ流儀。

### `allowed_paths` はガードレールであってサンドボックス境界ではない

`allowed_paths` は残すが、位置づけを変える。ephemeral コンテナではマウントを呼び出しごとに決められるため、`allowed_paths` は**マウント制約ではなくポリシー検査**（`ResolveAndCheck` 相当、symlink 解決後の判定）になる。既定は空 = 無制限とする。Cowork で毎回 config を編集させると摩擦になるためである。

### 証跡の記録

`create_workspace` 時に以下を一度だけ実行し、`meta.json` にキャッシュする。

- 入力 pcap の **SHA-256**
- `capinfos -M` の結果（パケット数 / 時間範囲 / snaplen / drop 数 など）
- 使用した **tshark バージョンとイメージ digest**

以降 `describe_workspace` はこの JSON を読むだけで、コンテナを起動しない。

### 分割キャプチャ

リングバッファ由来の分割キャプチャ（`cap_00001_*.pcap` …）は、ファイル集合で 1 つの論理キャプチャを成す。**v1 は単一ファイルのみ受け付ける。** 将来 `pcap_paths: []` を additive に追加し、`mergecap` で `<workspace>/work/merged.pcapng` に束ねることで「1 workspace : 1 論理キャプチャ」のルールを保つ。この場合のみ複製が発生するが、分割キャプチャでは避けようがない。

## Consequences

**Positive:**

- **GB 級 pcap を複製しない。** ディスクも時間も消費せず、証拠原本の完全性が保たれる
- ro マウントにより、dissector の脆弱性を突かれても**原本が改変されない**
- ワークスペースと証拠が 1 対 1 に対応するため、出力ファイルの由来が常に一意に定まる。`meta.json` の SHA-256 が chain of custody の基点になる
- `describe_workspace` がコンテナ不要になり、最も高頻度なメタ情報確認のコストがゼロになる
- config に固定パスを宣言させないため、Cowork のような環境でセットアップ摩擦が生じない

**Negative:**

- **pcap の親ディレクトリごと ro でマウントするため、同一ディレクトリ内の兄弟ファイルもコンテナから見える。** 単一ファイルの bind mount のほうが blast radius は小さいが、macOS の virtiofs 越しの挙動が未検証であるため、既定は親ディレクトリ ro とする（Phase 1 Open Question）
- `allowed_paths` の既定を無制限にしたため、**設定しない限りサーバーはホスト上の任意の読み取り可能なファイルを pcap として開こうとする。** ローカル単独利用を前提とした割り切りであり、共有環境に置く場合は必ず設定する必要がある
- 1 pcap : 1 workspace の制約により、2 つのキャプチャを比較する分析ではエージェントが 2 つのワークスペースを作り、結果の突き合わせを自ら行うことになる
- v1 では分割キャプチャを扱えない

## See also

- ADR-0002: 呼び出しごとの ephemeral コンテナ
- ADR-0005: 出力契約
- ADR-0007: ペイロード安全性（`out/objects/` の扱い）
