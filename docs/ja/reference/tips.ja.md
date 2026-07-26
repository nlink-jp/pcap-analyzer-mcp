# 実践 Tips — 調査の進め方

> Date: 2026-07-26

[`samples/README.md`][samples] が合成キャプチャでツールの使い方を
11 段階で教えるのに対し、こちらは**実際のキャプチャを調査するときの型とレシピ**を扱う。

本ページのフィルタは**すべて実キャプチャで動作を確認したもの**である（2026-07-26）。
検証に使った公開演習キャプチャ:

| 出典 | 使った範囲 |
|---|---|
| Unit 42「Wireshark を使った pcap からのオブジェクト抽出」演習 pcap 5 本 | HTTP / SMB / SMTP / FTP |
| [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK) | Kerberos / DCERPC / DNS トンネリング / 横展開 |
| [chrissanders/packets](https://github.com/chrissanders/packets)（Practical Packet Analysis 教材） | DNS ゾーン転送 / スキャン / TCP 異常 |

裏が取れなかったレシピは載せていない。

## 調査の型

| 順 | ツール | 目的 |
|---|---|---|
| 1 | `describe_workspace` | 規模と素性。コンテナを起動しないので実質無料 |
| 2 | `protocol_hierarchy` | **何が入っているか。フィルタを書く前に見る** |
| 3 | `list_conversations` | 誰と誰が話したか、`follow_stream` 用のストリーム番号 |
| 4 | `query_packets` | 絞り込みと事実の抽出。ここが主戦場 |
| 5 | `follow_stream` / `extract_objects` | 深堀りとファイル回収 |

### 2 を飛ばしてはいけない理由

SMB のキャプチャで `smb2.filename` を指定したら `matched: 0` が返った。
`protocol_hierarchy` を見ると `smb` が 604 フレームなのに対し `smb2` は 85 フレームで、
目的の転送は **SMB1** だった。`smb.file` に変えたら即座に命中した。

**同じ概念でもプロトコル世代でフィールド名が違う。** `matched: 0` は「存在しない」
ではなく「フィールド名が違う」ことがある。先に階層を見れば 1 回で済む。

## プロトコル別レシピ

### HTTP — 何がダウンロードされたか

まず要求の一覧。これだけで「どこから何を取ってきたか」がほぼ分かる。

```
query_packets(filter: "http.request",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "http.host", "http.request.method", "http.request.uri"])
```

次に応答側で中身の型を見る。`http.request_in` が要求のフレーム番号を指すので、
突き合わせができる。

```
query_packets(filter: "http.response",
              fields: ["frame.number", "http.response.code", "http.content_type",
                       "http.content_length", "http.request_in"])
```

`application/x-msdownload` や `application/msword` が見えたら実行ファイル・文書の
ダウンロードである。そこまで分かってから `extract_objects(protocol: "http")` に進む。

フィッシングの調査では投稿先も見る。

```
query_packets(filter: "http.request.method == \"POST\"",
              fields: ["http.host", "http.request.uri",
                       "urlencoded-form.key", "urlencoded-form.value"])
```

### SMB — 共有経由のファイルと横展開

SMB1 か SMB2 かを確認してからフィールドを選ぶ（上記の理由）。SMB1 の例:

```
query_packets(filter: "smb.file contains \".exe\" and smb.cmd == 0xa2",
              fields: ["frame.number", "ip.src", "ip.dst", "smb.file"])
```

`smb.cmd == 0xa2`（NT Create AndX）を付けるのが要点である。付けないと同じファイルへの
読み書き全部が並んで結果が膨れる。オープン時の 1 往復だけに絞れる。

**ファイル抽出で終わらせない。** 書き込んだ後に何をしたかは `svcctl` に出る。

```
query_packets(filter: "svcctl",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "svcctl.servicename", "svcctl.displayname",
                       "svcctl.binarypathname"])
```

`binarypathname` に置いたばかりの `.exe` が入っていれば、**サービス登録による横展開と
永続化**である。これは「どのファイルが転送されたか」より価値の高い所見であることが多い。

⚠️ **型付きフィールドが空のこともある。** psexec のキャプチャでは `svcctl.servicename` /
`displayname` / `binarypathname` が 18 件すべて空で、`_ws.col.Info` にだけ
`OpenSCManagerW request` → `OpenServiceW` → `StartServiceW` と操作名が入っていた。
**`_ws.col.Info` を必ず一緒に取ること**（後述の「結果の読み方」参照）。

ホスト名は NBNS の登録要求が手軽である。

```
query_packets(filter: "nbns.flags.response == 0 and nbns.flags.opcode == 5",
              fields: ["ip.src", "nbns.name"])
```

`QUINN-OFFICE-PC<00>` のように NetBIOS サフィックス付きで返る。IP だけの所見に
ホスト名を付けられる。

### SMTP — スパムボット化した端末

```
query_packets(filter: "smtp.req.command == \"MAIL\" or smtp.req.command == \"RCPT\"",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "smtp.req.command", "smtp.req.parameter"])
```

送信元が 1 つの内部 IP に集中し、宛先が外部の MX に散っていれば感染端末である。
本文とヘッダは `extract_objects(protocol: "imf")` で `.eml` として取れる。

**通数は `matched` で数える。** メールを全部取り出して数える必要はない。

### FTP — 制御チャネルだけで大半が分かる

```
query_packets(filter: "ftp.request.command or ftp.response.code",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "ftp.request.command", "ftp.request.arg",
                       "ftp.response.code", "ftp.response.arg"])
```

これ 1 回で以下が揃う。

| 見るもの | 意味 |
|---|---|
| `USER` / `PASS` | **平文の認証情報**。FTP なので当然そうなる |
| `RETR` / `STOR` | 取得か送出か。送出はデータ持ち出しの疑い |
| `SIZE` への `213` 応答 | 転送サイズ（バイト） |
| `227` | パッシブモードのデータ接続先 |

⚠️ `extract_objects(protocol: "ftp-data")` は**バイナリ `RETR` を書き出さない**。
`.exe` は 1 件も返らない。上のクエリでファイル名とサイズは取れるので、多くの調査は
それで足りる。詳細は[実地ノート](field-notes.ja.md)。

### DNS — トンネリングとゾーン転送

**TXT レコードによる C2 / トンネリング。** 同じ親ドメインに対する TXT 問い合わせが
大量に出るのが signature である。

```
query_packets(filter: "dns.qry.type == 16",
              fields: ["frame.number", "ip.src", "ip.dst", "dns.flags.response",
                       "dns.qry.name", "dns.qry.name.len", "dns.count.labels"])
```

実測例では 301 パケットのキャプチャで TXT が 114 件、名前は
`l.1.ns.example.tld` → `l.2.ns.example.tld` → `l.3...` と**左端ラベルだけが連番で
変化**していた。親ドメインが 1 つに固定され、ラベル数と名前長が揃っているのが特徴である。

`dns.qry.name.len` と `dns.count.labels` を必ず取ること。**長い名前・多いラベル・
1 ドメインへの集中**の 3 点がトンネリングの目印になる。

**ゾーン転送。** タイプ 252（AXFR）が通っていれば、内部の DNS レコードが丸ごと
持ち出されている。

```
query_packets(filter: "dns.qry.type == 252",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "dns.qry.name", "dns.count.answers"])
```

応答側の `dns.count.answers`（実測例では 21）が、持ち出されたレコード数である。

### Kerberos — パスワードスプレーとユーザー列挙

**1 回のクエリで、存在するアカウント・失敗・成功がすべて分かる。**

```
query_packets(filter: "kerberos",
              fields: ["frame.number", "ip.src", "ip.dst", "kerberos.msg_type",
                       "kerberos.CNameString", "kerberos.realm",
                       "kerberos.error_code", "kerberos.etype"])
```

`kerberos.msg_type` の 10 が AS-REQ、11 が AS-REP、30 が KRB-ERROR である。
攻撃の判定はエラーコードで行う。

| `error_code` | 意味 | 攻撃者にとって |
|---|---|---|
| 6 | `C_PRINCIPAL_UNKNOWN` | **そのユーザーは存在しない** |
| 25 | `PREAUTH_REQUIRED` | **ユーザーは実在する**（列挙成功） |
| 24 | `PREAUTH_FAILED` | 実在するがパスワードが違う |
| 52 | `RESPONSE_TOO_BIG` | TCP へ再試行させられただけ |

**成功はエラーではなく `msg_type == 11`（AS-REP）で見つける。** 実測例では 33
フレーム中、大量の AS-REQ に対し 6 と 25 のエラーが並ぶ中で、最後に 1 件だけ
AS-REP が返っていた。その `CNameString` が**スプレーで陥落したアカウント**である。

**暗号化タイプの格下げ。** AES（`etype` 17 / 18）が標準の環境に RC4（`etype` 23）が
混在していたら、skeleton key や overpass-the-hash を疑う。

```
query_packets(filter: "kerberos.etype == 23",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "kerberos.msg_type", "kerberos.CNameString"])
```

環境の既定を先に確認すること。RC4 が普通の環境なら、これは所見にならない。

### DCERPC / RPC — 列挙とリモート実行

**エンドポイントマッパーへの総当たりは偵察である。**

```
query_packets(filter: "epm",
              fields: ["frame.number", "ip.src", "ip.dst", "_ws.col.Info", "epm.uuid"])
```

`_ws.col.Info` に `Lookup response, Service:CLIPSVC Default RPC Interface` のように
**サービス名まで解決されて入る**。実測例では 700 パケット中 698 件が epm で、1 台の
ホストが全 RPC インターフェースを列挙していた。件数そのものが所見になる。

**`dcerpc.opnum` は単体では意味を持たない。** opnum は インターフェースごとの
連番なので、BIND がキャプチャに含まれていないと tshark は名前を解決できない。実測では
DCSync のキャプチャで `drsuapi` が `matched: 0` となり、`dcerpc` では
`opnum: 3` という数字しか得られなかった。BIND が写っていないキャプチャでは、
opnum から操作名を断定しないこと。

### スキャンと TCP の異常

**開いているポートだけを一撃で出す。** スキャン側の SYN を全部眺める必要はない。

```
query_packets(filter: "tcp.flags.syn == 1 and tcp.flags.ack == 1",
              fields: ["frame.number", "ip.src", "tcp.srcport", "ip.dst"])
```

SYN-ACK を返したポートだけが並ぶ。実測例では 2,011 パケットのスキャンに対して
返ってきたのは 12 件、実質 3 ポート（22 / 53 / 80）だけだった。

**再送・重複 ACK・ゼロウィンドウはまとめて拾える。**

```
query_packets(filter: "tcp.analysis.flags",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "_ws.col.Info", "tcp.time_delta"])
```

`tcp.time_delta` を並べると再送間隔が見える。実測例では 0.206 → 0.6 → 1.2 → 2.4 →
4.8 秒と**指数バックオフ**しており、宛先が応答を返していないことが一目で分かる。

## 結果の読み方

- **`matched` と `returned` を必ず比べる。** `matched` が大きいのに `returned` が
  上限で頭打ちなら、`limit` を上げるのではなく**フィルタを強める**。件数を知りたい
  だけなら `matched` がその答えである
- **`_ws.col.Info` を保険として足しておく。** これは Wireshark の Info 列そのもので、
  **型付きフィールドが空でも解決済みの操作名が入っていることがある。** psexec の
  キャプチャでは `svcctl.*` が全件空だったのに Info には `OpenSCManagerW request` /
  `StartServiceW request` と入っていた。`epm` のサービス名や TCP の
  `[TCP Retransmission]` も同様である。**`matched` が 0 でないのに全フィールドが空の
  ときは、まず Info を見る**
- **`fields` は必要な分だけ指定する。** 多いフィールド × 多い行は結果を肥大させ、
  クライアント側で扱いにくくなる。実際に `smb.file` と `smb2.filename` を同時指定して
  全 SMB パケットを引いたら 6 万文字を超えた
- **フィールド名を間違えると `invalid_arguments` が返り、`details.invalid_fields` に
  どれが悪いかが入る。** 推測で直さずそこを見る
- **`limit: 0` で全件を JSONL に落とせる。** SQL をかけたいときは data-toolbox-mcp へ
  渡す（[クライアント設定](client-setup.ja.md)参照）
- **大きいキャプチャには `async: true`。** 判断材料は `describe_workspace` の
  `packet_count` と `file_size`。サーバーはリクエストを直列処理するので、長い同期呼び出しは
  他をブロックする

## 抽出したファイルの扱い

- 返るのは**メタデータとパスだけ**で、バイト列は返らない。これは仕様である
- ファイルは `<sha256>.bin`（0600・実行ビットなし）で保存される。元の名前はマニフェスト側にある
- **多くの場合 SHA-256 だけで調査は終わる。** 中身を開かずに脅威情報へピボットできる
- ⚠️ **本物のマルウェアを扱うと AV が書き込み途中のファイルを隔離することがある。**
  そのオブジェクトは `operation not permitted` を理由に `skipped` へ入り、ハッシュも
  取れない。ツールの不具合ではなく、他のオブジェクトは通常どおり返る。回収のために
  AV 除外を設定する前に[実地ノート](field-notes.ja.md)を読むこと — 有効だが保護を外す

## 他の MCP サーバーへのピボット

抽出した値はそのまま同シリーズのツールに渡せる。

| 得た値 | 渡す先 |
|---|---|
| ファイルの SHA-256 | 脅威情報（VirusTotal 等） |
| 接続先 IP | `abuse-lookup` / `asn-lookup` / `tor-exit-lookup` |
| ドメイン | `whois-lookup` / `doh-lookup` |
| URL | `urlscan-lookup`（既定は private スキャン） |
| MAC アドレス | `mac-lookup` |

## ハマりどころ早見表

| 症状 | 対処 |
|---|---|
| `matched: 0` なのに存在するはず | プロトコル世代違い（`smb.` と `smb2.`）。`protocol_hierarchy` で確認 |
| `matched` は 0 でないのに全フィールドが空 | 型付きフィールドが埋まらないケース。`_ws.col.Info` を足す |
| `dcerpc.opnum` が数字のまま名前にならない | BIND がキャプチャに含まれていない。opnum から操作名を断定しない |
| 結果が大きすぎて扱えない | `fields` を減らす。フィルタを強める。`limit: 0` でファイルに落とす |
| `invalid_arguments` | `details.invalid_fields` を見る |
| `extract_objects` が `operation not permitted` | ホストの AV。[実地ノート](field-notes.ja.md) |
| `ftp-data` で `.exe` が取れない | tshark の制約。制御チャネルのクエリで代替 |
| `payload_unavailable_truncated_capture` | snaplen が小さくペイロードが記録されていない |
| 呼び出しが返らない | `async: true` を使う |

## 関連

- [サンプルキャプチャ][samples] — 合成キャプチャでの 11 段階ウォークスルー
- [実地ノート](field-notes.ja.md) — 実マルウェアを扱うときの AV の挙動と ftp-data の制約
- [クライアント設定](client-setup.ja.md) — 登録方法とトラブルシューティング

[samples]: ../../../samples/README.md
