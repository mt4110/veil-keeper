# veil-keeper

> 研究用・ポートフォリオ（オンデマンド専用、本番利用非推奨）
>
> 隔離環境での検証と学習を目的とします。本番の防御手段としては使わないでください。ルール適用は隔離 VM 内の明示サブコマンドに限ります。未確認の結果は未確認と表示します。

systemd の専用 cgroup と nftables の `socket cgroupv2` による出口制御を、未適用の状態で診断し、隔離 Linux VM で選別・許可・拒否・解除を検証する研究用ハーネスです。Linux の cgroup v2、nftables、systemd の動作を学びたいエンジニアを対象としています。

## 診断

`rust-toolchain.toml` で Rust 1.100.0 を指定しています。rustup から起動した Cargo と CI はこの指定を使います。

```sh
cargo build --locked
./target/debug/veil-keeper
./target/debug/veil-keeper plan tests/fixtures/e1-cgroup-request.json tests/fixtures/e1-cgroup-snapshot.json
```

引数なしの preflight は Linux で systemd、nft、cgroup v2、カーネルの情報を読み取ります。終了 0 は次の診断に進める候補を意味します。カーネルの `socket cgroupv2` 実動作は未確認のままです。Linux 以外では外部コマンドを起動する前に終了します。

`plan` は JSON の申告内容を照合し、未適用の結果を標準出力に返します。対象は起動前に固定した専用 slice 以下で生成される TCP/UDP ソケットです。申告の出所、実環境の適合性、強制の結果はすべて未確認です。旧 UID 方式では実観測から proc 全体の在籍を証明できず、候補生成を止めました。

任意の `--report FILE` で新規ファイルに同じ JSON を保存できます。出力先の親ディレクトリは自分または root が所有し、グループ・その他から書き込めない実ディレクトリを指定してください。既存ファイルと symlink は保全されます。

## 隔離 VM 実験

`verify b` はカウンタだけで選別を調べます。`verify c` は許可、拒否、解除後の復帰を検証します。いずれも任意の専用 guest を必要とします。セットアップ、採取、純粋な判定器 `check b|c REPORT` の手順は [隔離 VM 実験](experiments/README.md) にあります。診断と単体テストは VM なしで実行できます。

Rust 版は NIC のない aarch64 QEMU guest で、B の42フェーズと C の全6グループ・66試行を通過しました。C は IPv4/IPv6 の TCP・未接続 UDP・接続済み UDP で、許可・拒否・解除後の復帰を確認しました。UDP の送信ソケットを loopback に明示 bind し、受信側と厳密に照合しています。別構成での再現は未確認です。 [実験結果と再現課題](docs/C-UDP-IPV6.md)

## 既存手段

| 手段 | できることと本ハーネスの範囲 |
| --- | --- |
| [systemd のリソース制御](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) | `IPAddressAllow=` / `IPAddressDeny=` はユニットごとに IP アドレス・範囲を制御できます。255 以降の `NFTSet=` は cgroup ID などを nftables set に同期します。ここでは専用 slice のポート条件を含むオフライン診断と証拠照合に絞ります。 |
| [systemd-cgroup-nftables-policy-manager](https://github.com/mk-fg/systemd-cgroup-nftables-policy-manager) | systemd ユニットに応じて cgroup のルールを更新します。ここでは単発の隔離 VM 試験を扱います。 |
| [Tetragon](https://github.com/cilium/tetragon/) | eBPF による実行時観測と強制を提供します。ここでは固定した nftables セレクタを検証します。 |
| [OpenSnitch](https://github.com/evilsocket/opensnitch/) | 対話型のアプリケーションファイアウォールを提供します。ここでは明示的に起動する CLI で診断します。 |

## 検証で得たこと

1. nftables 1.1.7 の JSON では cgroup ID がパスとして表示され、ancestor level が省略される場合があります。テキストで level を、netlink デバッグ出力で数値 ID を照合します。
2. `meta l4proto` は JSON で TCP が整数 6、UDP が整数 17 になる場合があります。判定器は整数を要求します。
3. TCP の `ETIMEDOUT` や接続待ち期限だけで拒否とは判定しません。許可と対象外の送達、拒否時の未受信と該当 DROP カウンタだけの増加、拒否後の疎通をまとめて確認します。
4. cgroup への事後移動や外部で開いたソケットの継承では、対象 cgroup による選別から外れる場合があります。診断では持ち込み FD を対象範囲から外します。

## 開発時の依存スキャン

OSV-Scanner 2.x を PATH に置き、このリポジトリで `git config --local core.hooksPath .githooks` を実行すると、Git の pre-commit フックが有効になります。`Cargo.toml` または `Cargo.lock` のステージ済み変更があるときに、コミット対象の `Cargo.lock` を OSV に照会し、脆弱性の検出時や検査の失敗時はコミットを止めます。

[経緯](docs/HISTORY.md) · [署名付きリリース](docs/RELEASE.md) · [MIT](LICENSE)
