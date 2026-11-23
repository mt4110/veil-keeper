# 任意の隔離 VM で再現する

B と C はそれぞれ破棄可能な QEMU/KVM guest で試します。guest の用意は任意で、同梱の systemd 定義と Rust バイナリだけを持ち込みます。旧記録の出力形式に合わせるため、nftables 1.1.7 と libnftnl 1.3.2 を使用します。別バージョンで証拠形式が異なると、判定器は拒否します。

1. 専用の little-endian Linux guest に、systemd、cgroup v2、IPv4/IPv6 loopback、nf_tables と nft_socket を用意します。B と C は個別に初期状態から起動します。実験時の QEMU 引数は `-nic none` を使い、他のネットワークデバイス、ホスト共有、デバイスパススルーを外します。コンソールは guest に限定します。
2. Rust バイナリを guest 用に `cargo build --release --locked` でビルドし、オフラインで guest の `/usr/local/bin/veil-keeper` に root 所有・書換え不可で配置します。`systemd/` のユニットを guest の `/etc/systemd/system/` に導入します。試験用 UID/GID 19101 は guest で専用に予約します。
3. B では guest の `/etc/hostname` と実際のホスト名を `veil-cgroup-b` にし、kernel cmdline に `keeper.cgroup_b=1` を加えて起動します。C の対応する値は `veil-cgroup-c` と `keeper.cgroup_c=1` です。ルールセットは空であることを guest から確認します。
4. guest の root コンソールで `systemctl start keeper-cgroup-b.service` または `systemctl start keeper-cgroup-c.service` を一度だけ実行します。ユニットがそれぞれの `verify` を起動します。結果は journal と guest の `/run/keeper-b/report.json` または `/run/keeper-c/report.json` に残ります。再試行は初期状態から行います。
5. guest 内で `veil-keeper check b /run/keeper-b/report.json` または `veil-keeper check c /run/keeper-c/report.json` を実行します。証拠の内部整合性を判定します。別環境で判定する場合は読み取り専用メディアで必要なファイルだけを持ち出します。生のレポートに含まれる boot ID、PID、実測の環境値はそのまま公開しないでください。
6. 終了・失敗のいずれでも guest をシャットダウンして破棄し、再実行には初期状態を使います。エラー時には試験用テーブルの削除を試みます。強制停止で中断した guest はそのまま再利用しません。

B は IPv4/IPv6 × TCP、未接続 UDP、接続済み UDP × 7 条件の 42 phase です。起動直後・子・再起動、対象外、誤 slice、継承ソケット、移動前作成ソケットを観測します。ルールは counter-only です。

C は同じ 6 通信グループについて、未適用・適用中・解除後・誤 slice の 11 段階を確認します。適用中の拒否は未受信、対象 DROP カウンタ、同じ受信器での前後の疎通、対象内の前後の許可通信が揃ったグループで判定します。接続待ち期限と Linux カーネルから得た errno はレポートで区別します。
