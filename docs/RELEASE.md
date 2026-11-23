# 初回から署名付きでリリースする

対象のコミット、バージョン、対応プラットフォームを確定し、クリーンなチェックアウトから `cargo test --locked` と `cargo build --release --locked` を実行します。対象ごとの配布アーカイブを作り、ファイル一覧と検証範囲をリリースノートに記載します。

リリース担当者が管理する GPG 鍵で、配布資産それぞれに detached signature を作成します。

```sh
git tag -s v0.1.0 -m v0.1.0
gpg --armor --detach-sign --output veil-keeper-linux.tar.gz.sig veil-keeper-linux.tar.gz
gpg --verify veil-keeper-linux.tar.gz.sig veil-keeper-linux.tar.gz
```

署名の検証と署名者の鍵 fingerprint の照合を済ませ、アーカイブ、対応する `.sig`、公開鍵の入手先と fingerprint を添えて公開します。独立した信頼できる経路で fingerprint を照合できるようにします。
