# Qeen QUIC 実装におけるRFC非準拠・実装不適格事項

## 1. パケット番号管理（RFC9000 17.1）
- [x] パケット番号が2^62-1を超えた場合のwrap-around防止・明示的なエラー処理を追加する
- [x] 最大値超過時にコネクションエラーを発生させる

## 2. ストリームID・数管理（RFC9000 9/19）
- [x] ストリームIDの最大値（2^62-1）超過時のチェックを追加する

## 3. TLSハンドシェイク・鍵管理（RFC9001）
- [x] TLS1.3ハンドシェイクを本格実装し、外部TLSライブラリと連携する
- [x] Transport Parametersの正規エンコード・検証を実装する
- [x] 鍵更新時の再ネゴシエーション・エラー処理を追加する

## 4. ACK/CONNECTION_CLOSEフレームの細則
- [x] ACK Delayの単位変換（ACK Delay Exponent対応）を実装する
- [x] ACK Rangeやreason phrase長の最大値制限、エラーコード値域チェック等のRFC細則を実装する

## 5. ロス検出（RFC9002）
- [ ] ECN（Explicit Congestion Notification）対応を実装する
- [ ] パス検証（Path Validation）機能を実装する

## 6. フロー制御（RFC9000 4.1/19.7）
- [x] MaxDataFrame/MaxStreamDataFrame等を用いた送信上限管理・受信側でのフロー制御ロジックを厳密に実装する
- [x] フロー制御違反時にエラーを返す処理を追加する

## 7. パケット保護（RFC9001 5.3）
- [x] パケット番号をnonceに組み込む方式でnonce生成を実装する
- [x] 同じ鍵でnonceが重複しないようにする

## 8. テストカバレッジ・異常系
- [ ] 最大値超過、wrap-around、異常なパラメータ等のエッジケース・異常系テストを強化する

### テスト・補助実装の未完了事項
- [ ] Hkdf/InitialSecrets/ExpandLabel等の実装・テスト（Qeen.Tests/Security/Crypto/HkdfTests.cs, InitialSecretsTests.cs等のTODO参照）
- [ ] Header Protection（AES/ChaCha20等）の実装・テスト（HeaderProtectionTests.csのTODO参照）
- [ ] RFC9001ベクトルテスト・パケット暗号化/復号・nonce構築等の実装（Rfc9001VectorTests.csのTODO参照）
- [ ] サーバー側パケットヘッダー解析処理の実装（QuicListener.csのTODO参照）
- [ ] その他、テストコード中の「TODO」コメント箇所の実装

---
本TODOはRFC9000/9001/9002および他実装（quiche/quick-go等）との比較に基づくものです。
