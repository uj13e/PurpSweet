# Local WebSec Testing Tool

[English](README.md) | **日本語**

自社が所有、または**明示的にテスト許可を得た** Web システムの診断専用の、
HTTP(S) インターセプト型ローカル Web アプリです。Burp Suite / OWASP ZAP と
同じカテゴリのツールを、Python(FastAPI + mitmproxy)と React(TypeScript + Vite)で
自作しました。

> ⚠️ **利用条件**: 許可のない対象への使用は行わないでください。すべての通信は
> ローカル(127.0.0.1)で完結し、既定では外部への送信は行いません。ツールからの能動送信
> (Repeater / Intruder / Scanner / WebSocket Repeater など)は、**Scope に登録・有効化した
> ホストにのみ**実行されます(デフォルト拒否)。本ソフトウェアの利用に関する責任は
> すべて利用者にあります。

## 機能

- **インターセプトプロキシ** — mitmproxy をライブラリ組み込みで起動。HTTP/HTTPS を
  傍受し、リクエストを一時停止 → 編集(メソッド/パス/ヘッダー/ボディ)→ Forward / Drop。
  CA はワンタッチ DL。全通信を WebSocket でリアルタイム配信し SQLite に保存。
- **HTTP 履歴** — 一覧(メソッド/ホスト/ステータス/種別/長さ/時間/スコープ)、
  フィルタ、リクエスト/レスポンスの生データ詳細表示。
- **Repeater** — 履歴から送信 → 自由編集 → 何度でも再送。タブごとにレスポンス履歴を
  保持して比較。
- **Scope** — 能動送信の許可リスト(デフォルト拒否)を技術的ガードとして実装。
  ホスト名 / グロブ / 単一IP / **CIDR**(`10.0.0.0/8` など、IPv6可)に対応。
- **Intruder** — 差し込み位置マーカー `§値§`、攻撃モード4種
  (Sniper / Battering ram / Pitchfork / Cluster bomb)、ペイロード(リスト/数値範囲/
  ファイル)、**レート制御(同時実行数・送信間隔)必須**、総リクエスト数の上限ガード、
  結果一覧(status / length / time / grep 一致)。送信は Scope ゲートを通過。
- **Decoder** — Base64 / URL / HTML エンティティ / Hex の相互変換、MD5・SHA1/256/512
  ハッシュ。変換の重ねがけ(前段出力→次段入力)に対応。すべてローカル処理。
- **Comparer** — 2 テキストを単語 / バイト(文字)/ 行 単位で差分ハイライト(A のみ=赤、
  B のみ=緑)。履歴の詳細から **→ Comparer** で A→B に読み込み。
- **一覧のソート** — HTTP履歴 / Intruder 結果表 / Scanner 指摘一覧とも、見出しクリックで
  昇順⇄降順。
- **Scanner**
  - **受動診断**(送信なし): セキュリティヘッダ欠如 / Cookie 属性不備 / 秘密鍵・AWSキー・
    JWT・カード番号らしき露出 / **CORS 設定不備** / **スタックトレース露出** /
    **ディレクトリ一覧** / **HTTP 上の Basic 認証** / 混在コンテンツ /
    ASP.NET 等のバージョン開示。
  - **能動診断**(検出用。Scope 通過＋レート制御): SQLi / 反射XSS / OSコマンド
    インジェクション / **パストラバーサル・LFI** / **SSTI(テンプレート注入)** /
    **オープンリダイレクト** / **CRLF インジェクション**の**可能性**を判定。
    エラーを出さない**ブラインド脆弱性**も検出します:
    - **時間ベース**(SLEEP/pg_sleep/WAITFOR/sleep/ping で遅延 → 再送で相関確認)
    - **ブール差分**(`AND 1=1` と `AND 1=2` の応答差)
    - **エラーベース**(DB エラー署名)/ **反射マーカー**(XSS の未エンコード反射)
  - 挿入点: クエリ / フォーム / **JSON ボディ** / 任意で Cookie・UA・Referer ヘッダ。
    リダイレクト追従・到達性判定(認証等で未到達なら情報として提示)。
  - **CVE / バージョン診断** — 同梱テーブルによるオフライン照合。任意で NVD オンライン
    照会(既定OFF。送るのは製品名+バージョン文字列のみで、対象のデータは送りません)。
  - 指摘は深刻度付きで一覧化。
- **Sitemap** — 傍受 URL をホスト/パスのツリーで表示、ホストをスコープに登録。
- **WebSocket** — WS メッセージの**傍受履歴**(方向・本文)と、対象へ接続してメッセージを
  送受信する **WS Repeater**。送信は Scope ゲートを通過。HTTP履歴の 101(Upgrade)行を
  右クリック → 「WS Repeater へ送る」で URL と Cookie を引き継ぎ。
- **右クリックメニュー** — 履歴行から各ツールへ送る / 選択テキストを URL・Base64・HTML・Hex で
  エンコード/デコード(編集欄はその場置換、それ以外はコピー)。
- **UX** — 列幅リサイズ(HTTP履歴)、Request/Response 50%分割、文字コード自動判定、
  日本語 / English の UI 切り替え。

### Intruder の使い方(概要)

1. 履歴の詳細から **→ Intruder へ送る**(または直接テンプレートを記述)。
2. 値を差し込みたい箇所を選択して **§ 位置に設定**(`§値§` で囲まれる)。
3. 攻撃モードとペイロード(位置ごと)を設定。**同時実行数・間隔は必須**。
4. **攻撃開始**。結果表が随時更新。grep 語に一致した応答は緑で表示。
   - Sniper=1リストを1箇所ずつ / Battering ram=全箇所同値 / Pitchfork=位置ごとリストを並列 /
     Cluster bomb=全組み合わせ。
   - 総数が上限(既定10万、`WEBSEC_INTRUDER_MAX_TOTAL`)を超えると開始を拒否。

---

## セットアップ

### 前提

- **Python 3.12 または 3.13 を推奨**(3.11 でも動作します)。
  - ⚠️ **Python 3.14 は不可**(2026-09 時点)。依存の `zstandard` / `cffi` に 3.14 用の
    ビルド済み wheel が無く、ソースビルドに Visual C++ Build Tools が必要になり失敗します。
    3.14 を使わず、3.12/3.13 で venv を作ってください(3.14 はアンインストール不要)。
- **Node.js 18 以上**(フロントエンドのビルドに最初の一度だけ必要。下記参照)

### 1. バックエンド

**仮想環境(venv)の利用を推奨**します。一部の Debian 系環境では、システムの
setuptools と競合して mitmproxy の依存(pyperclip)のビルドが失敗するため、
venv でクリーンに入れるのが確実です。

**Linux / macOS**

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

**Windows(PowerShell)**

```powershell
py -0                                   # 導入済み版の一覧(-V:3.12 があるか確認)
# 無ければ: winget install -e --id Python.Python.3.12
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\activate                # cmd の場合: .venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

PowerShell で activate が拒否される場合は、一度だけ
`Set-ExecutionPolicy -Scope Process RemoteSigned` を実行してから有効化します。

**venv を使わない場合(Windows)**: **3.12 を明示**してインストール・起動します
(`run.py` を単体で打つと関連付けで 3.14 が使われるため不可):

```powershell
cd backend
py -3.12 -m pip install --upgrade pip setuptools wheel
py -3.12 -m pip install -r requirements.txt
py -3.12 run.py            # もしくは同梱の run.bat をダブルクリック
```

`run.bat` は venv があればそれを、無ければ `py -3.12` / `py -3.13` を自動で使います。

### 2. フロントエンド(最初に一度ビルド)

ビルド済み UI(`frontend/dist/`)はリポジトリに含めていないため、最初に一度ビルドします:

```bash
cd frontend
npm install
npm run build          # dist/ を生成 → バックエンドが配信
```

フロントを改造する場合は開発サーバも使えます:

```bash
npm run dev            # http://127.0.0.1:5173 (API/WS は :8777 にプロキシ)
```

### 3. 起動

```bash
cd backend
python run.py
```

| 用途     | URL                   |
|----------|-----------------------|
| UI / API | http://127.0.0.1:8777 |
| プロキシ | http://127.0.0.1:8080 |

ブラウザで `http://127.0.0.1:8777` を開けば UI が使えます。

---

## 使い方

1. **Scope** タブで診断対象ホストを登録(例 `example.com`、`*.staging.internal`)。
   これを行わないと Repeater などの能動送信はすべて 403 で拒否されます。
2. ブラウザ/OS の HTTP・HTTPS プロキシを `127.0.0.1:8080` に設定。
3. **設定/使い方** タブから **CA 証明書をダウンロード**し、**自分が管理する端末にのみ**
   信頼済みルートとして導入(HTTPS 復号のため)。
4. 対象をブラウズ → **HTTP履歴** に通信が流れる。行を選ぶと生データ詳細。
5. 詳細の **→ Repeater へ送る** で編集・再送・比較。
6. **Intercept** を ON にすると各リクエストが停止 → 編集して Forward / Drop。

### 環境変数(任意)

| 変数                         | 既定           | 説明                                                  |
|------------------------------|----------------|-------------------------------------------------------|
| `WEBSEC_API_HOST`            | `127.0.0.1`    | UI/API の待受アドレス                                 |
| `WEBSEC_API_PORT`            | `8777`         | UI/API ポート                                         |
| `WEBSEC_PROXY_HOST`          | `127.0.0.1`    | プロキシ待受アドレス                                  |
| `WEBSEC_PROXY_PORT`          | `8080`         | プロキシ待受ポート                                    |
| `WEBSEC_DATA_DIR`            | `backend/data` | SQLite の保存先                                       |
| `WEBSEC_MITM_CONFDIR`        | `~/.mitmproxy` | CA / 証明書の保存先                                   |
| `WEBSEC_INTRUDER_MAX_TOTAL`  | `100000`       | Intruder 1 回あたりの総リクエスト数上限               |
| `WEBSEC_UPSTREAM_PROXY`      | *(空)*         | ツールからの能動送信に使う上流プロキシ                |
| `WEBSEC_CONNECT_TIMEOUT`     | `8`            | 能動送信の接続タイムアウト(秒)                      |
| `WEBSEC_NVD_ONLINE`          | `0`            | NVD オンライン照会を有効化(`1` / `true` / `yes`)    |
| `WEBSEC_NVD_API_KEY`         | *(空)*         | NVD API キー(任意。レート制限が緩和されます)        |

---

## アーキテクチャ

```
frontend/ (React + TypeScript + Vite)
   │  fetch /api/*  +  WebSocket /ws
   ▼
backend/  (FastAPI, :8777)  ── SQLite (SQLAlchemy)
   │
   ├─ ProxyController: mitmproxy を専用スレッド+専用 asyncio ループで起動
   │     ・request フックで「一時停止」(asyncio.Event で待機、他フローは並行継続)
   │     ・UI からの解決は proxy ループへ call_soon_threadsafe で受け渡し
   │     ・response フックで DB 保存 + WebSocket 配信(スレッドセーフ)
   ├─ Repeater / Intruder / Scanner: httpx で送信(Scope ゲートを必ず通過)
   └─ ScopeManager: デフォルト拒否の許可リスト(能動送信の技術的ガード)
```

## テスト

```bash
cd backend && source .venv/bin/activate    # Windows: .venv\Scripts\activate
python selftest.py        # プロキシ捕捉/履歴/詳細/Scope ゲート/Intercept トグル
python intercept_test.py  # 一時停止→編集→Forward、および Drop
```

## 安全設計メモ

- **デフォルト拒否スコープ**: `app/scope.py` の `require_in_scope()` を能動送信の
  各経路が必ず呼ぶ。未登録ホストは送信されない(UI 文言ではなくコード上のガード)。
- **ローカル完結**: 既定で全リスナが 127.0.0.1 バインド。外部送信なし
  (NVD オンライン照会は任意で、送るのは製品名・バージョンのみ)。
- **レート制御**: `config.py` に同時実行数・送信間隔の既定を用意し、
  Intruder / Scanner では必須。
- **認証機能なし**: UI/API は単一ユーザーのローカル利用を前提としています。
  待受アドレスを変更してネットワークに公開しないでください。

## データとプライバシー

SQLite データベース(`backend/data/websec.db`)には、プロキシが傍受したすべての通信
(Cookie・トークン・個人情報を含み得ます)が保存されます。`.gitignore` で除外済みですが、
コミットや共有は絶対にしないでください。mitmproxy の CA 秘密鍵は `~/.mitmproxy`
(このリポジトリの外)にあります。診断が終わったら、信頼済みストアから CA を削除してください。

## コントリビュート

Issue・Pull Request を歓迎します。許可された利用のための安全機構(デフォルト拒否の
Scope ゲートとレート制御の必須化)は維持してください。

## ライセンス

[MIT](LICENSE) © 2026 Worldskyjp

本プロジェクトは [mitmproxy](https://mitmproxy.org/)、FastAPI、SQLAlchemy、httpx、
React などを利用しています。それぞれのライセンスに従います。
