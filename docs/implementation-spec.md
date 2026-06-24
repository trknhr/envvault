# Credlease 実装仕様書

- **文書バージョン:** 0.2-implementation-draft
- **作成日:** 2026-06-22
- **ステータス:** 実装開始用
- **実装言語:** Go
- **プロダクト名:** Credlease（仮称）
- **対象リリース:** Local MVP v0.1

## 1. 要約

Credleaseは、長期credentialを`.env`や対象プロセスへ置かず、実行時に用途・resource・scope・TTLを限定した短命credentialへ交換して貸し出す、ローカルファーストなcredential launcherである。

AI agentは代表的な利用者だが、Credleaseはagent専用ではない。`codex`、開発サーバー、テスト、migration、CLI、ブラウザログインなど、ローカルで起動する任意の開発フローを対象とする。

```dotenv
# Repositoryへ保存できる値
BACKEND_A_TOKEN=credlease://backend-a/dev
```

```bash
credlease exec --env-file .env -- codex
credlease exec --env-file .env -- npm run dev
credlease open admin-web/dev
```

Local MVPでは、エンドユーザーが明示的にインストールするものはGo製の`credlease`単一バイナリだけとする。CredleaseはOry Talosをmanaged runtimeとして必要時だけ起動し、Talos親APIキーから短命JWTを派生させる。

長期のraw secretはOS Credential Storeへ保存する。Talos SQLiteにはhashとmetadataのみを保存し、Repositoryおよび対象プロセスにはraw parent keyを渡さない。

## 2. プロダクトの定義

> Credleaseは、プロジェクト内のcredential参照を、実行時に短命・最小権限のcredentialへ解決し、対象プロセスまたはブラウザセッションへ一時的に貸し出すOSSである。

CredleaseはSecret Managerそのものではない。保存済みの長期secretをそのまま注入するのではなく、信頼anchorを使って実行ごとに新しいcredentialを発行する。

### 2.1 中核ユースケース

1. `.env`から長期APIキーを除去する。
2. Codexなどのprocessへ長期APIキーを渡さない。
3. ローカルBackendへ短命JWTでアクセスする。
4. 1P WebアプリへID/パスワードを渡さず、短命bootstrap tokenからブラウザセッションを作る。
5. 将来、中央STSへ移行してチーム共通policyとremote Backendを扱う。

### 2.2 Credential Hygiene上の位置づけ

Credlease Local MVPは次のレベルを提供する。

| Level | 内容 | Credlease Local MVP |
|---|---|---:|
| CH-0 | `.env`に平文の長期credential | 置換対象 |
| CH-1 | 長期credentialをOS Credential Storeへ移す | 対応 |
| CH-2 | 子processへ短命・scope限定credentialだけを渡す | **主要提供価値** |
| CH-3 | SSO、中央policy、user presenceで発行を制御 | 将来 |
| CH-4 | processへ短命token自体も渡さずbrokerで使用 | 非目標／将来オプション |

## 3. 目標と非目標

### 3.1 Local MVPの目標

- `.env`、Repository、shell historyへ長期credentialを保存しない。
- 対象processへTalos parent key、HMAC secret、signing private keyを渡さない。
- `.env`内の`credlease://<profile>`参照を短命JWTへ解決する。
- Profileごとにresource、scope、TTLを固定し、Repository側から権限を拡大できないようにする。
- Ory Talos OSSを利用者に意識させず、SQLite・single-nodeで自動管理する。
- 短命JWTのraw値をdiskへ永続化しない。
- JWT検証用JWKSをstableなfileとして提供する。
- `credlease open`により、1P Webアプリのbrowser sessionをID/パスワードなしで開始できる。
- 通常のローカル開発体験を大きく損なわない。

### 3.2 明示的な非目標

- 同一OSユーザー権限を持つ悪意あるprocessから完全に防御すること。
- 子processから短命JWTそのものを隠すこと。
- Codexが`credlease token`を再実行することの完全防止。
- prompt、stdout、stderr、HTTP bodyのDLPや自動redaction。
- VM、container、sandbox、egress proxyの提供。
- GitHub PAT、Stripe secretなど、3Pが長期secretしか受け付けないcredentialをTalos JWTへ置換すること。
- Password Manager全般の置換。
- 独自のOIDC Provider。
- Local MVPにおける中央hosted service。
- Local issuerをremote Backendが自動的に信頼する仕組み。

## 4. 想定利用者

- ローカル開発者。
- AI coding agentを利用する開発者。
- ローカルBackend、integration test、開発用管理画面を運用するチーム。
- `.env`へ長期APIキーを置きたくないOSS利用者。

## 5. 用語

| 用語 | 定義 |
|---|---|
| Credlease | OSS全体 |
| `credlease` | ユーザー向けGo CLI |
| Profile | credentialの発行policyを表す信頼済みローカル設定 |
| Reference | `credlease://<profile>`形式の参照 |
| Parent key | Talosで短命tokenをderiveする長期APIキー |
| Leased token | 対象processへ貸し出す短命JWT |
| Managed Talos | Credleaseが導入・設定・起動停止するTalos runtime |
| Local issuer | 開発者PC内のManaged Talosを利用する発行モード |
| Browser bootstrap token | browser session作成専用の短命JWT |
| Browser login code | Backendが発行する一回限りのopaque code |
| Resource Server | Leased tokenを検証するBackend |

## 6. アーキテクチャ

### 6.1 Process credential flow

```text
┌─────────────────────────────┐
│ Project                     │
│ .env                        │
│ TOKEN=credlease://api/dev   │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ credlease CLI               │
│ - Reference解析             │
│ - Profile解決               │
│ - Keyring連携               │
│ - Talos on-demand起動       │
│ - JWT derive                │
│ - Talos停止                 │
└──────────────┬──────────────┘
               │ short-lived JWT
               ▼
┌─────────────────────────────┐
│ Child Process               │
│ codex / npm / go test       │
└──────────────┬──────────────┘
               │ Bearer JWT
               ▼
┌─────────────────────────────┐
│ Backend A                   │
│ - JWKS署名検証              │
│ - exp/scope/resource検証    │
│ - 業務認可                  │
└─────────────────────────────┘
```

### 6.2 Browser session bootstrap flow

```text
credlease open admin-web/dev
        │
        │ 1. 60秒以下のbrowser bootstrap JWTをderive
        ▼
Backend POST /auth/credlease/browser-sessions
        │ 2. JWTを検証し、JWT session_idを一回だけ受理
        │ 3. 30秒以下・一回限りのopaque login codeを発行
        ▼
credlease
        │ 4. HTTPS login URLをChrome等で開く
        ▼
Browser GET /auth/credlease/complete?code=<opaque>
        │ 5. codeをatomicにconsume
        │ 6. HttpOnly session cookieを設定
        │ 7. codeを含まない固定URLへ303 redirect
        ▼
ログイン済み1P Webアプリ
```

BrowserへTalos JWT、parent key、ID、passwordを渡してはならない。URLに含めるのは短寿命・一回限りのopaque codeだけとする。

## 7. コンポーネントと責務

### 7.1 `credlease` CLI

責務:

- 初期化とManaged Talos導入。
- OS Credential Store連携。
- Profile CRUD。
- `.env` Referenceの解析と解決。
- Talosのon-demand起動・停止。
- 短命JWTのderive。
- 子processへのenvironment injection。
- Browser bootstrap endpointの呼び出しとbrowser起動。
- JWKS export。
- 診断、監査metadata、cleanup。

責務外:

- Backendの業務認可。
- Webアプリのsession storage。
- 3P API proxy。
- child processのsandbox化。
- Password form autofillのMVP実装。

### 7.2 Managed Talos

責務:

- Parent API key lifecycle。
- Parent key hashとmetadataのSQLite保存。
- Parent keyから短命JWTをderive。
- JWT signing。
- JWKS生成。

Talosは汎用API key serverでありagent専用ではない。Credleaseでは発行エンジンとして利用する。

### 7.3 OS Credential Store

保存するraw secret:

- Talos HMAC secret。
- Talos JWT signing private key、またはその復号material。
- ProfileごとのTalos parent API key。
- 将来のOIDC refresh token。
- 将来のlegacy browser credential。

保存しないもの:

- 発行済み短命JWT。
- Browser login code。
- audit log本文。

対象:

- macOS: Keychain。
- Linux: Secret Service互換keyring。
- Windows: Credential Manager。

MVPでは平文file fallbackを提供しない。Credential Storeが利用できない場合はfail closedとする。

### 7.4 Resource Server / Backend A

責務:

- JWT署名、issuer、`exp`、`nbf`、scope、resourceを検証する。
- tenant、repository、recordなどの最終業務認可を行う。
- Browser session bootstrap endpointを実装する場合、token replay cacheとone-time code storeを持つ。
- JWT本文、login code、session cookieをlogへ出さない。

## 8. 保存データとKey hierarchy

```text
OS Credential Store
├─ credlease/talos/hmac/current
├─ credlease/talos/signing/<kid>
└─ credlease/profile/<profile-id>/parent-key

Talos SQLite
└─ parent key hashes / scopes / status / expiry / metadata

Credlease config
└─ profile policy / non-secret runtime settings

JWKS file
└─ public keys only

Project .env
└─ credlease:// references only

Child process
└─ short-lived JWT only
```

### 8.1 永続化ルール

- Raw parent keyはOS Credential Store以外へ永続化しない。
- SQLiteへraw parent keyを保存しない。
- 発行済みJWTをdisk cacheへ保存しない。
- Browser login codeをCredlease側で保存しない。
- Backend側のlogin code storeはhash化したcodeまたは十分なentropyを持つopaque identifierを短時間だけ保存する。
- JWKSは公開情報としてfile保存を許可する。

## 9. Profileモデル

### 9.1 Profile kind

MVPは2種類を実装する。

```text
process          子processへJWTを環境変数として貸し出す
browser-session  1P Webアプリのsession bootstrapにJWTを使う
```

将来:

```text
browser-form     Chrome Extension + Native Hostでlegacy ID/passwordをfill
remote           中央STSからcredentialを取得
```

### 9.2 設定例

```yaml
version: 1

installation:
  id: 01JXXXXXXXXXXXXXXX

runtime:
  talos:
    mode: managed
    version: pinned-by-release-manifest
    lifecycle: on-demand

defaults:
  token_ttl: 10m
  max_token_ttl: 60m

profiles:
  backend-a/dev:
    kind: process
    issuer: talos
    resource: https://api.dev.example.com
    token_ttl: 10m
    max_token_ttl: 30m
    scopes:
      - repository:read
      - issue:read
      - issue:draft
    claims:
      environment: dev
    project_binding:
      mode: git-remote-and-root

  admin-web/dev:
    kind: browser-session
    issuer: talos
    resource: https://admin.dev.example.com
    scopes:
      - browser:session:create
    bootstrap_token_ttl: 60s
    login_code_ttl: 30s
    web_session_ttl: 30m
    exchange_url: https://admin.dev.example.com/auth/credlease/browser-sessions
    complete_url: https://admin.dev.example.com/auth/credlease/complete
    post_login_url: https://admin.dev.example.com/
    allowed_hosts:
      - admin.dev.example.com
```

### 9.3 Profileの安全制約

- Profileはユーザー側のCredlease configへ保存し、Repository内設定をauthorityにしない。
- Profile名からscope、resource、TTLをserver/client内部で解決する。
- `.env` URI queryによるscope、TTL、redirect先の上書きを禁止する。
- TTL短縮のみCLI flagで許可してよい。
- Profileごとにparent keyを分離する。
- Parent keyのscopeはProfileの最大scopeを超えてはならない。
- Browser URLはprofileに固定し、任意redirectを受け付けない。

## 10. `.env` Reference仕様

### 10.1 構文

```dotenv
BACKEND_A_TOKEN=credlease://backend-a/dev
```

### 10.2 解決規則

- 値全体が`credlease://` URIの場合のみ解決する。
- 部分文字列のtemplate展開はしない。
- queryとfragmentはMVPでは禁止する。
- URI pathを正規化し、`..`、空segment、percent-encoded separatorを拒否する。
- 未知のProfileはfail closed。
- 同一Profileの複数参照は同一`exec`内で同じJWTを再利用してよい。
- `.env`自体を変更しない。
- 解決後の値をstdout、debug log、auditへ出さない。

### 10.3 dotenv precedence

MVPのprecedenceは次とする。

1. CLIで明示した`--env KEY=VALUE`。
2. `--env-file`で読み込んだ値。
3. 親process環境。

ただし`credlease://`参照がある変数について、親環境の同名secretへfallbackしてはならない。

## 11. CLI仕様

### 11.1 初期化

```bash
credlease init
```

処理:

1. OSとarchitectureを検出。
2. Credlease release manifestから互換Talos versionを選択。
3. Talos artifactを取得し、checksumまたは署名を検証。
4. HMAC secretとsigning keyを生成。
5. raw secretをOS Credential Storeへ保存。
6. SQLiteを作成してmigration。
7. stable issuer IDとJWKSを生成。
8. config/data/cache directoryを作成。

再実行はidempotentとし、既存installationを破壊しない。

### 11.2 Profile作成

Process profile:

```bash
credlease profile add process backend-a/dev \
  --resource https://api.dev.example.com \
  --scope repository:read \
  --scope issue:read \
  --ttl 10m \
  --max-ttl 30m
```

Browser profile:

```bash
credlease profile add browser-session admin-web/dev \
  --resource https://admin.dev.example.com \
  --exchange-url https://admin.dev.example.com/auth/credlease/browser-sessions \
  --complete-url https://admin.dev.example.com/auth/credlease/complete \
  --post-login-url https://admin.dev.example.com/ \
  --scope browser:session:create \
  --bootstrap-ttl 60s \
  --code-ttl 30s \
  --session-ttl 30m
```

作成時にProfile専用parent keyをTalosでissueし、raw secretをkeyringへ保存する。

### 11.3 Token取得

```bash
credlease token backend-a/dev
credlease token backend-a/dev --format json
```

Raw stdoutはcredential helper連携用に提供する。TTYへ直接出力する場合はdefaultで警告し、`--quiet`または`--allow-tty`を要求する案を実装時に採用する。

JSON例:

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_at": "2026-06-22T12:10:00Z",
  "expires_in": 600,
  "profile": "backend-a/dev",
  "resource": "https://api.dev.example.com",
  "scope": ["repository:read", "issue:read"]
}
```

HTTP responseではないが、同様にtokenをlogへ出さない。

### 11.4 子process実行

```bash
credlease exec --env-file .env -- codex
credlease exec --env-file .env -- npm run dev
```

処理順序:

1. `.env`をparse。
2. Referencesを列挙。
3. Profileとproject bindingを検証。
4. runtime lockを取得。
5. OS Credential Storeから必要なsecretを取得。
6. Talosをloopback random portで起動。
7. 全JWTをderive。
8. Talosを停止し、portが閉じたことを確認。
9. secret-bearing runtime stateをcleanup。
10. child environmentを構築。
11. child processを起動。
12. signalをforwardし、child exit codeを返す。

重要要件:

- child process開始前にTalos Admin surfaceが停止していること。
- child environmentへparent key、HMAC secret、signing private keyを含めないこと。

### 11.5 Browser session開始

```bash
credlease open admin-web/dev
credlease open admin-web/dev --browser chrome
credlease open admin-web/dev --print-url
```

処理順序:

1. Profile kindが`browser-session`であることを確認。
2. 60秒以下のbootstrap JWTをderive。
3. JWTを`Authorization: Bearer`で`exchange_url`へPOST。
4. `Cache-Control: no-store`を要求し、JSON responseを受ける。
5. responseのlaunch URLがHTTPS、またはlocalhost HTTPであり、Profileのallowed hostに一致することを検証。
6. `--print-url`でなければOS標準機構でbrowserを起動。
7. JWTおよびlaunch URLのcodeをlogへ出さない。

Request:

```http
POST /auth/credlease/browser-sessions HTTP/1.1
Authorization: Bearer <bootstrap-jwt>
Content-Type: application/json
Cache-Control: no-store

{
  "requested_session_ttl_seconds": 1800,
  "client": "credlease-cli",
  "client_version": "0.1.0"
}
```

Response:

```http
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "launch_url": "https://admin.dev.example.com/auth/credlease/complete?code=<opaque>",
  "expires_at": "2026-06-22T12:00:30Z"
}
```

`requested_session_ttl_seconds`は上限要求であり、BackendがProfile policy以下へclampする。CLIから任意のredirect URLを送らない。

### 11.6 JWKS

```bash
credlease jwks show
credlease jwks export --output ~/.config/backend-a/credlease-jwks.json
credlease issuer show
```

Managed Talosが常駐しないため、Local BackendはJWKS fileを利用できる。

### 11.7 診断とreset

```bash
credlease doctor
credlease reset --dry-run
credlease reset
```

`doctor`はruntime、checksum、keyring、SQLite、Profile、JWKS、stale lock、一時fileを検査する。secret本文は表示しない。

## 12. Managed Talos Runtime仕様

### 12.1 配布

- Credlease releaseごとに互換Talos versionをpinする。
- artifact source、digest、platformを署名済みまたはrelease内manifestで固定する。
- checksum不一致なら実行しない。
- system-installed Talosは明示opt-inで許可する。
- third-party noticesを配布物へ含める。

### 12.2 On-demand lifecycle

Talosを起動する操作:

- `init`
- Profile CRUD
- `token`
- `exec`
- `open`
- key rotation
- `doctor`の一部

要件:

- loopback random portへbindする。
- filesystem lockで同時起動をserial化する。
- health check後にAPIを利用する。
- operation完了後にgraceful shutdownする。
- timeout後は強制終了する。
- shutdown後にportが閉じたことを確認する。
- Talos Admin APIを外部interfaceへbindしない。
- secret-bearing temporary fileを可能な限り作らない。必要時は0600相当、短寿命、atomic cleanupとする。

### 12.3 SQLite

- Repository配下へ置かない。
- permissionをユーザー本人だけへ制限する。
- migration前にbackupする。
- raw parent keyを含めない。
- crash recoveryとintegrity checkを提供する。

### 12.4 Talos adapter contract

Local MVPがtargetとするTalos HTTP contractは次とする。実際のrequest/response typeはpinしたTalos OpenAPIから生成または手書きし、`internal/issuer/talos`内へ隔離する。

Parent key issue:

```http
POST /v2alpha1/admin/issuedApiKeys
Content-Type: application/json

{
  "name": "credlease:backend-a/dev",
  "actor_id": "credlease-local:<installation-id>",
  "scopes": ["repository:read", "issue:read"],
  "ttl": "2160h",
  "metadata": {
    "credlease_profile": "backend-a/dev"
  }
}
```

Raw parent secretはresponseの`secret`から一度だけ取得し、OS Credential Storeへ直ちに保存する。

JWT derive:

```http
POST /v2alpha1/admin/apiKeys:derive
Content-Type: application/json

{
  "credential": "<parent-key>",
  "algorithm": "TOKEN_ALGORITHM_JWT",
  "ttl": "10m",
  "scopes": ["repository:read"],
  "custom_claims": {
    "credlease_profile": "backend-a/dev",
    "credlease_resource": "https://api.dev.example.com",
    "credlease_session_id": "01J...",
    "credlease_purpose": "process"
  }
}
```

Token文字列はresponseの`token.token`から取得する。

要件:

- `scopes`は常に明示する。省略してparent scope全体を継承しない。
- Derive前にCredlease側でもrequested scopeがProfile scopeのsubsetであることを検証する。
- Talosが拒否したscope、TTL、inactive parentを上書きやretryで緩和しない。
- Reserved standard claimsを`custom_claims`へ指定しない。Credlease custom claimは`credlease_` prefixを使用する。
- JWKSは`GET /v2alpha1/derivedKeys/jwks.json`から取得し、public fileへexportする。
- `v2alpha1`の変更はadapter testで検出し、Credlease release manifestの互換versionを更新するまで新versionを使用しない。

## 13. JWT仕様

### 13.1 共通必須条件

- 署名済みJWT。
- Profileで固定したscope以下。
- 短い`exp`。
- stable issuer。
- unique session ID。
- resource binding claim。
- `client`とproject metadata。

### 13.2 Credlease custom claims

```json
{
  "credlease_profile": "backend-a/dev",
  "credlease_resource": "https://api.dev.example.com",
  "credlease_session_id": "01J...",
  "credlease_project_id": "sha256:...",
  "credlease_user": "local-user",
  "credlease_client": "codex",
  "credlease_purpose": "process"
}
```

Browser bootstrap:

```json
{
  "credlease_profile": "admin-web/dev",
  "credlease_resource": "https://admin.dev.example.com",
  "credlease_session_id": "01J...",
  "credlease_client": "credlease-cli",
  "credlease_purpose": "browser-bootstrap"
}
```

Backendは`credlease_resource`を必須検証する。Talos adapterが標準`aud`をprofile単位で安全に設定できるようになった場合は、`aud`も必須検証へ移行する。

### 13.3 TTL

Default:

- Process token: 10分。
- Interactive process profile: 最大30分推奨。
- Browser bootstrap token: 最大60秒。
- Browser login code: 最大30秒。
- Browser web session: Profile policy、default 30分。

Profileが指定する`max_*`を超える値をclientから要求できない。

### 13.4 Refresh

`exec`は起動時に一度だけ解決する。起動済みprocessのenvironmentは更新しない。

Long-running processは将来の`credential-process`、SDK、local daemonで扱う。MVPの利用者は期限切れ時にprocessを再起動する。

## 14. Browser Session Protocol

### 14.0 Trust prerequisite

Local MVPのbrowser flowは、次のいずれかを満たすBackendだけを対象とする。

- Backendも同じローカル環境で動作し、export済みJWKSを読む。
- Remote 1P Backendへ当該Credlease installationのpublic JWKSが事前登録されている。

任意のローカルinstallationが生成した鍵をRemote Backendが自動的に信用してはならない。組織共通のRemote Backendは将来の`credlease-sts`を推奨する。

### 14.1 Backend exchange endpoint

Endpoint:

```text
POST /auth/credlease/browser-sessions
```

Backend要件:

1. Authorization header以外からbootstrap tokenを受け付けない。
2. JWT署名、issuer、exp、scope、resource、purposeを検証する。
3. `credlease_session_id`をreplay cacheへatomic insertする。
4. 同じsession IDを再利用したrequestを拒否する。
5. 一回限りのopaque codeをcryptographically secure randomで生成する。
6. codeのraw値をlogしない。
7. codeは最大30秒、使用回数1回。
8. fixed complete URLのみを返す。
9. responseへ`Cache-Control: no-store`を設定する。

### 14.2 Complete endpoint

Endpoint:

```text
GET /auth/credlease/complete?code=<opaque>
```

Backend要件:

1. codeをatomicにconsumeする。
2. expired、unknown、used codeを同一のgeneric errorで拒否する。
3. session cookieを設定する。
4. 303 See OtherでProfile固定のpost-login URLへredirectする。
5. codeをredirect先へ引き継がない。
6. responseへ`Referrer-Policy: no-referrer`および`Cache-Control: no-store`を設定する。

### 14.3 Cookie要件

- `HttpOnly`必須。
- HTTPS環境では`Secure`必須。
- `SameSite=Lax`またはより厳格。
- PathとDomainを最小化。
- Session IDをURLやlocalStorageへ保存しない。
- Web session TTLはProfile policy以下。

### 14.4 Redirect要件

- CLIから任意redirect先を送らない。
- Backendはquery parameter由来の任意redirectを許可しない。
- `post_login_url`はserver configとCredlease Profileの両方で固定する。
- URL host mismatchはCLIでもBackendでも拒否する。

## 15. Legacy ID/Password Autofill（将来仕様）

1P WebアプリはBrowser Session Protocolを優先し、ID/passwordを扱わない。

ID/passwordしか受け付けないlegacy site向けには、v0.3以降で次を検討する。

```text
credlease open legacy-console
  ↓ one-time fill lease
Chrome Extension
  ↓ Native Messaging
Credlease Native Host
  ↓ origin確認・user presence確認
OS Credential Store
  ↓ username/passwordを一回だけ返す
Chrome Extension
  ↓ form fill。defaultではsubmitしない
```

要件案:

- Chrome Manifest V3 extension。
- Native Messaging Hostは`credlease native-host`。
- Leaseはorigin、credential ID、exp、max uses=1へbinding。
- Extensionは現在tab originをNative Hostへ送る。
- Native Hostはorigin完全一致後にのみkeyringへアクセスする。
- Autofill前に明示的なuser actionを要求する。
- Passwordをextension storage、log、clipboardへ保存しない。
- 自動submitをdefaultで禁止する。

この機能はLocal MVP v0.1のrelease gateに含めない。

## 16. Project binding

Repository内の変更だけで高権限Profileを利用されることを減らす。

MVP modes:

- `none`
- `path-hash`
- `git-remote-and-root`

推奨defaultは`git-remote-and-root`。

初回利用時にTTY確認を行い、bindingをユーザーconfigへ保存する。Non-interactive環境では未承認bindingを拒否する。

## 17. Go実装構成

```text
credlease/
├── cmd/
│   └── credlease/
├── internal/
│   ├── cli/
│   ├── config/
│   ├── profile/
│   ├── envref/
│   ├── keyring/
│   ├── runtime/
│   │   └── talos/
│   ├── issuer/
│   │   └── talos/
│   ├── process/
│   ├── browser/
│   ├── jwks/
│   ├── audit/
│   ├── lock/
│   └── doctor/
├── pkg/
│   ├── verifier/
│   └── browsersession/
├── examples/
│   ├── backend-go/
│   ├── backend-typescript/
│   ├── browser-session-go/
│   └── codex/
├── test/
│   ├── acceptance/
│   ├── fixtures/
│   └── fake-keyring/
└── docs/
    ├── threat-model.md
    ├── profiles.md
    ├── browser-session.md
    └── remote-sts.md
```

### 17.1 主要interface

```go
type ProfileKind string

const (
    ProfileKindProcess        ProfileKind = "process"
    ProfileKindBrowserSession ProfileKind = "browser-session"
)

type Grant struct {
    Profile   string
    Resource  string
    Scopes    []string
    TTL       time.Duration
    Claims    map[string]any
}

type Credential struct {
    AccessToken string
    TokenType   string
    ExpiresAt   time.Time
    Scopes      []string
}

type Issuer interface {
    Issue(ctx context.Context, grant Grant) (Credential, error)
}

type SecretStore interface {
    Get(ctx context.Context, key string) ([]byte, error)
    Put(ctx context.Context, key string, value []byte) error
    Delete(ctx context.Context, key string) error
}

type ManagedRuntime interface {
    Start(ctx context.Context) (Endpoint, error)
    Stop(ctx context.Context) error
    Migrate(ctx context.Context) error
    Version(ctx context.Context) (string, error)
}

type BrowserOpener interface {
    Open(ctx context.Context, rawURL string, browser string) error
}

type BrowserReplayStore interface {
    ConsumeSessionID(ctx context.Context, sessionID string, expiresAt time.Time) error
}

type BrowserLoginCodeStore interface {
    Create(ctx context.Context, grant BrowserGrant, ttl time.Duration) (rawCode string, error error)
    Consume(ctx context.Context, rawCode string) (BrowserGrant, error)
}

type WebSessionIssuer interface {
    Issue(ctx context.Context, grant BrowserGrant, ttl time.Duration) (SessionCookie, error)
}
```

`BrowserReplayStore`と`BrowserLoginCodeStore`はatomicなsingle-use semanticを提供しなければならない。Reference implementationはmemory storeをexample用、SQLite storeをローカル実用例として提供する。production remote Backend向けRedis等はinterface実装に委ねる。

Talos固有処理を`internal/runtime/talos`と`internal/issuer/talos`へ閉じ込め、OpenAPIの変更が他packageへ漏れないようにする。

## 18. 機能要件

| ID | 要件 |
|---|---|
| FR-001 | 単一の`credlease`バイナリで初期化できる |
| FR-002 | 互換Talos runtimeを自動導入し、digestを検証できる |
| FR-003 | raw long-lived secretをOS Credential Storeへ保存する |
| FR-004 | Profileごとにparent keyを分離する |
| FR-005 | `.env`の`credlease://`参照を解決する |
| FR-006 | 発行JWTをdiskへ保存せずchildへ注入する |
| FR-007 | Talosをon-demandで起動・停止する |
| FR-008 | `exec` child開始前にTalosが停止している |
| FR-009 | scope、TTL、resourceをRepositoryから拡大できない |
| FR-010 | JWKSをfileへexportできる |
| FR-011 | token、parent key、login codeをlogへ出さない |
| FR-012 | child exit codeとsignal semanticsを保持する |
| FR-013 | concurrency lockとcrash cleanupを提供する |
| FR-014 | `credlease open`でbrowser bootstrap sessionを開始できる |
| FR-015 | Browser URLへJWTを含めない |
| FR-016 | Browser login codeは一回限りかつ短寿命である |
| FR-017 | `doctor`と`reset`を提供する |

## 19. 非機能要件

### 19.1 セキュリティ

- secretを含むfileを原則作成しない。
- 必要なtemporary fileは0600相当、短寿命、atomic cleanup。
- Authorization header、JWT、parent key、cookie、login codeをlogしない。
- HTTP error bodyをそのままdebug logへ出さず、redactionする。
- Browser exchangeはHTTPS必須。localhostのみHTTPを許可可能。
- Talos Admin APIはloopback以外へbindしない。
- Supply chain metadataとchecksumを必須とする。

### 19.2 性能目標

- Warm token issue: p95 1秒以内。
- Cold Talos startup + issue + stop: p95 3秒以内。
- `credlease open`のbrowser launch開始: p95 4秒以内。
- Credlease自身の追加RSS: 50MB未満を目標。

MVPではSLOではなく測定目標とする。

### 19.3 可用性

- Talos artifact取得後はoffline process token発行が可能。
- Browser sessionは対象Backendへのnetwork接続を必要とする。
- Migration失敗時に既存DBを破壊しない。

### 19.4 Privacy

- Telemetryはdefault off。
- Auditはmetadata-only。
- command arguments、prompt、environment全体を収集しない。

## 20. Audit

記録例:

```json
{
  "time": "2026-06-22T12:00:00Z",
  "event": "credential_issued",
  "profile": "backend-a/dev",
  "kind": "process",
  "resource": "https://api.dev.example.com",
  "scopes": ["repository:read"],
  "ttl_seconds": 600,
  "session_id": "01J...",
  "project_id": "sha256:...",
  "result": "success"
}
```

Browser例:

```json
{
  "time": "2026-06-22T12:00:00Z",
  "event": "browser_session_requested",
  "profile": "admin-web/dev",
  "session_id": "01J...",
  "result": "success"
}
```

記録禁止:

- JWT本文。
- raw parent key。
- signing private key。
- Authorization header。
- login code。
- session cookie。
- `.env`全体。

## 21. エラーコード

| Code | 意味 |
|---|---|
| `CREDLEASE_CONFIG_INVALID` | 設定不正 |
| `CREDLEASE_PROFILE_NOT_FOUND` | 未知のProfile |
| `CREDLEASE_PROFILE_KIND_MISMATCH` | commandとProfile kindが不一致 |
| `CREDLEASE_PROJECT_NOT_TRUSTED` | project binding未承認 |
| `CREDLEASE_KEYRING_UNAVAILABLE` | OS Credential Store利用不可 |
| `CREDLEASE_KEYRING_LOCKED` | Credential Storeがlocked |
| `CREDLEASE_PARENT_KEY_MISSING` | parent key欠落 |
| `CREDLEASE_RUNTIME_UNAVAILABLE` | Talos起動失敗 |
| `CREDLEASE_RUNTIME_INCOMPATIBLE` | Talos version不一致 |
| `CREDLEASE_ISSUE_FAILED` | JWT derive失敗 |
| `CREDLEASE_REFERENCE_INVALID` | Reference構文不正 |
| `CREDLEASE_BROWSER_EXCHANGE_FAILED` | Browser exchange失敗 |
| `CREDLEASE_BROWSER_URL_REJECTED` | launch URLがpolicy不一致 |
| `CREDLEASE_CLEANUP_FAILED` | cleanup失敗 |
| `CREDLEASE_LOCK_TIMEOUT` | runtime lock取得timeout |

Error messageにはsecret値やserver responseのAuthorization情報を含めない。

## 22. Security Model

### 22.1 守る対象

- Talos parent key。
- HMAC secret。
- JWT signing private key。
- 長期Backend credential。
- 将来のOIDC refresh token。
- Browser session cookieとlogin code。

### 22.2 想定事故と保証

| 事象 | Credleaseの効果 |
|---|---|
| `.env`がcommitされる | Profile参照しか漏れない |
| Codexが`.env`を読む | Profile名しか見えない |
| Childがenvironmentを読む | 短命JWTは見えるがparent keyは見えない |
| JWTがpromptへ混入 | TTL・scope・resourceで影響を限定 |
| SQLiteが流出 | raw parent keyを含まない |
| Repositoryが高権限Profileを参照 | project bindingとuser configで拒否可能 |
| Talos Admin APIへの接続 | child開始前にTalosを停止して露出を減らす |
| Browser URL履歴が流出 | JWTではなく短寿命・一回限りcodeのみ |
| Browser codeが再利用される | Backendのatomic consumeで拒否 |
| Keychainが侵害される | Local trust root侵害でありMVP防御範囲外 |
| 同一ユーザーprocessが`credlease token`を実行 | 完全防止しない |

### 22.3 残存リスク

- Leased tokenはBearerであり、有効中はコピー利用できる。
- 同一OSユーザーのprocessはCredlease CLIを起動できる。
- Local issuerをremote Backendが信頼するにはkey registrationまたは中央STSが必要。
- Talos signing keyまたはparent key侵害にはLocal MVPだけでは耐えない。
- 短命tokenで実行済みのwriteや保存データはtoken expiry後も残る。
- Browser session cookieをbrowser automationから完全に隠すことは本仕様の対象外。

## 23. テスト戦略

### 23.1 Test layers

1. **Unit tests**  
   URI parser、Profile validation、TTL clamp、claim生成、URL allowlist、redaction。

2. **Component tests**  
   Fake keyring、fake Talos HTTP server、runtime lifecycle、browser HTTP client。

3. **Integration tests**  
   実Talos binary + SQLite + OS keyring adapterまたはCI用isolated keyring。

4. **End-to-end acceptance tests**  
   Sample Backend、実JWT検証、browser session exchange、child process inspection。

5. **Security regression tests**  
   disk scan、log scan、environment scan、replay、redirect、race、crash cleanup。

### 23.2 Test fixtures

- `test-backend`: JWT scope/resource endpointとbrowser session endpointを持つGo server。
- `inspect-child`: environment、parent PID、open portsを検査してJSONを返すhelper。
- `fake-browser`: launch URLをcaptureするhelper。
- `fake-keyring`: memory-only test implementation。
- `secret-canary`: disk/logへ出てはならない一意のparent key marker。

## 24. 受け入れテスト

以下のP0 testをLocal MVPのrelease gateとする。

### AT-INIT-001: 初期化成功

**Given** 未初期化のユーザー環境  
**When** `credlease init`を実行する  
**Then** config、SQLite、JWKS、managed runtimeが作成される  
**And** HMAC secretとsigning keyがOS Credential Storeに保存される  
**And** commandはexit code 0を返す。

### AT-INIT-002: 再初期化のidempotency

**Given** 初期化済み環境  
**When** `credlease init`を再実行する  
**Then** parent key、signing key、DBを暗黙にrotateまたは破壊しない  
**And** exit code 0を返す。

### AT-SEC-001: Raw long-lived secretがdiskへ残らない

**Given** `secret-canary`を含むHMAC secret、signing key、parent keyで初期化済み  
**When** `init`、`profile add`、`token`、`exec`を完了する  
**Then** Credlease config/data/cache、SQLite、logs、audit、temporary directoryをbinary-safe scanしてもcanaryが存在しない。

### AT-PROFILE-001: Profile専用parent key

**Given** 2つのProfileを作成する  
**When** keyring entryとTalos metadataを確認する  
**Then** それぞれ異なるparent keyを持つ  
**And** Talos側scopeはProfile最大scopeを超えない。

### AT-REF-001: `.env` Reference解決

**Given** `.env`に`TOKEN=credlease://backend-a/dev`がある  
**When** `credlease exec --env-file .env -- inspect-child`を実行する  
**Then** childの`TOKEN`は署名検証可能なJWTである  
**And** `.env` fileは変更されていない。

### AT-REF-002: 未知Profileはfail closed

**Given** `.env`に未知のProfile参照がある  
**When** `credlease exec`を実行する  
**Then** childは起動されない  
**And** `CREDLEASE_PROFILE_NOT_FOUND`を返す  
**And** 親環境の同名secretへfallbackしない。

### AT-REF-003: Queryによる権限昇格拒否

**Given** `TOKEN=credlease://backend-a/dev?scope=admin&ttl=24h`  
**When** `credlease exec`を実行する  
**Then** childは起動されない  
**And** `CREDLEASE_REFERENCE_INVALID`を返す。

### AT-EXEC-001: Childへparent authorityを渡さない

**Given** 有効なprocess Profile  
**When** `inspect-child`を`credlease exec`で起動する  
**Then** leased JWTだけが指定envへ存在する  
**And** parent key、HMAC secret、signing private keyはchild environmentに存在しない。

### AT-EXEC-002: Talos停止後にchild起動

**Given** on-demand runtime  
**When** `credlease exec`で`inspect-child`を起動する  
**Then** childの起動時刻はTalos shutdown完了後である  
**And** childからTalos Admin portへ接続できない  
**And** loopback portが閉じている。

### AT-EXEC-003: Exit code伝播

**Given** exit code 42を返すchild command  
**When** `credlease exec -- <command>`を実行する  
**Then** Credleaseは42を返す。

### AT-EXEC-004: Signal伝播

**Given** 長時間動作するchild  
**When** CredleaseへSIGINTを送る  
**Then** childへSIGINTが伝播する  
**And** Credleaseはplatform標準の終了semanticを保持する。

### AT-JWT-001: TTL enforcement

**Given** TTL 5秒のtest Profile  
**When** 発行直後にBackendへrequestする  
**Then** requestは成功する  
**And** 5秒と許容clock skew経過後は401となる。

### AT-JWT-002: Scope enforcement

**Given** `document:read`のみのJWT  
**When** read endpointへrequestする  
**Then** 成功する  
**When** write endpointへrequestする  
**Then** 403となる。

### AT-JWT-003: Resource enforcement

**Given** Backend A用JWT  
**When** Backend B verifierへ提示する  
**Then** resource mismatchで拒否される。

### AT-JWKS-001: JWKSでの検証

**Given** `credlease jwks export`で生成したJWKS  
**When** sample BackendがJWTを検証する  
**Then** signatureと`kid`を検証できる。

### AT-LOG-001: Secret redaction

**Given** token issue成功・失敗・HTTP 500・Talos crashを発生させる  
**When** stdout、stderr、audit、log、crash outputをscanする  
**Then** JWT、parent key、Authorization header、HMAC secretが存在しない。

### AT-CRASH-001: Runtime crash cleanup

**Given** Talos起動中にCredlease processを強制終了する  
**When** 次回`credlease doctor --repair`を実行する  
**Then** stale process、lock、temporary secret fileをcleanupする  
**And** DB integrityを確認する。

### AT-CONCURRENCY-001: 同時発行

**Given** 同一installationで10並列の`credlease token`  
**When** 同時実行する  
**Then** deadlockしない  
**And** すべて有効なJWTを返す、またはdocumented lock timeoutを返す  
**And** SQLiteを破損しない。

### AT-BROWSER-001: Browser session成立

**Given** 有効なbrowser-session Profileとsample Backend  
**When** `credlease open admin-web/dev`を実行する  
**Then** exchange endpointへbootstrap JWTがAuthorization headerで送られる  
**And** fake browserがone-time code付きlaunch URLを受け取る  
**When** fake browserがcomplete URLへアクセスする  
**Then** HttpOnly session cookieが設定され  
**And** codeを含まないpost-login URLへ303 redirectされる。

### AT-BROWSER-002: JWTをURLへ含めない

**Given** `credlease open` flow  
**When** fake browser、Backend access log、redirect chainを検査する  
**Then** Talos JWTはURL、Referer、browser history向けURLへ存在しない。

### AT-BROWSER-003: Login codeは一回限り

**Given** 未使用のlogin code  
**When** complete endpointへ1回目のrequestを送る  
**Then** sessionが作成される  
**When** 同じcodeで2回目のrequestを送る  
**Then** generic 400または410で拒否される  
**And** 新しいsessionは作成されない。

### AT-BROWSER-004: Login code expiration

**Given** code TTL 2秒のtest Profile  
**When** 期限後にcomplete endpointへaccessする  
**Then** sessionは作成されない。

### AT-BROWSER-005: Bootstrap JWT replay拒否

**Given** 同一`credlease_session_id`を持つbootstrap JWT  
**When** exchange endpointへ2回送る  
**Then** 1回目だけcodeを発行し  
**And** 2回目をreplayとして拒否する。

### AT-BROWSER-006: Launch URL allowlist

**Given** Backendが`https://evil.example/`をlaunch URLとして返す  
**When** `credlease open`を実行する  
**Then** browserを起動せず  
**And** `CREDLEASE_BROWSER_URL_REJECTED`を返す。

### AT-BROWSER-007: Cookie security attributes

**Given** production HTTPS mode  
**When** complete endpointがsession cookieを返す  
**Then** cookieに`HttpOnly`、`Secure`、`SameSite=Lax`以上が設定される。

### AT-BROWSER-008: 任意redirect拒否

**Given** complete URLへ`redirect=https://evil.example`を追加する  
**When** endpointへaccessする  
**Then** Backendはその値を無視または拒否し  
**And** 固定post-login URL以外へredirectしない。

### AT-KEYRING-001: Keyring unavailable時のfail closed

**Given** OS Credential Storeが利用できない  
**When** `credlease init`またはtoken issueを実行する  
**Then** 平文file fallbackを作らず  
**And** `CREDLEASE_KEYRING_UNAVAILABLE`を返す。

### AT-RESET-001: Reset

**Given** 初期化済みinstallation  
**When** `credlease reset`を明示確認付きで実行する  
**Then** runtime、SQLite、profiles、JWKS、keyring entriesを削除する  
**And** Repository fileを削除しない。

## 25. Platform test matrix

| Platform | v0.1 Release gate | 備考 |
|---|---:|---|
| macOS latest two major versions | 必須 | Keychain、default browser、Chrome指定 |
| Ubuntu LTS current/previous | 必須 | Secret Service利用可能なdesktop session |
| Windows 11 | Preview | Credential Manager、process/signal差異を検証 |
| Headless Linux without Secret Service | 非対応 | fail closedを確認 |

Windowsをv0.1 GAへ含める場合は全P0 acceptance testを必須に引き上げる。

## 26. Definition of Done

Local MVP v0.1は次をすべて満たしたとき完了とする。

- P0 acceptance testsがTier 1 platformで全件pass。
- `go test ./...`、race detector、static analysisがpass。
- Talos versionとdigestがrelease manifestへpinされる。
- Third-party license noticesを同梱。
- Threat model、quickstart、uninstall、recovery docsがある。
- Sample Go Backendでprocess JWTとbrowser sessionの両方を確認できる。
- `.env`、SQLite、logs、temporary directoryへのsecret persistence regression testがCIで実行される。
- Security limitationsをREADMEの上位セクションへ記載する。

## 27. 実装順序

### Phase 1: Core credential lease

1. Config/data path。
2. Keyring abstraction。
3. Managed Talos download、digest verification、runtime lifecycle。
4. SQLite migration。
5. Profile CRUDとparent key issue。
6. Talos JWT derive adapter。
7. `token`。
8. Reference parser。
9. `exec`とsignal/exit code伝播。
10. JWKS exportとGo verifier。
11. Security regression tests。

### Phase 2: Browser session

1. Browser-session Profile。
2. `credlease open` HTTP client。
3. URL allowlistとbrowser opener。
4. Go `pkg/browsersession` middleware/store interface。
5. Sample Backendのexchange/complete endpoint。
6. Replay cacheとone-time code tests。
7. Cookie/redirect security tests。

### Phase 3: Distribution and ergonomics

1. `doctor`、`reset`、repair。
2. Homebrew/Scoop/package distribution。
3. Shell completion。
4. Windows support hardening。
5. Parent/signing key rotation。

## 28. 今後の構想

### v0.2: Local daemon and refresh

- Unix domain socket / Windows named pipe。
- `credlease credential-process <profile>`。
- SDK for Go、TypeScript、Python。
- memory-only token cache。
- optional user-presence confirmation。
- long-running process向けrefreshing token source。

### v0.3: Browser form integration

- Chrome Manifest V3 extension。
- Native Messaging Host。
- Origin-bound one-time fill lease。
- OS Credential StoreからID/passwordを取得。
- user gesture必須、default no-submit。

### v0.4: Remote STS / Team mode

```text
Developer
  ↓ Authorization Code + PKCE / Device Flow
credlease CLI
  ↓ RFC 8693-style Token Exchange
credlease-sts
  ↓ central policy
Central Talos
  ↓ short-lived JWT
Developer process / browser
```

- OIDC login。
- Central Profile registry。
- Remote Backend共通trust anchor。
- Team audit、rate limit、group/tenant policy。
- CI OIDC federation。
- local/remote modeで同じ`credlease://` UX。

### v1.0: Provider platform

- Talos以外のissuer adapter。
- OpenBao、AWS STS、GCP、Azure。
- DPoP/mTLS sender-constrained token。
- signed project manifests。
- organization profile distribution。
- optional egress broker。

## 29. 未決事項

1. Credleaseという名称を正式採用するか。
2. Talos artifact取得元と署名検証方式。
3. Linux Secret Serviceがlockedの場合のUX。
4. Raw tokenをTTYへ出す`token` commandのdefault policy。
5. Project bindingのdefaultとpath移動時の扱い。
6. Talos custom claimと標準`aud`の最終設計。
7. Parent key expiryとrotation周期。
8. Signing key rotation時のJWKS overlap期間。
9. Browser sessionのBackend store reference implementationをmemory、SQLite、Redisのどこまで提供するか。
10. Windowsをv0.1 GAへ含めるか。

## 30. 依存する外部仕様・実装

- Ory Talos: API keyのissue、verify、revoke、短命JWT/Macaroon deriveを担う。
- JWT / JWKS: Resource Serverによるoffline signature verification。
- OS Credential Store: raw long-lived secretの保存。
- OAuth security practice: browser URLへaccess tokenを置かず、短寿命のintermediate codeを用いる設計の参考。
- Chrome Native Messaging: 将来のlegacy password fillでextensionとnative processを接続する候補。

## 31. 一文での定義

> Credleaseは、長期credentialを`.env`や対象processへ置かず、ローカルの信頼anchorから実行単位の短命credentialまたはbrowser sessionを発行して貸し出すOSSである。
