---
id: web-generic-jwt-kid-absolute-path-source-key-disclosure
title: JWT kid 绝对路径读取源码取硬编码密钥：黑名单只挡打印不挡加载
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-kid-absolute-path-source-disclosure
aliases:
- kid 绝对路径
- os.path.join 绝对路径覆盖
- JWT 源码泄露取密钥
- withheld 黑名单绕过
- 硬编码签名密钥
- kid 文件读取
tags:
- jwt
- kid
- path-traversal
- source-disclosure
- hardcoded-key
- authentication-bypass
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:55:51+08:00'
  notes: 已对照原文与 3 张 data-URI 图（已解码到 ingest/staging/92907_imgs）核对：kid=nope.key 报错 KEY LOAD FAILED '/app/keys/nope.key' 证实 os.path.join(KEYS_DIR,kid) 拼接；kid=/etc/passwd 401/3964 内容被打印，flag.txt 与 editor.key 401/withheld；kid=/app/app.py 读到 load_key/is_protected 逻辑与硬编码 EDITOR_KEY=ch-pr0t0type-edit0r-s1gn1ng-k3y-d0-n0t-sh1p，is_protected 只控制是否打印；用该 key 重签 role=editor 的 HS256 JWT 后 /admin 返回 sun{h0tw1r3d_4dm1n_jwt}，与图03 一致。未复跑；无 CVE/版本；frontmatter 无 sources/source_url。
---

## 一句话结论

服务端用 `os.path.join(KEYS_DIR, kid)` 把 JWT Header 的 `kid` 拼成密钥文件路径；当 `kid` 以 `/` 开头时 `os.path.join` 会丢弃 `KEYS_DIR`，直接读取任意绝对路径。读取 `/app/app.py` 源码即可拿到硬编码的编辑器签名密钥，再用它重签 `role=editor` 的 HS256 JWT 通过 `/admin`；所谓 `withheld` 黑名单只决定“是否打印”，文件其实早已被读取。

## 原理

- **kid 是攻击者可控的未验证 Header**：JWT 的 Header 在验签前就可被客户端任意修改；服务端若把它当文件名/查询条件使用，就引入了注入面。
- **os.path.join 的绝对路径覆盖语义**：`os.path.join('/app/keys', '/etc/passwd')` 返回 `/etc/passwd`，第二个参数以 `/` 开头时前面整段被丢弃；因此连 `../` 都不需要，一个绝对路径即可越出密钥目录。
- **报错泄露路径构造方式**：`kid=nope.key` 返回 `KEY LOAD FAILED :: [Errno 2] ... '/app/keys/nope.key'`，直接暴露了拼接规则与密钥目录。
- **黑名单只挡输出不挡读取**：代码在 `try` 中先 `load_key(kid)` 读取文件；异常分支里 `is_protected(kid)` 只设置 `withheld=True` 决定是否打印内容。文件内容已经读入内存，固定黑名单（如 `flag.txt`、`editor.key`）并不能阻止读取，只是不展示。
- **源码是黑名单外的高价值目标**：`/app/app.py` 不在黑名单，且源码里硬编码了 `EDITOR_KEY`；同一把钥匙还被写进 `editor.key` 数据文件——数据文件被挡，但生成它的代码没被挡，等价于密钥泄露。
- **为什么最终可伪造**：HS256 是对 `header.payload` 做 HMAC-SHA256；拿到密钥后把 payload 的 `role` 改为 `editor` 重新签名，服务端验签通过并信任 `role`。

## 触发条件

- JWT 验证流程使用 Header `kid` 选择密钥文件，且直接拼接路径。
- 拼接使用 `os.path.join`、字符串拼接或类似方式，未限制 `kid` 为白名单文件名。
- 服务端对敏感文件采用“读取后不打印”的黑名单，而不是在读取前拒绝。
- 应用源码/配置中硬编码了签名密钥，或密钥可由可读文件推导。
- 服务端先验签再读 role，攻击者需要一把有效密钥。

## 利用步骤

1. 正常登录获取一个低权限 JWT，base64url 解码 Header/Payload，确认 `kid` 字段与 `role`。
2. 把 `kid` 改成不存在的文件名，观察报错是否泄露完整路径（确认路径拼接规则）。
3. 用绝对路径读取 `/etc/passwd` 验证任意文件读取；再读取应用源码（如 `/app/app.py`）。
4. 在源码中搜索密钥常量、`EDITOR_KEY`、`SECRET`、`token_hex`、写密钥文件的逻辑；记录硬编码密钥。
5. 构造 payload 把 `role` 改为 `editor`，用该密钥做 HS256 签名，`kid` 可设为 `editor.key` 或任意值（取决于服务端校验逻辑）。
6. 携带伪造 JWT 访问 `/admin`，确认越权成功并读取 flag/敏感数据。

## PoC

```http
POST /login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

name=reader
```

```python
import jwt, requests

# 1) 探测路径拼接：kid=nope.key -> 报错泄露 /app/keys/nope.key
# 2) 任意文件读取：kid=/etc/passwd
# 3) 读源码：kid=/app/app.py
EDITOR_KEY = "ch-pr0t0type-edit0r-s1gn1ng-k3y-d0-n0t-sh1p"  # 从源码中读到
token = jwt.encode(
    {"sub": "reader", "role": "editor"},
    EDITOR_KEY,
    algorithm="HS256",
    headers={"kid": "editor.key", "typ": "JWT"},
)
r = requests.get("http://target/admin", cookies={"token": token})
print(r.status_code, r.text)
```

原文实测：`kid=/etc/passwd` 内容被原样打印；`kid=/app/flag.txt` 与 `kid=/app/keys/editor.key` 返回 `withheld`；`kid=/app/app.py` 读到源码与 `EDITOR_KEY`，重签后 `/admin` 返回 `sun{h0tw1r3d_4dm1n_jwt}`。

## 变体与关联

- **路径构造变体**：`os.path.join` 绝对路径覆盖、字符串拼接 `KEYS_DIR + kid`、`../` 穿越、URL 编码/双重编码、Windows 盘符/UNC 路径。
- **密钥来源变体**：源码硬编码、环境变量、配置文件、同目录可读文件、密钥文件与源码重复存储。
- **黑名单绕过变体**：黑名单只挡打印 → 读源码/配置；黑名单按文件名匹配 → 用绝对路径/软链接/大小写/编码绕过；黑名单在读取后判断 → 寻找未列入的等价文件。
- **关联卡片**：[[web-generic-jwt-kid-injection]]（kid SQL 注入与基础路径穿越）、[[web-generic-jwt-jku-header-hijack]]（Header 控制公钥来源）、[[web-generic-jwt-alg-none-bypass]]（无密钥绕过）。
- **边界**：若 `kid` 走白名单映射、使用 `basename()`、`realpath` + 目录边界校验，或密钥不在可读文件中，本链不成立。

## 检测与防御

- **检测**：JWT Header 的 `kid` 含 `/`、`..`、绝对路径、异常长字符串；`kid` 探测产生大量文件不存在错误；错误响应泄露服务器路径；同一账号突然出现 `role` 提升。
- **防御**：`kid` 只做白名单映射（`{"reader": key1, "editor": key2}`），绝不拼接路径；必须用文件时先 `basename()`，再用 `realpath` 校验位于密钥目录内；黑名单必须在读取前拒绝，且不依赖固定路径表。
- **密钥管理**：签名密钥放 KMS/环境变量并定期轮换，禁止硬编码在源码；不要把同一密钥同时写入源码和数据文件；错误信息不回显服务器路径。
- **验证**：修复后用 `kid=/etc/passwd`、`kid=../../app.py`、`kid=/app/app.py` 回归，确认均被拒绝且不泄露内容。
