---
id: web-generic-auth-miniprogram-md5-charsort-sign-forgery
title: 小程序签名 = MD5(逐字符排序(AppId+AppSecret+Ticks+Nonce+参数串))：硬编码密钥复刻后任意改参重签
type: scenario
domain: web
path: web/generic/auth
technique: miniprogram-md5-charsort-sign-forgery
aliases:
- 小程序 Sign 逆向
- 逐字符排序签名
- Ticks Nonce 签名复现
- AppSecret 硬编码签名
- 小程序请求签名伪造
- 签名参数串重放
tags:
- web
- auth
- api
- signature
- md5
- miniprogram
- wechat
- js-reverse
- client-side-secret
- replay
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:21:31+08:00'
  notes: 已对照原文与唯一图片核对：图 01 被模糊，仅可见 function a(o,n){...return o.Sign=c,o.Ticks=a,o.Nonce=i,o}，签名函数与正文一致；AppId+AppSecret+Ticks+Nonce+参数串、逐字符排序、MD5 大写、参数按 key 首字符排序、对象/数组只拼 key 均按原文正文整理。已校正原文 Nonce 生成式的错误结论：Math.random 式取值范围为 (1,1e8]，并非负数，实际弱点是 Math.random 非密码学随机且客户端可控。未验证点：原文未给出目标产品/版本，未在真实接口复算签名；图片主体模糊，算法细节以正文为准。
---

## 一句话结论

小程序的请求签名把 `AppId`、硬编码在客户端的 `AppSecret`、`Ticks`、`Nonce` 与业务参数串拼成一个字符串，逐字符排序后取 MD5 大写；反编译或调试还原这套规则后，攻击者可在 Python/Burp 脚本中为任意篡改过的业务参数重算合法 `Sign`，且 `Ticks` 可固定复用、`Nonce` 由客户端自造，服务端若不做时间窗与 nonce 去重，签名就退化为可任意伪造的参数格式校验。

## 原理

- 抓包可见请求头 `Sign`、`Ticks`（毫秒时间戳）、`Nonce`（随机数）；改动 `branchId`、`userId` 等业务参数后服务端返回 401，说明 `Sign` 覆盖了请求体，而不只是固定因子。
- 静态检索小程序反编译产物（`rg -i "sign|signature|nonce|timestamp|ticks|secret|hmac|md5|sha" --type js`）定位到 `common/request.js`；调用链为 `wx.request -> 请求拦截器 -> dealHeader -> 签名生成 -> 发送请求`。
- 签名串构造：`signString = AppId + AppSecret + Ticks + Nonce + paramString`，其中 `paramString` 由业务参数按 key 排序后拼接：`Object.keys(params).sort((e,r) => e.charCodeAt(0) - r.charCodeAt(0))`，普通值拼 `key + value`，`null`/数组/对象只拼 key 名。
- 关键设计：把整个 `signString` 拆成单字符数组排序（`sorted(list(signString))`），去空格后做 MD5 并转大写。逐字符排序意味着字符顺序完全不参与签名，签名只取决于字符多重集合；因此参数键顺序交换后签名仍相同，任意互为字母异位词的拼接串也会得到同一签名。
- 为什么可伪造：`AppSecret` 硬编码在小程序包中，算法也随客户端分发；签名所需的每个输入（AppId、AppSecret、Ticks、Nonce、参数）攻击者都能获得或自造，服务端无法区分官方客户端与复刻脚本。签名只证明“知道这套公开算法”，不证明“请求来自合法客户端”。
- 参数完整性也有缺口：对象/数组类型的值只把 key 名纳入签名，嵌套值被篡改不会改变 `Sign`；若业务接口读取嵌套字段，可在不重算签名的情况下改值。
- 重放条件：原文验证 `Ticks` 设置较大时间戳后仍可重复使用，且每次请求只需更换业务参数与 `Nonce`；说明服务端没有严格的时间窗校验与 nonce 一次性消费，签名请求可被批量重放/改写。
- 原文称 `Nonce` 生成式 `(Math.random()*(1-1e8)+1e8)` 会产生负数，但按该式取值范围是 `(1, 1e8]`，并非负数；实际弱点是使用非密码学随机源 `Math.random`，且 nonce 完全由客户端控制。

## 触发条件

- 目标为微信小程序或类似前端应用，请求头带 `Sign`/`Ticks`/`Nonce`（或同义字段），签名错误时返回 401 或“签名验证失败”。
- 签名逻辑位于 JS 层，可通过 wxapkg 解密反编译（如 wxappUnpacker、unveilr）或微信开发者工具断点获得。
- 签名密钥（本例 `AppSecret`）硬编码在客户端，或签名只使用请求中可见的字段，不存在服务端独占密钥或动态挑战。
- 服务端不严格校验时间戳窗口，或接受较大的未来时间戳；`Nonce` 不绑定会话、不做已用去重。
- 攻击者持有访问目标接口所需的会话/Token（若接口要求登录）。

## 利用步骤

1. 抓取一个正常请求，记录 `AppId`、`Sign`、`Ticks`、`Nonce`、`Openid` 等头与 JSON body；修改任一业务参数重发，确认 401，证明签名覆盖参数。
2. 获取小程序包并解密反编译：主包/分包得到 `app-service.js` 等 JS；用 ripgrep 按 `sign`、`nonce`、`ticks`、`secret`、`md5` 等关键词定位请求封装文件。
3. 静态阅读 `dealHeader` 与签名函数，记录参数序列化规则（按 key 首字符排序、对象/数组只拼 key）、拼接顺序、字符级排序、MD5 大小写与空格处理。
4. 在微信开发者工具中对请求拦截器、`dealHeader`、MD5 计算前后下断点，观察真实入参与返回值；混淆的单字母变量以实际字符串为准，不能凭直觉拼。
5. 用 Python 复刻算法，先对原始抓包请求复算，必须与抓包 `Sign` 完全一致再继续；不一致时逐项核对 key 排序依据、嵌套值处理、字符排序与大小写。
6. 修改业务参数（如 `userid`、`branchId`），生成新的 `Nonce` 并复用或新造 `Ticks`，重算 `Sign` 后发送；把逻辑写成 Burp 插件/脚本，实现拦截、改包、自动重签。
7. 在授权范围内批量验证其它接口；若响应成功，评估越权/数据篡改的实际影响并留存请求响应证据。

## PoC

Python 复刻签名（按原文逻辑整理，字段名需按目标调整）：

```python
import hashlib
import random
import time


def serialize_params(params):
    if not params:
        return ""
    # 原文按 key 的第一个字符 ASCII 排序（不是完整 key 字典序）
    sorted_keys = sorted(params.keys(), key=lambda x: ord(x[0]))
    out = []
    for key in sorted_keys:
        value = params[key]
        if value is None or isinstance(value, (list, dict)):
            out.append(key)          # 对象/数组只拼 key 名
        else:
            out.append(key + str(value))
    return "".join(out)


def generate_signature(app_id, app_secret, params, ticks, nonce):
    sign_string = app_id + app_secret + str(ticks) + nonce + serialize_params(params)
    # 逐字符排序；原文随后去掉所有空格
    sorted_string = "".join(sorted(list(sign_string))).replace(" ", "")
    return hashlib.md5(sorted_string.encode("utf-8")).hexdigest().upper()


def gen_nonce():
    # 原文用 Math.random 派生；范围 (1, 1e8]，仅作格式复刻
    return str(int(random.random() * (1 - 100000000) + 100000000))


params = {"userid": 1107, "branchId": "001"}
ticks = int(time.time() * 1000)
nonce = gen_nonce()
print(generate_signature(APP_ID, APP_SECRET, params, ticks, nonce))
```

请求头示例（字段名与顺序按目标抓包）：

```http
POST /mp/AssistantMessage/unreadcount HTTP/1.1
Host: target
Appid: <APP_ID>
Sign: <重算后的 32 位大写 MD5>
Ticks: <毫秒时间戳，可复用较大值>
Nonce: <客户端自造随机数>
Openid: <会话中的 openid>
Content-Type: application/json;charset=UTF-8

{"userid": 1107}
```

说明：原文未给出目标产品与版本；Python 复刻需先用原始请求校验成功。JavaScript 的字符排序按 UTF-16 code unit，Python 按 Unicode code point，对 BMP 字符一致，含 emoji 等非 BMP 字符时需改用等价排序。

## 变体与关联

- 变体：只按 key 首字符排序时，首字符相同的 key 顺序不稳定；由于最终还会做字符级排序，这个排序其实是冗余设计，但也意味着任意字符排列（字母异位词）都能得到相同签名。
- 变体：对象/数组只拼 key 名，嵌套值不在签名范围内；可先测“只改嵌套字段、不改 Sign”是否被服务端接受。
- 变体：`Ticks` 可固定复用、`Nonce` 仅校验格式不校验消费时，同一签名可长期重放；服务端若只防篡改不防重放，还可改造成重放类业务漏洞。
- 变体：签名算法换成 SHA1/SHA256、HMAC、RSA，或密钥藏在本地加密配置/AES 解密后的 config 中，逆向路径不同、结论一致。
- 关联：[[web-generic-auth-miniprogram-local-config-signature-forgery]]（本地加密配置恢复 appKey 后伪造 HMAC 签名）、[[web-generic-auth-miniprogram-hardcoded-hawk-authorization-forgery]]（硬编码 Hawk 凭据伪造 Authorization）、[[web-generic-auth-miniprogram-digest-md5-path-timestamp]]（无密钥 digest）、[[web-generic-auth-nested-md5-sign-reverse-forgery]]（嵌套序列化 + 二次 MD5）、[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（客户端 nonce + 无密钥 SHA1）。
- 边界：服务端使用仅自己持有的 HMAC 密钥、签名覆盖 method/path/body hash 且时间戳/nonce 严格校验并一次性消费、密钥由服务端按会话动态下发并绑定设备时，本手法不成立。

## 检测与防御

- 检测：前端 JS 中出现 `AppSecret`、`Ticks`、`Nonce`、MD5/字符排序拼接逻辑；同一 `Ticks`/`Nonce` 在大量请求中重复；签名校验通过但业务参数分布异常、请求节奏脚本化；非官方客户端来源或 IP/设备画像突变。
- 防御：签名改用服务端独占密钥的 HMAC-SHA256（或非对称签名），覆盖 HTTP 方法、路径、query、body hash、时间戳与 nonce；密钥不下发客户端，客户端只做传输封装。
- 防御：`Ticks` 使用短时间窗（如 ±5 分钟）并拒绝异常大/未来时间戳；`Nonce` 由服务端签发或绑定会话，服务端用 Redis 等持久化已用 nonce 并设 TTL。
- 防御：签名只做完整性校验，不能替代鉴权；业务接口仍需服务端会话身份与对象级授权，禁止信任 body 里的 `userid` 等身份字段。
- 加固：对小程序包做混淆/完整性校验仅提高逆向成本，不能替代服务端信任边界；对批量改包重签行为做限速与告警。
