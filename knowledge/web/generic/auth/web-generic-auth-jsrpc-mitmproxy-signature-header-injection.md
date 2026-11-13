---
id: web-generic-auth-jsrpc-mitmproxy-signature-header-injection
title: JS 断点暴露内部签名函数 + JsRpc + mitmproxy 上游代理：为 Burp 请求自动注入动态签名头
type: scenario
domain: web
path: web/generic/auth
technique: jsrpc-mitmproxy-dynamic-signature-header
aliases:
- JsRpc mitmproxy 联动
- mitmproxy 自动加签
- 签名头自动注入
- 断点暴露函数 window._
- Burp 上游代理动态签名
tags:
- api
- signature
- js-reverse
- jsrpc
- mitmproxy
- burp
- brute-force
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V611
  verified_at: '2026-11-12T19:47:03+08:00'
  notes: 已对照原文全文与17张图核对：图02/03四个签名头（Nonce/Custappid/Timestamp/Signature）、图04全局搜索定位chunk、图05签名函数_()、图06全局调用ReferenceError、图07/08断点作用域调用成功、图09 window._=_后全局可用、图10/11 Hlclient连接与regAction、图12 /go返回JSON、图13 Python requests取签名、图14 .mitmproxy证书、图15 Burp上游代理127.0.0.1:8081、图16/17 Burp原值与经mitmproxy改写后的四头对比。卡片PoC与原文一致（脚本名encrypt.js记为rpc.py）。dedup：既有js-signature-jsrpc-autodecoder为JSRPC+Flask+autoDecoder集成，本卡为JSRPC+mitmproxy上游代理request(flow)注入四头；KB既有按集成工具分卡（Galaxy/Sekiro/SignMe等），判定related非同链，保留。frontmatter无sources/source_url。未实际运行RPC/mitmproxy/Burp。
---

## 一句话结论

当接口校验 `Custappid/Timestamp/Signature/Nonce` 等前端生成的动态签名头时，可在浏览器断点处把闭包内的签名函数挂到 `window`，用 JsRpc（Hlclient）注册为 WebSocket 远程动作；再把 mitmproxy 作为 Burp 的上游代理，在 mitmproxy 脚本中调用本地 RPC 获取新签名并改写请求头，从而让 Burp 的爆破/改包请求始终带合法签名。

## 原理

- 签名函数常定义在 webpack 模块闭包中，全局不可见，但函数内部持有 `custAppId`、签名密钥、nonce 生成逻辑等；在发送请求的代码行下断点，即可在断点暂停时的作用域内调用它。
- 断点作用域内执行 `window._ = _`（或等价赋值）把内部函数泄露为全局，之后无需断点也能调用。
- JsRpc 的 `jsEnv.js` 在页面注入 `Hlclient`，与本机 `ws://127.0.0.1:12080/ws` 建立 WebSocket；`regAction` 注册的动作在页面上下文执行，HTTP 接口 `/go?group=&name=&action=` 可同步取回结果。
- mitmproxy 作为 Burp 的上游代理：Burp 把请求发给 mitmproxy → mitmproxy 的 `request(flow)` 钩子调用 JSRPC 取最新签名并设置请求头 → 转发到目标。这样无需修改 Burp 插件，也无需理解签名算法细节，只需复用页面原生函数。
- 之所以可行：签名校验只证明“请求由持有前端代码的一方生成”，而攻击者在浏览器中就能执行同一段代码；nonce/timestamp 由原函数一并重算，服务端的一次性/时间窗校验也被同步满足。

## 触发条件

- 目标请求带前端动态生成的签名头/字段，且服务端校验（改动任一字段即失败）。
- 攻击者可在浏览器中打开页面并下断点（需已登录或可访问登录页）。
- 签名函数可通过断点作用域暴露，且页面会话保持存活。
- 本地可运行 JsRpc 与 mitmproxy（Python 3.10+），且 mitmproxy 证书被 Burp/系统信任。

## 利用步骤

1. 抓包确认四个头（示例 `Custappid`、`Timestamp`、`Signature`、`Nonce`），任意改动响应失败，说明服务端校验。
2. DevTools 全局搜索 `Signature`/`Signature:` 定位签名函数（示例 `_()`），在调用处下断点并触发请求。
3. 断点暂停后在 Console 调用 `_()` 验证可用，然后执行 `window._ = _` 暴露为全局，放行断点。
4. 注入 JsRpc 的 `jsEnv.js`，连接 `var demo = new Hlclient("ws://127.0.0.1:12080/ws?group=group1&name=code")`。
5. 注册动作：`demo.regAction("getinfo", function(resolve){ resolve(JSON.stringify(_())) })`，用 `http://localhost:12080/go?...&action=getinfo` 验证返回 JSON。
6. 编写 mitmproxy 脚本：`request(flow)` 中 POST 调用 RPC，`eval` 解析后设置 `Nonce/Custappid/Timestamp/Signature` 四个头。
7. `mitmproxy -p 8081 -s rpc.py` 启动，把 Burp 的上游代理设为 `127.0.0.1:8081`；此后 Burp 发往目标的请求都会被自动加签，可直接进 Intruder 爆破验证码发送/校验接口。

## PoC

```javascript
// 1) 断点作用域内暴露内部签名函数
window._ = _;

// 2) JsRpc 注册远程动作
var demo = new Hlclient("ws://127.0.0.1:12080/ws?group=group1&name=code");
demo.regAction("getinfo", function (resolve) {
    var infos = _();
    resolve(JSON.stringify(infos));
});
```

```python
# mitmproxy 脚本 rpc.py
import requests

def get_rpc():
    url = "http://127.0.0.1:12080/go"
    data = {"group": "group1", "name": "code", "action": "getinfo"}
    return requests.post(url, data=data).json()["data"]

def request(flow):
    result = eval(get_rpc())
    flow.request.headers["Nonce"] = result["nonce"]
    flow.request.headers["Custappid"] = result["custAppId"]
    flow.request.headers["Timestamp"] = str(result["timestamp"])
    flow.request.headers["Signature"] = result["signature"]
```

```bash
mitmproxy -p 8081 -s rpc.py
# Burp: Settings → Network → Upstream Proxy Servers → 127.0.0.1:8081
```

## 变体与关联

- 变体：不修改 Burp 上游代理，改用 autoDecoder/Flask 或 Burp 插件（Galaxy/SignMe）在 Burp 内直接代签。
- 变体：签名算法简单且无环境依赖时，用 Python/Node 复刻算法；JsRpc 适合混淆严重或依赖浏览器环境。
- 关联：[[web-generic-auth-js-signature-jsrpc-autodecoder]]（同一 JSRPC 代签思路，集成方式为 autoDecoder+Flask）、[[tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign]]、[[web-generic-auth-sekiro-jsrpc-yakit-hotload-rensign-batch]]。
- 边界：页面刷新/作用域变化需重新暴露；服务端若做设备指纹或验证码风控，签名合法也不足以自动爆破。

## 检测与防御

- 检测：同一会话高频请求且签名/时间戳/nonce 全部合法；来自本地代理的批量请求；参数枚举速率异常。
- 防御：不要把签名密钥放在前端；签名仅作完整性辅助，授权在服务端做对象/角色校验；时间戳窗口 + nonce 一次性校验 + 频控/验证码风控。
