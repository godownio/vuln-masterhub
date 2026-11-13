---
id: tools-burp-autodecoder-flask-sekiro-jsrpc-body-encrypt-decrypt
title: autoDecoder + Flask 中间层 + Sekiro 浏览器 JSRPC：不还原前端 AES 算法，运行时调用页面加解密函数实现 Burp 请求/响应透明加解密
type: scenario
domain: tools
path: tools/burp
technique: autodecoder-flask-sekiro-jsrpc-body-crypto
tags:
- burp
- autodecoder
- sekiro
- jsrpc
- flask
- websocket
- aes
- encryption
- decryption
- frontend-encryption
- pentest
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V509
  verified_at: '2026-11-11T04:54:42+08:00'
  notes: 已对照原文 content.md 与 16 张截图核对：图02 请求/响应均密文；图03 启动器定位 getData；图04 拦截器 e.data=Object(r["b"])(e.data,b.dfg,b.cvb)；图05/06 加密函数为 CryptoJS AES-CBC+ZeroPadding+Base64（s 返回密文、o 解密）；图07/08 Sekiro 分组与浏览器 JS 文档（wss 改 ws）；图09/10 bind_client 语义与设备列表；图16 autoDecoder 成功解密出明文请求/响应。卡内 Flask/Sekiro 代码与原文一致（已修正原文括号笔误与 aes_dec 调用 enc 的笔误）。dedup：与 Flask 复刻算法卡、MCP/Skill 生成 JSRPC 工件卡、js-hook-bridge 卡均为不同机制（运行时浏览器 oracle vs Python 复刻/自动生成/hook 上报），非重复。非组件问题，无 affected_versions。原文未在本机执行。
url: /docs/tools/burp/tools-burp-autodecoder-flask-sekiro-jsrpc-body-encrypt-decrypt/
draft: false
kb_aliases:
- autoDecoder Sekiro 加解密
- Flask 转发 sekiro aes_enc
- 浏览器 JS 环境透明加解密
- 前端 AES 请求响应全密文
- Burp 接前端加密函数
- sekiro registerAction 加解密
---

## 一句话结论

当目标请求与响应体全部是前端 AES 密文、且 key/iv 动态生成时，不必在 Python 里复刻算法：在页面控制台把 debug 出的加密/解密函数挂到 `window`，用 Sekiro 浏览器 JS 环境注册 `aes_enc`/`aes_dec` 动作，再写一个 Flask 接口把 autoDecoder 传来的 `dataBody` 连同 key/iv 转发给 Sekiro 的 HTTP 接口取回结果，autoDecoder 配置成该接口后即可在 Burp 的拦截、重放里自动解密查看与改包重加密。

## 原理

- **定位加密函数**：在 Burp 看到请求/响应均为密文后，Chrome DevTools 的网络面板用“启动器”列定位发请求的业务函数（示例 `getData`），在请求拦截器处下断点，F10 单步到 `e.data = Object(r["b"])(e.data, b.dfg, b.cvb)`——`Object(r["b"])` 就是加密函数，第二、三个参数是 key/iv；控制台打印它并双击即可跟进函数定义（示例为 CryptoJS AES-CBC + ZeroPadding + Base64 输出），解密函数同理。
- **运行时复用而非复刻**：加密函数闭包依赖页面运行时（模块变量、key/iv 对象），在控制台执行 `window.enc = Object(r["b"])`、`window.dec = Object(r["a"])` 把函数提升到全局，Sekiro 的 action 里直接调用它们，省去还原混淆算法和依赖。
- **Sekiro 浏览器 JS 环境**：页面注入 `SekiroClient` 后，它用 WebSocket 主动连接本地/远程 Sekiro 服务端（`/business/register?group=分组&clientId=...`），`client.registerAction("aes_enc", function(request, resolve, reject){ resolve(enc(request["enc_par"], ...)) })` 注册动作；调用方通过 HTTP 接口 `/business/invoke`（或 SDK 封装）传参拿到返回值。本地 RPC 时把官方示例的 `wss://` 改为 `ws://`。
- **Flask 二层接口**：autoDecoder 只约定 `dataBody`/`dataHeaders` 这类表单字段，不直接说 Sekiro 协议；Flask 的 `/aes_encode` 取 `dataBody`，附带 `group`、`sekiro_token`、`action`、`enc_par`、`bind_client`、`key`、`iv` 等参数 POST 给 Sekiro，解析响应 JSON 的 `data` 字段返回给 autoDecoder。这样算法变化时只改浏览器端，不用改 Python。
- **bind_client 的必要性**：Sekiro 默认按 one-by-one 轮转把调用分发给同组的多个设备/页面；多标签页或多设备在线时，加解密可能落到不同 key/iv 的页面导致乱码或失败。`bind_client` 指定 clientId 后所有调用固定在同一设备，配合页面内的同一份 key/iv。
- **autoDecoder 上游代理**：autoDecoder 的“接口加解密”把 Burp 的请求/响应体交给 Flask 的加密/解密接口，Burp 拦截、Repeater、Intruder 中看到的就是明文；改完的参数发送前自动加密。
- **为什么有效**：前端加密只提高改包成本，密钥与算法对浏览器完全可见；把浏览器变成“加解密 oracle”后，Burp 侧不需要理解算法即可任意改包。

## 触发条件

- 目标请求/响应体由前端 JS 加密（本文为 AES-CBC + ZeroPadding + Base64，整体 body 一个密文）。
- 测试者能以合法账号打开目标页面，并在控制台注入 Sekiro 客户端（页面 CSP 未阻止 `ws://` 连接）。
- 本地运行 Sekiro 服务端与 Flask，浏览器可访问对应端口；Burp 所在机器可访问 Flask。
- 能通过断点/控制台拿到加密、解密函数（或至少能调用它们）与当前 key/iv。
- key/iv 在页面生命周期内稳定（动态生成问题见关联卡）。

## 利用步骤

1. 抓包确认请求与响应均为密文，记录字段形态（整体 body 还是 JSON 字段）。
2. DevTools 网络面板按启动器定位业务函数（如 `getData`），在请求拦截器下断点，找出加密调用 `e.data = Object(r["b"])(e.data, key, iv)`；控制台双击跟进函数实现，确认算法、模式、填充、编码与 key/iv 来源。
3. 在控制台执行 `window.enc = Object(r["b"])`、`window.dec = Object(r["a"])`（变量名按实际闭包访问方式调整），用样例密文/明文验证两个函数可用。
4. 在 Sekiro 管理页新建分组（避免匿名分组性能差），在页面注入浏览器 JS 客户端：`new SekiroClient("ws://<host>:<port>/business/register?group=<组>&clientId=" + Math.random())`。
5. 注册动作：`client.registerAction("aes_enc", ...)` 调 `window.enc(request["enc_par"], key, iv)`，`client.registerAction("aes_dec", ...)` 调 `window.dec(...)`；key/iv 可先硬编码，动态场景改为从页面存储动态读取（见关联卡）。
6. 编写 Flask `/aes_encode` 与 `/aes_decode`：取 `request.form.get('dataBody')`，组装 `group`、`sekiro_token`、`action`、`enc_par`、`bind_client`、`key`、`iv` POST 到 Sekiro HTTP 接口，返回 `json.loads(res.text)['data']`。
7. 在 autoDecoder 中把加密/解密接口指向 Flask，选择作用模块（Proxy/Repeater/Intruder），保存配置；在 Burp 中重放请求，确认看到明文并可改包重加密。
8. 页面刷新后如 key/iv 变化导致失败，改用从页面存储动态读取 key/iv 的 action（见关联卡），或让注入页与目标页保持同一浏览器会话。

## PoC

```javascript
// 1) 页面控制台：把前端加密/解密函数提升到全局
window.enc = Object(r["b"]);   // AES 加密：enc(plaintext, key, iv)，CryptoJS AES-CBC + ZeroPadding + Base64
window.dec = Object(r["a"]);   // AES 解密

// 2) 注入 Sekiro 浏览器客户端并注册动作（本地 RPC 时 wss 改 ws）
var client = new SekiroClient(
  "ws://localhost:端口/business/register?group=分组名&clientId=" + Math.random());

client.registerAction("aes_enc", function (request, resolve, reject) { // 加密
  resolve(enc(request["enc_par"], request["key"], request["iv"]));
});
client.registerAction("aes_dec", function (request, resolve, reject) { // 解密
  resolve(dec(request["dec_par"], request["key"], request["iv"]));
});
```

```python
# 3) Flask 二层接口（加密；解密同理）
@app.route('/aes_encode', methods=["POST"])
def encrypt():
    param = request.form.get('dataBody')      # autoDecoder 传来的 POST body
    data = {
        "group": "分组名",
        "sekiro_token": "xxxxx",              # Sekiro 管理页
        "action": "aes_enc",                  # 注册的 action 名
        "enc_par": param,
        "bind_client": "设备ID",              # 固定转发到同一浏览器页面
        "key": key,
        "iv": iv
    }
    res = requests.post(url, data)
    return json.loads(res.text)['data']       # 返回密文/明文给 autoDecoder
```

## 变体与关联

- **Flask 直接复刻算法**：在 Python 中用 CryptoJS 等价库实现 AES，适合算法简单且 key/iv 固定的场景（[[tools-burp-autodecoder-flask-custom-encrypt-decrypt-script]]）；本卡适合算法混淆或 key/iv 依赖浏览器环境的情况。
- **JSRPC 框架变体**：Hlclient JsRpc（[[web-generic-auth-js-signature-jsrpc-autodecoder]] 的代签场景）、Galaxy + JsRpc（[[tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign]]）、Sekiro + Yakit（[[web-generic-auth-sekiro-jsrpc-yakit-hotload-rensign-batch]]）；本卡是 Sekiro + autoDecoder/Flask 的 body 加解密组合。
- **key/iv 动态问题**：页面刷新后 sessionStorage 中的 key/iv 重置会导致硬编码失效，处理见 [[web-generic-auth-frontend-aes-key-iv-sessionstorage-localstorage-ua-stability]]。
- **边界**：页面关闭/刷新后 Sekiro 连接断开、window 上的函数丢失，需重新注入；若服务端对请求签名/防重放有额外校验，加密之外还要同步重算签名；Flask 与 Sekiro 仅监听本机，避免暴露。

## 检测与防御

- **检测**：同一会话/账号出现密文结构重复或固定 key 特征的请求；本机存在 Sekiro 默认端口（5612 等）的 WebSocket 长连接与 `/business/register` 访问；Burp 侧自动化改包特征（参数枚举、请求速率异常、无页面操作轨迹）。
- **检测**：服务端对同一 token 的密文重放、参数变异与高频调用做风控；对比正常客户端设备指纹/UA/Referer 序列。
- **防御**：不要把客户端加密当作安全边界；敏感校验与授权必须在服务端完成；使用服务端下发短期密钥、请求签名、nonce/时间窗与频控；对关键业务增加二次验证（MFA/验证码/操作审计）。
- **测试侧安全**：Sekiro 与 Flask 只监听 `127.0.0.1` 或内网，测试结束关闭；key/iv 与抓包内容按敏感数据处理。
