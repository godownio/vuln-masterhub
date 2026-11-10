---
id: tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign
title: Galaxy + JsRpc 透明加解密与动态签名：Burp hook 自动改包重放
type: scenario
domain: tools
path: tools/burp
technique: galaxy-jsrpc-auto-encrypt-decrypt-dynamic-sign
aliases:
- Galaxy 自动加解密
- JsRpc 动态签名
- Burp 透明加解密
- requestId timestamp sign 自动更新
- AES CBC 报文加解密
- Jython Burp hook
- Galaxy HttpHook
tags:
- burp
- galaxy
- jsrpc
- websocket
- aes
- cbc
- signature
- requestid
- timestamp
- jython
- pentest
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:15:04+08:00'
  notes: 已对照原文与15张图核对：图01 请求头 requestId/timestamp/sign 与 Base64 密文、图03 AES CBC key/iv=1234567891234567、图04 拦截器中 r=Date.parse(new Date)/i=p()/s=MD5(n+i+r)/t.data=l(n)、图05 控制台验证、图06 window.requestId/window.v1/window.sign 注册、图07-08 regAction 与 127.0.0.1:12080 返回 time/id/sign、图09 Galaxy AES_CBC 模板、图10-13 四段 hook 与 JsRpc 调用、图14-15 明文改包重放效果，均与卡片一致。卡片已注明仅针对原文靶场与硬编码 key/iv、未标组件版本，未设置 versions。原子性：单一「Galaxy 四段 hook + JsRpc 浏览器代算动态签名」工具链场景，未过粗；与 autoDecoder+JsRpc、JS Hook+Bridge 等卡仅工具组合不同（dedup 均 new），dup-scan 无本卡 pair。未在本机安装 Galaxy/JsRpc 或对靶场执行。
---

## 一句话结论

目标站点的请求体用前端 AES-CBC 加密，且每个请求必须携带由 JS 生成的 `requestId`、`timestamp`、`sign`（`MD5(JSON.stringify(排序后的参数)+requestId+timestamp)`），在 Burp 里改包或重放会立即失效；把 Galaxy 的四个 Burp hook（请求/响应进出 Burp/服务端）与 JsRpc 组合：Galaxy 用提取的 key/iv 自动解密/加密请求与响应体，JsRpc 在已登录浏览器上下文里调用站点原始 JS 函数生成新的 `requestId/timestamp/sign` 并通过本地 HTTP 接口回填请求头，即可在 Burp 中看到明文、任意改参并自动重签重放。

## 原理

- **Galaxy 的四段 hook**：Galaxy 是 Burp 插件，按流量方向提供 `hook_request_to_burp`（客户端→Burp，解密请求体给 Burp 看）、`hook_request_to_server`（Burp→服务端，加密被修改的明文并更新签名）、`hook_response_to_burp`（服务端→Burp，解密响应）、`hook_response_to_client`（Burp→客户端，把明文响应重新加密）。hook 用 Jython 编写，可通过 `request.getBody()/setContent()/getHeaders()/setHeaders()` 读写报文。
- **请求体加密**：前端 `function l(t){ return a.a.AES.encrypt(t, key, {iv: iv, mode: CBC, padding: Pkcs7}).toString() }`，key/iv 均硬编码为 `1234567891234567`；服务端只接受 Base64 后的密文。Galaxy 模板（AES_CBC）填入相同 key/iv 即可在 Burp 侧解密/加密，不需要还原前端 AES 实现。
- **三个动态请求头**：前端在请求拦截器里：
  - `r = Date.parse(new Date)` → `timestamp`；
  - `n = JSON.stringify(v(t.data))`，其中 `v()` 会删除空值并对参数排序/归一化；
  - `i = p()` → 32 位随机 `requestId`（固定位置字符 + 随机字符）；
  - `s = a.a.MD5(n + i + r)` → `sign`；
  后端校验三者与密文的一致性，因此改包、重放、直接 Repeater 都会失败。
- **JsRpc 在浏览器里代算**：在页面控制台注入 JsRpc 客户端（WebSocket 连到本地 `127.0.0.1:12080`），把原函数挂到 `window`：`window.requestId=p; window.v1=v; window.sign=a.a.MD5`，再用 `demo.regAction("hello", ...)` 注册动作。Burp 每次把明文 body 作为 `param` 拼到 `http://127.0.0.1:12080/go?group=zzz&action=hello&param=`，浏览器端执行 `v1(param) → JSON.stringify → sign(...)` 并把 `{time,id,sign}` 回传。
- **为什么组合有效**：签名依赖页面运行时的 `sessionStorage`、时间、随机数与混淆后的 MD5 实现；与其在 Python 里复刻（易受混淆/动态逻辑影响），不如让浏览器执行原函数。JsRpc 只负责“算签名”，Galaxy 只负责“加解密与读写报文”，两者解耦。
- **GET 与 POST 区分**：站点只有 POST body 加密，GET 请求体为空但仍需签名；hook 中对 `request.getMethod()=="GET"` 直接放行或只更新请求头，对 POST 才做 Base64 解码/解密、再加密回写，避免把 GET 的明文误加密。

## 触发条件

- 目标 Web 应用请求/响应体由前端 JS 加密（AES-CBC 等），且请求头包含服务端强校验的签名/时间戳/随机数；
- 测试者能以合法账号打开页面，并在控制台注入 JsRpc 客户端（页面无严格 CSP 阻止 `ws://127.0.0.1:12080`）；
- 本地运行 JsRpc 服务端与 Burp + Galaxy 插件，浏览器可访问 `127.0.0.1:12080`；
- 能从 JS 中提取 AES key/iv（或改用 JsRpc 调用前端加密函数）；
- 签名函数的依赖（sessionStorage、全局对象、排序函数）在页面上下文中可用。

## 利用步骤

1. 抓包确认 POST body 为 Base64 密文，请求头含 `requestId/timestamp/sign`；改动任一参数或重放会失败。
2. 在浏览器 DevTools 全局搜索 `sign`/`requestId`/`timestamp`，在请求拦截器处下断点，确认 `r=Date.parse(new Date)`、`i=p()`、`s=MD5(n+i+r)`、`n=JSON.stringify(v(data))`、`t.data=l(n)`，并记录 AES key/iv 与 `l()` 实现。
3. 注入 JsRpc 客户端，注册原函数：`window.requestId=p; window.v1=v; window.sign=a.a.MD5`；再 `regAction("hello", function(resolve,param){ n=JSON.stringify(v1(param)); var time=Date.parse(new Date); var id=requestId(); var sg=sign(n+id+time).toString(); resolve({time:time.toString(),id:id,sign:sg}); })`。
4. 浏览器访问 `http://127.0.0.1:12080/go?group=zzz&action=hello&param=<明文>` 验证返回 JSON 的 `data` 中含 time/id/sign。
5. 配置 Galaxy 的 AES-CBC 模板：`ALGORITHM="AES/CBC/PKCS5Padding"`、`secret=iv=b"1234567891234567"`、`paramMap={"iv":iv}`、`jsonKey="data"`。
6. 编写 `hook_request_to_burp`：GET 直接返回；POST 时 `b64decode(body) → decrypt → setContent(明文)`。
7. 编写 `hook_request_to_server`：GET 走 JsRpc 空 body 只更新三个头；POST 时取 Burp 中明文 `request.getContent()`，把原始 body 作为 param 调 JsRpc 拿新头，`head.put` 覆盖 `sign/requestId/timestamp`，再 `encrypt(明文) → b64encode → setContent(密文)`。
8. 编写 `hook_response_to_burp`（解密响应）和 `hook_response_to_client`（重新加密响应），保持浏览器侧正常显示。
9. 在 Burp Repeater 中修改明文参数，Galaxy 自动重加密并重签，服务端返回正常业务数据（原文效果图：借阅记录查询、用户信息查询可直接重放）。

## PoC

JsRpc 浏览器端注册（原文）：

```javascript
window.requestId = p
window.v1 = v
window.sign = a.a.MD5

demo.regAction("hello", function (resolve, param) {
    n = JSON.stringify(v1(param))
    var time = Date.parse(new Date);
    var id = requestId()
    var sg = sign(n + id + time).toString()
    var data = {"time": "", "id": "", "sign": ""}
    data["time"] = time.toString()
    data["id"] = id
    data["sign"] = sg
    resolve(data);
})
```

Galaxy hook 关键片段（Jython）：

```python
from org.m2sec.core.outer import HttpClient

def hook_request_to_server(request):
    if request.getMethod() == "GET":
        burpRequestBody = ''
    else:
        data = request.getContent()
        burpRequestBody = request.getBody()

    url = "http://127.0.0.1:12080/go?group=zzz&action=hello&param="
    jsrpcRequest = request.of(url + burpRequestBody)
    jsrpcResponse = HttpClient.send(jsrpcRequest)
    headData = json.loads(jsrpcResponse.getJson()["data"])

    head = request.getHeaders()
    head.put("sign", headData["sign"])
    head.put("requestId", headData["id"])
    head.put("timestamp", headData["time"])
    request.setHeaders(head)

    if request.getMethod() != "GET":
        request.setContent(CodeUtil.b64encode(encrypt(data)))
    return request
```

## 变体与关联

- **变体**：加密算法不局限于 AES-CBC，可换 SM4/RSA/自定义混淆；Galaxy 也支持 Java/JS hook 与自定义模板。
- **变体**：签名函数无法直接暴露时，可在页面 hook 原请求拦截器，记录最近一次 `{body, headers}` 后重放/微调；或把 JsRpc 用于同时加密 body（不提取 key）。
- **变体**：同类工具链还有 autoDecoder + JsRpc、Sekiro（自建 WebSocket JSRPC）+ Yakit 热加载、Burp JS Hook + 本地 Bridge、burpy/pyro 等，选择取决于插件生态与是否需要双向加解密。
- **关联**：[[web-generic-auth-js-signature-jsrpc-autodecoder]]（JsRpc + autoDecoder 动态代签，本卡改用 Galaxy 并增加报文透明加解密）、[[web-generic-auth-sekiro-jsrpc-yakit-hotload-rensign-batch]]（Sekiro/Yakit 批量代签）、[[tools-burp-js-hook-bridge-traffic-encrypt-decrypt]]（JS hook + 本地 Bridge，不还原算法）、[[tools-burp-autodecoder-flask-custom-encrypt-decrypt-script]]（autoDecoder + Flask 自定义加解密）、[[tools-burp-burpy-pyro-python-auto-encrypt-decrypt]]（burpy/pyro 加解密）。

## 检测与防御

- **根本问题**：前端硬编码 AES key/iv 与签名密钥对用户完全可见，客户端加密/签名只能提高改包成本，不能作为安全边界；敏感校验必须在服务端完成。
- **服务端加固**：`requestId` 一次性且服务端生成/校验，`timestamp` 限制有效期并拒绝重复；签名密钥放服务端，使用 HMAC 而非前端 MD5；对同一会话的高频重放/参数变化做速率限制与告警。
- **检测**：短时间内同一 token 出现多个不同 `requestId`/`timestamp` 但参数高度相似的请求、来自同一浏览器的自动化重放、`sign` 正确但业务参数异常的组合，可作为 Burp 自动化改包/爆破特征；WAF 可对固定 UA + 高频参数变异做关联。
- **测试侧安全**：JsRpc 仅监听 `127.0.0.1`，不要暴露到公网；使用隔离浏览器 profile/测试账号；Galaxy hook 中的 key/iv 与抓包数据按敏感信息处理。
- **纵深防御**：对关键业务增加服务端二次校验（验证码、MFA、操作审计）；不要仅依赖客户端签名判断请求合法性。
