---
id: tools-burp-js-hook-bridge-traffic-encrypt-decrypt
title: JS Hook + 本地 Bridge + Burp 扩展：不还原算法直接加解密 Web 流量
type: scenario
domain: tools
path: tools/burp
technique: js-hook-bridge-burp-encrypt-decrypt
tags:
- burp
- javascript
- js-hook
- rpc
- encryption
- decryption
- tooling
- api-testing
- mitm
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:37:25+08:00'
  notes: 已对照原文及图01-13核对：encrypt/decrypt wrapper 上报 /report、注入客户端轮询 /task、Burp 扩展 Bridge Decryptor Pro 右键 Encrypt Content/Send Decrypted to Repeater、Decrypted 标签与明文 test/test1 回填均与截图一致；Bridge 端点契约与原文代码一致；未复跑
url: /docs/tools/burp/tools-burp-js-hook-bridge-traffic-encrypt-decrypt/
draft: false
kb_aliases:
- JS_HOOK 流量加解密框架
- Bridge Decryptor Pro
- encrypt/decrypt hook
- 浏览器 RPC 加解密
- Burp Decrypted tab
- 前端加密流量改包
---

## 一句话结论

不用还原前端的加密算法：用 Burp 等中间人把页面里的 `encrypt`/`decrypt` 函数包一层 hook，把每次调用的明文/密文上报到本地 `127.0.0.1:9999` 的 Bridge；Burp 扩展再通过 RPC 让浏览器里的原函数加密选中的明文或解密响应，从而在 Repeater/Decrypted 标签里直接改包、读明文。

## 原理

- **hook 原函数而不是重写算法**：页面加载后执行 `window.raw_encrypt = encrypt; encrypt = function(x){ ... }`，wrapper 先调用原函数得到密文，再把 `{plaintext, ciphertext}` POST 到本地 Bridge，最后返回密文；`decrypt` 同理反向上报。这样 key/iv、混淆、WASM、运行时环境全部由浏览器负责，测试者只关心“明文进、密文出”。
- **明文/密文映射表**：Bridge 保存 hook 上报的对应关系，Burp 扩展据此把请求体里的密文替换成明文展示（Decrypted tab），或把响应里的密文还原为明文。
- **RPC 让 Burp 主动调用页面函数**：注入的 JS 客户端定时 `GET http://127.0.0.1:9999/task` 轮询任务；Burp 扩展在用户右键 “Encrypt Content” 或点击响应的 “Decrypted” 标签时创建 `ENCRYPT`/`DECRYPT` 任务（带 `id` 与 `payload`）；浏览器执行 `window.raw_encrypt(task.payload)`/`raw_decrypt`，把结果 POST 回 `/task`，扩展再回填到 Burp 请求/响应。
- **为什么可行**：前端加密的密钥与算法必须存在于浏览器运行时；hook 直接复用真实函数，避免了本地重写 JS 时的编码、填充、`this` 绑定、动态 key 差异。Bridge 只是浏览器与 Burp 之间的本地 HTTP 通道，不参与密码学计算。
- **数据流**：Burp 注入 hook → 页面发请求时 wrapper 上报明文/密文 → Bridge 存储 → 扩展展示 Decrypted；用户改明文 → 扩展创建加密任务 → 浏览器原函数加密 → 扩展回填 → 发出合法密文请求；响应密文 → 扩展创建解密任务 → 浏览器原函数解密 → 展示明文。

## 触发条件

- 目标 Web 应用的请求/响应由前端 JS 加密/解密，且加密/解密函数可在页面全局作用域访问或被 hook 捕获。
- 能通过 Burp 代理、浏览器扩展或 DevTools 向页面注入 hook 代码（需在业务函数调用前完成包装）。
- 本地可运行 Bridge 服务（默认 9999，提供 `/report` 与 `/task`），浏览器能访问 `127.0.0.1:9999`，且 Bridge 允许目标页 Origin 的 CORS 请求。
- Burp 加载对应 Python 扩展（Bridge Decryptor Pro），请求/响应编辑界面出现 Decrypted 标签。
- 目标没有严格 CSP 阻止 `connect-src http://127.0.0.1:9999`，也没有完整性校验/反调试阻止 hook。

## 利用步骤

1. 在页面 JS 中定位加密/解密函数（全局搜索 `encrypt`/`decrypt`、XHR 断点、调用栈），确认函数名与参数/返回格式。
2. 在函数定义之后注入 hook：保存 `window.raw_encrypt`/`raw_decrypt`，用 wrapper 替换原函数，wrapper 内调用原函数并 `fetch` 上报到 Bridge `/report`。
3. 启动本地 Bridge（9999），加载 Burp 扩展（扩展类型 Python，选择 `main.py`）；扩展负责 `/report` 存储、`/task` 队列与 Burp 右键菜单/Decrypted 标签。
4. 在浏览器正常操作，hook 自动上报明文/密文；Burp 请求/响应出现 Decrypted 标签，可查看明文。
5. 修改请求明文：右键选中明文 → 扩展菜单 `Bridge Decryptor Pro → Encrypt Content`（或 `Send Decrypted to Repeater`），扩展创建 ENCRYPT 任务；页面注入的轮询客户端调用 `window.raw_encrypt`，结果回填到请求体后发送。
6. 查看响应明文：点击响应的 `Decrypted` 标签，扩展创建 DECRYPT 任务，浏览器调用 `window.raw_decrypt`，扩展用返回明文渲染。
7. 修改参数后重复 5–6，完成重放/越权/爆破等测试；测试结束移除 hook 与扩展，关闭 Bridge。

## PoC

```javascript
// 注入到页面：hook encrypt/decrypt 并上报（最小版）
window.raw_encrypt = encrypt;
encrypt = function (x) {
  const cipher = window.raw_encrypt(x);
  fetch('http://127.0.0.1:9999/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plaintext: x, ciphertext: cipher })
  });
  return cipher;
};

window.raw_decrypt = decrypt;
decrypt = function (x) {
  const plain = window.raw_decrypt(x);
  fetch('http://127.0.0.1:9999/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plaintext: plain, ciphertext: x })
  });
  return plain;
};
```

```javascript
// 注入到页面：轮询 Bridge 任务并回传结果
(async function poll() {
  try {
    const r = await fetch('http://127.0.0.1:9999/task');
    const task = await r.json();
    if (task.type !== 'IDLE') {
      let result = null;
      if (task.type === 'ENCRYPT') result = window.raw_encrypt(task.payload);
      if (task.type === 'DECRYPT') result = window.raw_decrypt(task.payload);
      if (result !== null) {
        await fetch('http://127.0.0.1:9999/task', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: task.id, result })
        });
      }
    }
  } catch (e) {}
  setTimeout(poll, 300);
})();
```

```text
Bridge 端点契约：
POST /report  {"plaintext": "...", "ciphertext": "..."}   # hook 上报映射
GET  /task                                                # 浏览器轮询，返回 {type:"IDLE"|"ENCRYPT"|"DECRYPT", id, payload}
POST /task    {"id": "...", "result": "..."}              # 浏览器回传加解密结果
```

原文在 Burp + 浏览器环境完成请求加密、响应解密与 Repeater 改包；本卡未复跑。

## 变体与关联

- **变体：hook 底层 API**：若业务函数被闭包隐藏，可 hook `crypto.subtle.encrypt/decrypt`、`CryptoJS.AES.encrypt/decrypt`、`XMLHttpRequest.prototype.send`、`window.fetch`，从参数/返回值提取明文与密文。
- **变体：Proxy/defineProperty**：用 `Proxy` 包裹对象方法或 `Object.defineProperty` 替换属性，保持函数引用与 `this` 绑定。
- **变体：WebSocket/长轮询**：把 `/task` 轮询换成 WebSocket，降低延迟；Bridge 仍只做消息转发。
- **关联**：[[tools-burp-encrypted-api-proxy-decrypt-resign]]（mitmproxy 上下游代理透明解密/重签，适合不依赖浏览器的场景）、[[code-analysis-reverse-obfuscation-mcp-skill-jsrpc-autodecoder-automation]]（JSRPC + Flask + autoDecoder 的自动化版本）、[[code-analysis-reverse-frontend-request-response-encryption-automation]]（XHR 断点定位 + PyExecJS 本地复现）。
- **边界**：函数不可全局访问/被内联时 hook 失败；CSP `connect-src` 阻止 localhost；页面在 hook 前已缓存函数引用；WASM/Worker 内加密需在对应上下文注入；Bridge 必须只监听 127.0.0.1，避免把加解密能力暴露给他人。

## 检测与防御

- 这是授权测试工具；对防守方，前端加密只是提高逆向成本，不能替代 TLS、服务端鉴权与参数校验。
- 加固：启用 CSP 限制 `connect-src`，避免页面任意向 localhost 发请求；对关键 JS 做完整性校验/SRI；服务端校验密文来源、时间戳、nonce 与业务权限，不能因为“前端加密”就信任请求。
- 检测：页面出现对 `127.0.0.1:9999` 的异常 fetch、`raw_encrypt`/`raw_decrypt` 全局变量、请求/响应体在短时间内的明文-密文规律变化；Burp 侧出现大量 Decrypted 标签与自动化重放。
- 响应：若发现测试/攻击流量，审计相关接口的越权与重放风险，轮换会话与密钥，检查是否有敏感数据被批量拉取。
