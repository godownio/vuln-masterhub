---
id: web-nodejs-fs-readfile-proc-symlink-filter-bypass
title: Node.js fs.readFile 过滤绝对路径与 ..：借 .config/bin/process_informations → /proc 软链接读 /proc/self/root 下任意文件
type: scenario
domain: web
path: web/nodejs
technique: nodejs-readfile-proc-symlink-filter-bypass
tags:
- nodejs
- express
- arbitrary-file-read
- path-filter-bypass
- symlink
- proc
- lfi
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T12:35:35+08:00'
  notes: 已对照 app.js 的 startsWith("/")/includes("..")/includes("../") 过滤、init.sh 的 ln -s /proc .config/bin/process_informations 与截图 25-27 的 self/cmdline、self/environ、self/root/home/leila/.ssh/id_rsa 请求逐项核对；链路由哈希长度扩展先取得 admin，再读文件，原文打通；未复现。
url: /docs/web/nodejs/web-nodejs-fs-readfile-proc-symlink-filter-bypass/
draft: false
kb_aliases:
- Node.js 任意文件读取绕过
- /proc/self/root 软链接
- process_informations
- fs.readFile 过滤绕过
- 相对路径读 /proc
- leila id_rsa
---

## 一句话结论

Express 的 `/file/get` 只检查 `file.startsWith("/")`、`file.includes("..")`、`file.includes("../")` 就调用 `fs.readFile(file)`；但初始化脚本 `init.sh` 在应用目录创建了 `ln -s /proc .config/bin/process_informations`，于是请求 `.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa` 既不以 `/` 开头也不含 `..`，`fs.readFile` 会沿软链接进入 `/proc/self/root`，以 Node 进程权限读取其可访问的任意文件（本例读到 leila 的 SSH 私钥、`/proc/self/environ`、`/proc/self/cmdline`）。

## 原理

- **词法过滤 vs 文件系统解析**：代码对用户传入的字符串做字面检查，阻止绝对路径和 `..`；但操作系统解析路径时会跟随符号链接。`/proc/self/root` 是一个指向当前进程根目录的魔术链接，`/proc/self/environ`、`/proc/self/cmdline` 等也是内核生成的特殊文件。
- **软链接来源**：`init.sh` 中有 `ln -s /proc .config/bin/process_informations`，在应用工作目录（`/var/www/api`）下创建了 `.config/bin/process_informations -> /proc`。攻击者不需要自己创建链接，直接使用该已存在的链接即可。
- **路径构造**：`.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa`
  - 以 `.` 开头，不匹配 `startsWith("/")`；
  - 不含 `..`，不触发 `includes("..")`；
  - `self` 指当前 Node 进程；`root` 指该进程的根目录；后续路径按正常文件系统解析；
  - Node 以 leila 用户运行，因此能读取 leila 家目录下的私钥（文件权限允许）。
- **可读面**：同一技巧可读 `self/environ`（环境变量/密钥）、`self/cmdline`（启动参数）、`self/maps`（内存布局）、`self/cwd`、`self/fd/N`（打开的文件描述符）等；若进程以 root 运行，则可读 root 可访问的文件。
- **前置认证**：该应用的 `/file/get` 还要求 `identification`/`ihash` 头通过 SHA256 签名与 `::admin:True` 检查；本例先通过哈希长度扩展伪造 admin 身份（见关联卡），再调用文件读取。文件读取本身是独立的路径过滤绕过原语。

## 触发条件

- Node.js/Express 应用把用户可控路径传给 `fs.readFile`/`fs.createReadStream` 等，并仅用字符串前缀/子串黑名单过滤。
- 应用工作目录或其子目录存在指向 `/proc`（或其他敏感目录）的软链接；或攻击者能通过其他功能创建这样的链接。
- 应用进程对目标文件有读权限。
- 若接口有认证，攻击者需先通过认证绕过/拿到低权会话。

## 利用步骤

1. 枚举应用目录/公开文件，寻找 `.config`、`process_informations` 等异常软链接（`ls -la`、错误信息、源码/初始化脚本）。
2. 构造相对路径：`.config/bin/process_informations/self/cmdline`、`.../self/environ`，确认读取成功。
3. 读取目标用户家目录：`.config/bin/process_informations/self/root/home/<user>/.ssh/id_rsa`，保存私钥。
4. 用私钥 SSH 登录目标用户，继续主机枚举。
5. 也可读 `self/maps`、`self/cwd`、`self/fd/*` 辅助后续利用；注意 `fs.readFile` 对特殊文件可能返回截断/空内容，必要时改用 `createReadStream`/多次读。

## PoC

```http
GET /file/get?file=.config/bin/process_informations/self/cmdline HTTP/1.1
Host: 10.129.30.104:3000
identification: <通过认证的 identification>
ihash: <对应 hash>
```

```http
GET /file/get?file=.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa HTTP/1.1
Host: 10.129.30.104:3000
identification: <通过认证的 identification>
ihash: <对应 hash>
```

响应中 `message` 字段即文件内容；SSH 私钥以 `-----BEGIN OPENSSH PRIVATE KEY-----` 开头。

```bash
# 保存私钥后
chmod 600 leila_ssh
ssh -i leila_ssh leila@ouija.htb
```

## 变体与关联

- **其他软链接**：`/proc` 之外，应用目录中指向 `/`、`/etc`、`/home`、日志目录的软链接同样可被利用；枚举 `find . -type l -ls`。
- **其他特殊路径**：`/proc/self/cwd`（当前工作目录）、`/proc/self/fd/<n>`（已打开的文件，可用于读被删除/受限文件）、`/dev/fd/<n>`。
- **过滤绕过**：若同时过滤 `.` 或软链接名，可尝试 URL 编码、Unicode、大小写、空字节（旧 Node）、`path.normalize` 差异等。
- 关联：[[web-nodejs-jspdf-node-readfile-arbitrary-file-read]]（Node `fs.readFile` 直接路径读取的另一入口）、[[crypto-hash-sha256-length-extension-append-field]]（本例先伪造 admin 身份）。

## 检测与防御

- **代码**：不要用字符串黑名单做路径安全；用 `fs.realpath`/`path.resolve` 得到真实路径，再检查是否位于允许目录内；拒绝解析到 `/proc`、`/sys`、`/dev` 等特殊文件系统；对 `fs.readFile` 调用做统一封装。
- **部署**：应用目录不要放指向 `/proc`、`/etc`、`/home` 的软链接；用最小权限用户运行；把 `/proc` 的敏感项通过容器/挂载隐藏（只读、`hidepid`）。
- **检测**：请求参数中出现 `process_informations`、`/proc/self`、`self/root`、`environ`、`id_rsa` 等；Node 进程对 `/proc/*/environ`、`/proc/*/root` 的异常读取；应用目录中出现异常软链接。
