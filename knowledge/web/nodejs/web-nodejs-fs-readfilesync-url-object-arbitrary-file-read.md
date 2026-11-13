---
id: web-nodejs-fs-readfilesync-url-object-arbitrary-file-read
title: 'fs.readFileSync 接受 file: URL 对象：参数注入 file[href]/file[origin]/file[protocol]/file[pathname] 读取任意文件'
type: scenario
domain: web
path: web/nodejs
technique: fs-readfilesync-url-object-injection-file-read
aliases:
- file[href] file[pathname]
- readFileSync URL 对象
- file 协议读取本地文件
- fs 路径参数类型混淆
- Node.js 任意文件读取
tags:
- nodejs
- fs
- file-read
- url
- query-parser
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V632
  verified_at: '2026-11-13T00:45:01+08:00'
  notes: 已对照原文12511全文与13张截图核对：URL对象条件（href/origin truthy、protocol=file:、hostname为空、pathname非空）与原文五条完全一致，PoC与原文 payload file[href]=a&file[origin]=1&file[protocol]=file:&file[hostname]=&file[pathname]=... 一致。dedup的related候选 jspdf(0.904)/proc-symlink-filter(0.914)/upload-api-fileurl(0.891) 触发层与机制均不同，非同链。原文未标注组件版本，affected_versions为空。小瑕疵：触发条件处 fs.readFileSync/fs.readFile/fs.readFileSync 重复书写，第三项应为 readFile，不影响技术内容。未在真实环境复现。
---

## 一句话结论

Node.js 的 `fs.readFileSync`/`fs.readFile` 等路径 API 允许 path 参数是 WHATWG URL 对象；当应用把用户可控的参数对象（如 Express 解析出的 `file[href]=...`）直接传给 fs 时，攻击者提供 `href`、`origin`、`protocol=file:`、空的 `hostname` 和非空 `pathname`，即可读取服务器任意本地文件，而不需要在请求里出现可能被过滤的 `file:///...` 字符串。

## 原理

- Node.js fs 文档允许路径参数为 `string | Buffer | URL | integer(fd)`。内部判断“是否为 URL 对象”的条件很宽松：对象只要 `href` 与 `origin` 均为 truthy 就按 URL 处理，随后交给 `fileURLToPath`。
- `fileURLToPath` 只接受 `protocol === 'file:'`；在 Windows 上 `hostname` 非空会被当作 UNC 路径 `\\hostname\path` 去远程加载，因此要求 hostname 为空；在 Linux 上 hostname 必须为空或 `localhost`；最终使用 `pathname` 作为本地文件路径。
- 也就是说，一个普通的 JS 对象 `{href:'a', origin:'1', protocol:'file:', hostname:'', pathname:'/etc/passwd'}` 就足以让 fs 把它当 URL 解析并读取 `pathname`。
- Express 的 extended 查询解析器（qs）支持嵌套语法，`file[href]=a&file[origin]=1&file[protocol]=file:&file[hostname]=&file[pathname]=/etc/passwd` 会原样构造出上述对象；应用若把 `req.query.file` 直接传入 fs，即形成任意文件读取。
- 相比直接传 `file:///etc/passwd` 字符串，用参数对象构造的价值在于：绕开“参数必须是普通路径”或“禁止 file: 字符串”的浅层过滤，并适配那些只接收对象（非字符串）的调用形态。

## 触发条件

- 应用把 `req.query.file`、`req.body.file` 等用户可控对象直接传给 `fs.readFileSync`/`fs.readFile`/`fs.readFileSync` 封装函数，未做 `String()` 强转或类型校验。
- 应用使用支持嵌套对象的查询/表单解析器（Express extended/qs 等）。
- Node 进程对目标文件有读权限。

## 利用步骤

1. 找到把请求参数传给 fs 读取的接口（文件预览、模板加载、图片读取、下载等）。
2. 构造满足 URL 对象条件的参数：`href` 非空、`origin` 非空、`protocol=file:`、`hostname` 为空、`pathname` 为目标文件路径。
3. 发送请求，读取内容随业务响应返回（回显、下载、错误信息等）。
4. Windows 目标把 `pathname` 换成 `C:/Windows/win.ini` 等本地路径；hostname 保持为空。

## PoC

请求：

```
GET /read?file[href]=a&file[origin]=1&file[protocol]=file:&file[hostname]=&file[pathname]=/etc/passwd HTTP/1.1
Host: target
```

对应的易受攻击服务端写法：

```javascript
const fs = require('fs');
app.get('/read', (req, res) => {
    res.send(fs.readFileSync(req.query.file, 'utf8'));
});
```

## 变体与关联

- 若接口只取 `file.pathname` 再自行读取，则直接传路径字符串即可，不需要构造完整 URL 对象。
- fs 也接受 `file://` 字符串；当过滤只禁字符串形态而解析器又允许嵌套参数时，改传对象是更有效的绕过。
- Windows 下 hostname 非空会走 UNC 路径（`\\host\path`），在允许出站 SMB 的环境中可指向远程共享；原文按“hostname 为空”给出条件。
- 关联 [[web-nodejs-jspdf-node-readfile-arbitrary-file-read]]、[[web-nodejs-postcss-sourcemappingurl-arbitrary-file-read]]：readFileSync 路径直入造成文件读取的其它入口。

## 检测与防御

- 对 fs 路径参数强制 `typeof path === 'string'`（或 Buffer），拒绝对象/数组；必要时先 `String()` 归一化。
- 读取前用 `path.resolve` 归一化并校验落在白名单目录内；禁止 `file:` URL 进入 fs。
- 关闭不必要的嵌套参数解析；对参数做 schema 校验。
- 检测请求中出现 `file[href]=`、`[protocol]=file:`、`[pathname]=` 等嵌套字段组合。
