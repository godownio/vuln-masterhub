---
id: ctf-reverse-wasm-login-date-now-timestamp-bruteforce
title: WASM 前端登录时间戳签名：覆盖 Date.now 在给定时间窗内爆破 MD5 前缀
type: scenario
domain: ctf
path: ctf/reverse
technique: wasm-date-now-timestamp-bruteforce
aliases:
- WASM 登录爆破
- Date.now 覆盖
- MD5 前缀爆破
- 自定义 Base64 表
- wasm-login
- WebAssembly 认证逆向
tags:
- reverse
- wasm
- webassembly
- timestamp
- bruteforce
- md5
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:25+08:00'
  notes: 已对照原文前端/WASM 截图与爆破脚本核对；MD5 前缀与时间窗一致；PoC 未复跑。
---

## 一句话结论

前端登录页不向后端发请求，而是用 WASM 导出的 `authenticate(username,password)` 生成一段依赖 `Date.now` 的签名，再把签名 JSON 做 MD5、检查前缀 `ccaf33e3512e31f3`；由于 WASM 通过 `env.Date.now` 导入时间，攻击者可以在 Node.js 中加载同一 WASM、把 `Date.now` 覆盖为可控值，在题目给出的“2025-12-22 00:00–06:00”时间窗内逐毫秒爆破，命中 MD5 前缀后即得 flag。

## 原理

- **纯前端校验**：抓包没有登录请求；`index.html` 的 `simulateServerRequest` 把 `authenticate` 返回的 JSON 做 `JSON.stringify`，再算 `MD5`，只要结果以 `ccaf33e3512e31f3` 开头就 `resolve({success:true})`。
- **WASM 导出认证**：`release.wasm` 导出 `authenticate`，内部用自定义 Base64 码表 `NhR4UJ+z5qFGiTCaAIDYwZ0dLl6PEXKgostxuMv8rHBp3n9emjQf1cWb2/VkS7yO` 编码密码等字段，并导入 `env.Date.now` 取当前时间；签名完全由输入和时间戳决定。
- **时间窗提示**：题目说明登录发生在“2025年12月第三个周末爆肝到周一凌晨”，即 2025-12-22 00:00–06:00（+08:00）；时间戳是唯一未知量，窗口约 6 小时 = 21,600,000 毫秒，对本地 WASM 调用是可接受规模。
- **为什么能覆盖时间**：WASM 的导入对象由宿主 JS 提供；`WebAssembly.instantiate(module, {env:{Date:{now:()=>this.currentTime}}})` 即可让 WASM 每次调用读到攻击者设定的毫秒值，不需要修改 WASM 本身。
- **为什么不用逆自定义 Base64**：如果直接调用导出的 `authenticate`，编码细节由 WASM 自己处理；自定义码表只在需要手工构造输入/复现签名时才重要。爆破法把 WASM 当作黑盒 oracle。
- **命中判据**：对每个候选时间戳 `t`，调用 `authenticate("admin","admin")`，对返回字符串做 MD5，检查前缀；命中后该时间戳对应的 MD5 即 flag 内容（题目要求 32 位小写十六进制）。

## 触发条件

- 登录校验完全在客户端完成，或客户端签名决定服务端/前端是否放行。
- 认证逻辑编译为 WASM，且时间源通过 import（如 `env.Date.now`）注入，宿主可覆盖。
- 签名只依赖少量可枚举输入（时间戳、用户名、密码），且已知大致时间窗口。
- 能拿到 `release.wasm` 与前端 JS，能在 Node.js 中实例化。
- 校验是 MD5 前缀/等值比较，爆破可行且无速率限制（本地计算）。

## 利用步骤

1. 分析 `index.html`/`release.js`，定位 `simulateServerRequest` 的 MD5 前缀判断与 `authenticate` 调用。
2. 用 `wasm2wat` 或反编译查看 `authenticate` 的 import/export，确认 `env.Date.now` 与自定义 Base64 码表；记录导出函数签名。
3. 在 Node.js 中读取 `release.wasm`，用 `WebAssembly.compile/instantiate` 加载，imports 提供可变的 `Date.now`、空的 `console.log`、`abort`。
4. 实现 AssemblyScript 字符串读写（`__new`、`__pin`、`__unpin`，字符串长度在 `ptr-4`，UTF-16），或直接复用原文的 `WasmInterop`。
5. 设定时间窗起止（如 `2025-12-22T00:00:00+08:00` 到 `06:00:00+08:00`），逐毫秒设置 `currentTime`，调用 `authenticate('admin','admin')`，计算 MD5 并比较前缀。
6. 命中后输出时间戳、返回字符串和 MD5；按题目格式提交 `flag{md5}`。

## PoC

原文 Node.js 脚本的核心逻辑（精简）：

```javascript
const fs = require('fs');
const crypto = require('crypto');

const wasmBuffer = fs.readFileSync('./build/release.wasm');
let currentTime = 0;

const imports = {
  env: {
    abort: () => { throw new Error('abort'); },
    'console.log': () => {},
    'Date.now': () => currentTime,
  },
};

(async () => {
  const { instance } = await WebAssembly.instantiate(wasmBuffer, imports);
  const e = instance.exports;

  function readString(ptr) {
    if (!ptr) return null;
    const U32 = new Uint32Array(e.memory.buffer);
    const U16 = new Uint16Array(e.memory.buffer);
    const len = U32[(ptr - 4) >>> 2] >>> 1;
    const start = ptr >>> 1;
    let s = '';
    for (let i = 0; i < len; i++) s += String.fromCharCode(U16[start + i]);
    return s;
  }
  function allocString(str) {
    const ptr = e.__new(str.length << 1, 2) >>> 0;
    const U16 = new Uint16Array(e.memory.buffer);
    for (let i = 0; i < str.length; i++) U16[(ptr >>> 1) + i] = str.charCodeAt(i);
    return ptr;
  }
  function authenticate(user, pass) {
    const u = allocString(user), p = allocString(pass);
    e.__pin(u); e.__pin(p);
    try { return readString(e.authenticate(u, p) >>> 0); }
    finally { e.__unpin(u); e.__unpin(p); }
  }

  const start = new Date('2025-12-22T00:00:00+08:00').getTime();
  const end   = new Date('2025-12-22T06:00:00+08:00').getTime();
  for (let t = start; t <= end; t++) {
    currentTime = t;
    const result = authenticate('admin', 'admin');
    const hash = crypto.createHash('md5').update(result).digest('hex');
    if (hash.startsWith('ccaf33e3512e31f3')) {
      console.log('timestamp:', t, 'md5:', hash);
      console.log('flag{' + hash + '}');
      break;
    }
  }
})();
```

原文最终结果：`flag{ccaf33e3512e31f36228f0b97ccbc8f1}`。

## 变体与关联

- 变体：时间单位可能是秒、毫秒或 `performance.now()`；先确认 import 的函数名和单位。
- 变体：随机源可能是 `Math.random`/`crypto.getRandomValues`，同样可在宿主侧覆盖或固定种子。
- 变体：若校验不是 MD5 前缀而是等值/签名验证，可先逆向自定义 Base64 码表和字段拼接顺序，再离线构造。
- 关联：[[ctf-reverse-wasm-login-fnv1a-feistel-xorshift-keystream]]（另一种 WASM 登录逆向）、[[web-generic-auth-client-nonce-weak-sha1-signature-forgery]]（客户端 nonce/签名可复现）、[[web-generic-auth-login-bruteforce-response-payload]]（登录爆破与时间戳 payload 变换）。
- 边界：时间窗过大（如数年）时逐毫秒爆破不可行，需要进一步缩小范围或逆向签名结构；若 WASM 使用不可覆盖的 `performance.now`/`Date` 内部实现，需 patch 或复刻算法。

## 检测与防御

- **架构**：认证必须在服务端完成；客户端只做输入预处理。不要用客户端本地计算的结果决定是否放行。
- **时间/签名**：服务端签发一次性 nonce 并校验有效期，签名覆盖 nonce + 时间 + 请求体；限制尝试频率。
- **逆向对抗**：不要把完整认证逻辑和密钥放在 WASM/JS 中；即使混淆，本地代码最终可被 instrument。
- **检测**：登录页无网络请求却返回成功、前端出现 `MD5`/`startsWith` 前缀比较、WASM 导入 `Date.now`/`Math.random` 等可覆盖时间源；异常高频本地计算/自动化浏览器。
