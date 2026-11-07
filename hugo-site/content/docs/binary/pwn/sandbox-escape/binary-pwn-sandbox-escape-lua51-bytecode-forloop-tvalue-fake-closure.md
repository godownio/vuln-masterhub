---
id: binary-pwn-sandbox-escape-lua51-bytecode-forloop-tvalue-fake-closure
title: Lua 5.1 字节码沙箱逃逸：OP_FORLOOP 类型混淆泄露对象地址，伪造 LClosure/TValue 实现任意读
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: lua51-bytecode-forloop-tvalue-fake-closure-sandbox-escape
tags:
- pwn
- sandbox-escape
- lua
- bytecode
- type-confusion
- tvalue
- arbitrary-read
- setfenv
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:12:43+08:00'
  notes: 已对照阶段3 核对：luaL_loadbuffer 字节码、OP_FORLOOP 类型混淆、LClosure/Proto/TValue 伪造、String 任意读、io 包 /proc/self/mem 均吻合；PoC 未执行
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-lua51-bytecode-forloop-tvalue-fake-closure/
draft: false
kb_aliases:
- Lua 5.1 字节码沙箱
- OP_FORLOOP 类型混淆
- TValue 伪造
- LClosure 伪造
- luaL_loadbuffer 字节码
- setfenv 逃逸
- /proc/self/mem shellcode
---

## 一句话结论

沙箱用 `setfenv` 限制 Lua 函数的全局环境、却允许 `luaL_loadbuffer` 加载攻击者提供的二进制字节码时，攻击者可以完全控制 Lua VM：用 `OP_FORLOOP` 把 GC 对象当作 `lua_Number` 读取，泄露对象地址；再通过闭包捕获索引改写栈上的“当前函数”为伪造 `LClosure`，指向伪造 `Proto` 与 `TValue` 数组，伪造 `String` 对象实现任意地址读；最后从 CClosure/全局表恢复沙箱外的 `io` 包，经 `/proc/self/mem` 写入 shellcode。

## 原理

- **字节码信任边界**：`luaL_loadbuffer` 默认接受预编译字节码；字节码中的寄存器类型、常量表、闭包捕获索引都由攻击者控制，Lua 5.1 没有字节码签名/验证。仅用 `setfenv` 限制环境并不能限制 VM 内部的类型操作。
- **OP_FORLOOP 类型混淆**：Lua 的 `TValue` 是 `{ union { GCObject *gc; void *p; lua_Number n; int b; } Value; int tt; }`。`OP_FORLOOP` 假定 `ra/ra+1/ra+2` 是 Number，直接 `nvalue()` 读取并做浮点加法，再把结果 `setnvalue()` 写回。如果 `ra` 实际是 GC 对象，`nvalue()` 会把对象指针的位模式当 double 读出/写回，从而泄露对象地址（指针→double→整数）。
- **伪造 LClosure/Proto/TValue**：Lua 加载函数常量时，会从栈上取“当前函数”对象，访问其 `Proto->k` 常量数组。通过闭包捕获机制：调用闭包 A 时指定它捕获的栈索引；如果把捕获索引设为 A 自身压栈的位置，就能在 A 执行时控制“当前函数”。把该位置伪造成 `LClosure`，其 `p` 指向伪造 `Proto`，`k` 指向伪造 `TValue` 数组，就能让 `LOADK` 等指令加载任意伪造 TValue。
- **任意地址读**：Lua String 对象的内存布局是 `CommonHeader` + `reserved/hash/len` + 字符串内容，内容紧跟在对象头之后。伪造一个 `String` TValue，把其数据指针/长度指向目标地址，Lua 的 `string.sub`/拼接等操作就会把目标地址内容当字符串读出。
- **恢复沙箱外环境**：题目在全局环境注册了 `string` 与 `io` 包，只是用 `setfenv` 把用户函数的环境换成空表。通过 CClosure 泄露其环境表/全局表地址，伪造 table 类型 TValue 指回真实全局表，即可拿到 `io` 包；`io.open("/proc/self/mem","w")` + 定位代码段写入 shellcode，完成任意代码执行。
- **为什么可行**：Lua 的沙箱是“环境表”级别的访问控制，不是内存隔离；字节码层没有类型验证，VM 假定字节码可信。攻击者一旦能加载字节码，就拥有 VM 级内存原语。

## 触发条件

- 目标使用 Lua 5.1（或兼容字节码的版本），并通过 `luaL_loadbuffer`/`lua_load` 加载不可信字节码；未拒绝二进制 chunk（未使用 `luaL_loadbufferx` 的 "t" 文本模式）。
- 沙箱仅通过 `setfenv`/环境表限制 API，未在独立进程/seccomp 中运行；仍注册了 `string`、`io` 等包或可通过 CClosure 找回。
- 攻击者可多次执行 Lua 代码、观察返回/错误，便于泄露与调试；目标可写 `/proc/self/mem` 或存在其它代码执行路径。
- 目标 Lua 的 `TValue`/`LClosure`/`Proto` 布局与版本匹配（5.1 与 5.3/5.4 差异很大）。

## 利用步骤

1. **确认字节码加载**：测试提交以 `\x1bLua` 开头的二进制 chunk 是否被接受；若被拒绝，寻找 `loadstring`/`load` 的二进制模式或其它加载点。
2. **构造 OP_FORLOOP 泄露**：用字节码把目标 GC 对象放入 `ra`，`ra+1=0`、`ra+2=0`，执行 `OP_FORLOOP`，使对象指针被当 double 写回；再用算术/字符串转换把 double 转成整数地址（或直接观察寄存器）。
3. **伪造闭包与常量表**：利用闭包捕获索引控制“当前函数”，在栈上布置伪造 `LClosure`（`p` 指向伪造 `Proto`，`k` 指向伪造 TValue 数组），让后续 `LOADK` 返回攻击者构造的 TValue。
4. **伪造 String 任意读**：构造 `String` TValue，使 `len` 足够大、数据指针指向目标地址；用 `string.sub`/拼接读取目标内存。先用已知地址（如字符串自身）校准偏移。
5. **泄露全局表**：从 `string.format` 等 CClosure 的 upvalue/环境中泄露 `lua_State` 的全局表地址；伪造 table TValue 指向真实全局表，读取 `io`、`os` 等包。
6. **写 shellcode**：用 `io.open("/proc/self/mem","r+")` 定位可执行代码段（或 libc 函数），写入 shellcode/ROP，触发执行；也可直接调用 `os.execute`（若可达）。
7. **验证**：在沙箱内执行 `io` 操作或命令，确认逃逸。

## PoC

```lua
-- 原语利用核心（示意）：伪造 TValue 后读取字符串对象地址与全局表
local s = ""
local fake_closure_str = faketval(addr_offset(s.format, -12) .. s)
local g_table_addr = fake_closure_str:sub(13, 20)
local leak_base    = fake_closure_str:sub(21, 28)
local g_table      = faketval(g_table_addr .. "\5\0\0\0\0\0\0\0")
pwn(g_table, u64(leak_base))
```

```c
/* OP_FORLOOP 的关键逻辑：ra 被假定为 Number，实际可为 GC 对象 */
lua_Number step = nvalue(ra+2);
lua_Number idx  = luai_numadd(nvalue(ra), step);
lua_Number limit= nvalue(ra+1);
if (luai_numlt(0, step) ? luai_numle(idx, limit)
                        : luai_numle(limit, idx)) {
  dojump(L, pc, GETARG_sBx(i));
  setnvalue(ra, idx);
  setnvalue(ra+3, idx);
}
```

具体字节码需要按目标 Lua 5.1 的 opcode 编码、`Proto`/`TValue` 偏移与 GC 布局生成；原文用自定义工具构造并分阶段调试。本卡不执行 PoC。

## 变体与关联

- **Lua 5.2/5.3/5.4**：字节码格式与类型检查不同；5.3 引入整数/浮点两种 Number，OP_FORLOOP 的类型混淆窗口变化，需重新验证。
- **只允许文本 chunk**：若 `load` 拒绝二进制，可尝试 `loadstring` 的 `mode` 参数、`string.dump` 的滥用、或先通过其它漏洞写内存。
- **无 io 包**：可通过 CClosure/`package.loaded`/`os` 库恢复；若完全无 C 库，需要纯内存原语，难度更高。
- **关联**：[[binary-pwn-sandbox-escape-roblox-lua-writable-typetag-private-address]]（另一类 Lua 类型标记绕过）、[[ctf-reverse-lua53-bytecode-xor-rc4]]（Lua 字节码逆向）、[[binary-pwn-sandbox-escape-sandboxjs-object-values-function-array-fromentries]]（其它语言沙箱逃逸）。
- **边界**：要求能加载攻击者字节码且未做 VM 级隔离；若沙箱运行在独立进程 + seccomp + 只读文件系统，仍可逃逸 Lua 但写 `/proc/self/mem`/执行 shellcode 可能被阻止。

## 检测与防御

- **拒绝字节码**：加载不可信代码时只用文本模式（`luaL_loadbufferx(..., "t")` 或 `load(..., "t")`），拒绝 `\x1bLua` 开头 chunk；不要向用户暴露 `string.dump` 结果的可执行入口。
- **真正隔离**：Lua 沙箱放在独立进程/容器，使用 seccomp、只读 rootfs、无 `/proc/self/mem` 写权限、丢弃 `io/os/package`；不要依赖 `setfenv` 作为安全边界。
- **限制 C 库**：不注册 `io`、`os`、`package`、`debug`；若必须提供，使用能力受限的封装并审计 CClosure 的 upvalue。
- **检测**：请求中出现 `\x1bLua` 字节码、异常的 `loadstring`/`load` 二进制模式、`/proc/self/mem`/`/proc/self/maps` 访问、Lua VM 崩溃或类型断言失败；监控沙箱进程的 `io.open`/`os.execute`。
- **更新**：使用带字节码验证的 Lua 版本/补丁，或启用了 `LUA_USE_APICHECK` 的构建进行测试；生产环境不要把 `luaL_loadbuffer` 直接暴露给不可信输入。
