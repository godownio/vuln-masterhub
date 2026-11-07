---
id: binary-pwn-sandbox-escape-roblox-lua-writable-typetag-private-address
title: Roblox Lua 沙箱类型标记绕过：write 可改私有对象 TypeTag，read 的访问拒绝被翻转
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: roblox-lua-writable-typetag-private-address-bypass
tags:
- sandbox-escape
- lua
- roblox
- access-control
- typetag
- blacklist-bypass
- string-concatenation
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:47:33+08:00'
  notes: 已对照原文 World's Hardestest Flag 核对：客户端黑名单 {position,humanoid,destroy,name,typetag,flag}、Storage 0x6767(TypeTag=0,Value=FLAG)/0x4141、read 仅按 TypeTag==0 拒绝、write 无地址/字段限制、["Type".."Tag"] 拼接绕过、必须同一次执行、print 经 RemoteEvent 回显、rbxl zstd 压缩与实测 flag 均一致。Crab Trap(基础 seccomp ORW)与 Proper Pwning(gets+ret2win+ret 对齐)跳过合理。原文为 CTF，无组件版本；未本机复跑。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-roblox-lua-writable-typetag-private-address/
draft: false
kb_aliases:
- World's Hardestest Flag
- Roblox Lua 沙箱逃逸
- TypeTag 访问控制绕过
- writable metadata 授权绕过
- 客户端关键词黑名单拼接绕过
---

## 一句话结论

Roblox 游戏的 Lua 沙箱用 `Storage[address].TypeTag == 0` 表示“私有地址”，`read` 遇到 TypeTag=0 就返回 ACCESS DENIED；但 `write(address, new_data)` 既没有私有地址检查，也允许改 `TypeTag`，于是攻击者先 `write(0x6767, {["Type".."Tag"]=4})` 把私有对象的类型标记改成非 0，再在**同一次执行**里 `read(0x6767)` 即可读出 flag；客户端关键词黑名单只查连续字面量，用 Lua 字符串拼接构造字段名即可绕过。

## 原理

- **客户端过滤**：终端把输入整体 `string.lower` 后做 `string.find`，黑名单是 `{"position","humanoid","destroy","name","typetag","flag"}`；它只拦连续字符串，不做 Lua 语法/AST 分析，因此 `["Type".."Tag"]` 不会命中 `typetag`。
- **服务端执行**：服务器用 `ReplicatedStorage.Loadstring` 在自定义环境编译执行用户 Lua，只暴露 `write/read/print` 等安全函数；`print` 通过 `RemoteEvent:FireClient` 回显到终端，正好作为外带通道。
- **模拟内存**：每次执行都新建 `Storage = {[0x6767] = {TypeTag=0, Value=FLAG}, [0x4141] = {TypeTag=4, Value="You!"}}`；私有地址 0x6767 的 Value 就是 flag。
- **访问控制缺陷**：`read(address)` 只看 `Storage[address].TypeTag`，为 0 就拒绝；`write(address, new_data)` 直接遍历 `new_data` 合并到 `Storage[address]`，不检查地址是否私有、也不限制可写字段。授权元数据（TypeTag）与业务数据放在同一个可写表里，是典型的“可写元数据当权限位”错误。
- **必须同一次执行**：`Storage` 每次 `server_execute` 重建，不能分两次提交 write/read；payload 必须一行内先改 TypeTag 再读 Value。
- **为什么能读 flag**：`read` 的拒绝分支只由 TypeTag 决定，TypeTag 被改成 4 后走 `return tvalue.Value`，flag 随 `print` 回显。

## 触发条件

- 应用提供 Lua（或其他脚本）在线执行/沙箱，用户输入经 `loadstring`/`eval` 在自定义环境中运行。
- 沙箱用对象内可写字段（TypeTag、is_private、permission）做访问控制，且 `write` 能修改该字段。
- 客户端只做关键词黑名单/字符串过滤，没有服务端 AST 校验。
- 敏感数据与可写对象在同一 Storage/模拟内存中，且存在回显通道（print/日志/RemoteEvent）。

## 利用步骤

1. 逆向下发的 Roblox place（`<roblox!` 开头）；新版压缩用 zstd，旧的按 LZ4 的 rbxl 解析脚本会失败，先解压出脚本块。
2. 定位客户端终端脚本、服务端 Mainframe 与 `ExecuteCode` RemoteEvent；确认客户端黑名单与服务端 `read/write/print` 实现。
3. 确认私有地址（如 0x6767）与 TypeTag 语义：`read` 只在 TypeTag==0 时拒绝。
4. 构造绕过黑名单的字段名：`["Type".."Tag"]`，避免连续 `typetag` 字面量。
5. 在同一次提交中先写 TypeTag 再读 Value：`write(0x6767,{["Type".."Tag"]=4});print(read(0x6767))`。
6. 通过终端 Submit 触发服务端执行，`print` 回显 flag。
7. 若客户端还过滤其他关键词（flag/name 等），继续用字符串拼接、`string.char`、变量间接引用等方式构造，避免连续字面量。

## PoC

```lua
write(0x6767,{["Type".."Tag"]=4});print(read(0x6767))
```

目标端逻辑（简化）：

```lua
local Storage = {
    [0x6767] = { TypeTag = 0, Value = FLAG },
    [0x4141] = { TypeTag = 4, Value = "You!" }
}

local function read(address)
    local tvalue = Storage[address]
    if not tvalue then return "nil" end
    if tvalue.TypeTag == 0 then return "[ACCESS DENIED]" end
    return tvalue.Value
end

local function write(address, new_data)
    if Storage[address] then
        for key, val in pairs(new_data) do
            Storage[address][key] = val
        end
    end
end
```

原文在真实 Roblox 游戏中通过终端提交 payload，回显 `bronco{d34th_t0_th3_dehs_f0r3v3r}`；未在本机复跑。

## 变体与关联

- **可写元数据授权**：`is_admin`、`permission`、`owner`、`locked` 等字段若与业务数据同表且可被 write 修改，均可翻转访问控制。
- **黑名单绕过**：字符串拼接 `["Type".."Tag"]`、`string.char`、变量间接引用、大小写/编码；客户端过滤永远不应作为安全边界。
- **沙箱逃逸**：若 `loadstring` 环境暴露宿主函数/元表，可进一步升级到任意代码执行；本题只需读 flag。
- **关联**：[[binary-pwn-sandbox-escape-python-regex-ast-alias-concat]]（字符串拼接绕过黑名单）、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（语言沙箱逃逸）；本卡强调“可写 TypeTag 翻转访问控制”的逻辑缺陷。

## 检测与防御

- 授权元数据与业务数据分离，放入不可被脚本 write 的独立表/服务端只读结构；`write` 对字段名和地址做白名单。
- `read` 先按地址查私有表做拒绝，不能依赖对象内可写 TypeTag；对 0x6767 等私有地址硬编码拒绝。
- 服务端做 Lua AST/字节码级校验，不只依赖客户端关键词黑名单；禁用 `loadstring` 或使用受限沙箱。
- 检测：用户脚本出现 `["Type".."Tag"]`、`string.char` 拼接、对私有地址的 write、同一次执行中 write 后紧跟 read；RemoteEvent 输入含拼接构造的敏感字段名。
