---
id: ctf-web-go-rbac-map-order-error-reset-bypass
title: Go RBAC 权限门控绕过：map 遍历乱序 + 错误分支不重置导致 return 权限累积
type: scenario
domain: ctf
path: ctf/web
technique: go-rbac-map-order-error-reset-permission-bypass
tags:
- ctf
- web
- go
- gin
- rbac
- logic-bug
- map-iteration
- access-control
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:10:07+08:00'
  notes: 已对照原文与唯一图片核对；Go map 顺序与错误分支不重置机理成立，已修正为概率性表述；PoC 未在本机执行。
url: /docs/ctf/web/ctf-web-go-rbac-map-order-error-reset-bypass/
draft: false
kb_aliases:
- CISCN 决赛 AWDP RBAC
- Go map 遍历顺序绕过
- RBAC 权限累积
- change_return 门控
- 错误分支不重置权限
- Go RBAC 逻辑漏洞
---

## 一句话结论

一个 Go/Gin RBAC 服务把待授予权限放进 `map[string]int`，其中同时包含“打开 return 门控”的 `rbac:change_return:1`、“关闭门控”的 `rbac:change_return:0` 和目标 `flag:return`；`updateRBAC` 按 map 遍历顺序逐项处理，而 Go 的 map 遍历顺序是随机化的，多次请求中总会有一次把 `flag:return` 排在 `:1` 与 `:0` 之间，从而被错误授予。又因为只有成功分支调用 `initRBAC()` 重置，传入不存在的 `FuncName` 让 `execCommand` 返回 400 时权限不会重置，攻击者可以反复请求累积 `file:return` 与 `flag:return`，最后用 `getFile` 读取 `/flag`。

## 原理

- **权限授予结构**：`ExecStruct` 包含 `File`、`Directory`、`Pwd`、`Flag`、`FuncName`、`Param`；服务把数组元素转成 `类型:值` 键放进 `RBACToGrant`，最多 8 项（`File` 的 `"return"` 特例占 3 项）。随后 `updateRBAC(RBACToGrant)` 更新全局 `RBACList`。
- **门控逻辑**：`updateRBAC` 对键做后缀判断：
  - 以 `:read` 结尾：只有 `rbac:change_read==1` 才写入（初始为 1）；
  - 以 `:return` 结尾：只有 `rbac:change_return==1` 才写入（初始为 0）；
  - `rbac:change_return:1`：把 `rbac:change_return` 置 1；
  - `rbac:change_return:0`：把 `rbac:change_return` 置 0；
  - 其他键直接写入。
- **设计意图**：只有 `File:["return"]` 会触发特例，把 `rbac:change_return:1`、`file:return`、`rbac:change_return:0` 三个键加入 map，使 `file:return` 在门控打开期间被授予，随后门控关闭；`flag:return` 来自 `Flag` 数组，但本应在门控关闭时被拒绝。
- **map 遍历乱序**：Go 的 `map` 迭代顺序未定义且每次迭代随机化。`RBACToGrant` 中键的顺序不可控，若某次遍历恰好是 `rbac:change_return:1 → flag:return → rbac:change_return:0`，`flag:return` 就会在门控为 1 时被写入；若 `flag:return` 在 `:1` 之前或 `:0` 之后，则被拒绝。因此单次请求是概率性的，多次请求即可命中。
- **为什么能累积**：`execCommand` 成功时返回 200 并调用 `initRBAC()`；`FuncName` 不存在时返回 400，但错误分支没有调用 `initRBAC()`，`RBACList` 保留上一次请求授予的权限。攻击者用 `FuncName="getFile1"`（不存在）反复发同一个包：单次请求中 `file:return` 与 `flag:return` 都只有在遍历时位于 `:1` 之后、`:0` 之前才会被写入，单次是概率性的；一旦某次遍历把 `:0` 排在 `:1` 之前，门控最终停在 1，后续请求会跳过特例分支、直接按门控授予两者，从而稳定累积并读到 flag。
- **读取条件**：`getFile` 要求 `file:read==1`；`param` 含 `"flag"` 时还要求 `flag:read==1`；返回内容要求 `file:return==1`，含 flag 时还要求 `flag:return==1`。`file:read`/`flag:read` 由 `File`/`Flag` 数组的 `"read"` 通过普通 `:read` 分支写入，`file:return` 由 `File:["return"]` 特例授予，`flag:return` 由 map 乱序授予。
- **漏洞本质**：安全决策依赖无序容器的遍历顺序（顺序假设错误），且状态机在异常路径上没有复位（状态泄漏/累积），两个小问题组合成权限提升。

## 触发条件

- 目标为该 Go/Gin RBAC 服务（CISCN 决赛 AWDP 题目环境或相同代码）。
- `/execSysFunc` 可访问，JSON 可同时提交 `File`、`Flag`、`FuncName`、`Param`。
- `rbac:change_read` 初始为 1（允许授予 `:read`），`rbac:change_return` 初始为 0（需要通过 `File:["return"]` 特例打开）。
- `FuncName` 可传入不存在的函数名，使 `execCommand` 返回错误且不触发 `initRBAC()`。
- 目标未对同一会话的 RBAC 状态做请求级重置/隔离。

## 利用步骤

1. 请求 `/getCurrentRBAC` 确认初始权限（`file:read`、`flag:read`、`file:return`、`flag:return` 均为 0，`rbac:read`、`rbac:change_read` 为 1）。
2. 构造 JSON：`{"File":["read","return"],"flag":["read","return"],"FuncName":"getFile1","Param":""}`，其中 `getFile1` 不存在，目的是让 `execCommand` 报错并跳过 `initRBAC()`。
3. 重复 POST 到 `/execSysFunc` 若干次（文章脚本为 6 次）。由于 map 遍历顺序随机，`file:return`/`flag:return` 会在某次恰好排在 `:1` 与 `:0` 之间而被授予；若门控被留在 1，后续请求更会稳定授予。
4. 再次请求 `/getCurrentRBAC`（或在响应中）确认 `file:return` 与 `flag:return` 均为 1。
5. 发送 `{"File":["read","return"],"flag":["read","return"],"FuncName":"getFile","Param":"/flag"}`，响应 `result` 即 flag 内容。

## PoC

```python
import requests

url = "http://target/execSysFunc"

payload_grant = {
    "File": ["read", "return"],
    "flag": ["read", "return"],
    "FuncName": "getFile1",   # 不存在的函数名：400 且不触发 initRBAC()
    "Param": ""
}

for _ in range(6):
    r = requests.post(url, json=payload_grant)
    print(r.status_code, r.text)

payload_read = {
    "File": ["read", "return"],
    "flag": ["read", "return"],
    "FuncName": "getFile",
    "Param": "/flag"
}
print(requests.post(url, json=payload_read).text)
```

关键点：`File` 中的 `"return"` 会触发 `rbac:change_return:1 → file:return → rbac:change_return:0` 三个键；`flag` 中的 `"return"` 会加入 `flag:return`。map 遍历顺序随机，因此需要多试几次；错误函数名保证权限不被重置。

## 变体与关联

- **概率性变体**：若目标 Go 版本的 map 顺序恰好对攻击者不利，增加请求次数即可；也可通过调整 `File`/`Flag` 数组长度改变键的数量与命中概率（注意 `maxDeep` 上限 8）。
- **状态复位变体**：若错误分支也调用 `initRBAC()`，则需要一次请求内同时命中 `file:return` 与 `flag:return`（概率更低但仍非零）；防御应在所有退出路径复位。
- **同类语言问题**：其他语言的哈希表/字典遍历顺序同样可能不稳定（如 PHP 数组是有序的，Go map 明确无序）；审计时搜索“遍历 map 并按顺序修改状态/权限”的代码。
- **同类 CTF 逻辑漏洞**：权限状态机、门控标志、临时提权、请求间状态未隔离等，参见 [[ctf-web-php-str-replace-double-write-object-cast-md5-magic-hash]] 等多阶段认证绕过卡。

## 检测与防御

- 不要依赖 `map` 遍历顺序做安全决策：把授权项放入有序切片，先计算最终状态，再统一应用；或显式分离“打开门控 → 授予 → 关闭门控”三个阶段。
- 在所有退出路径（成功、错误、panic）重置请求级 RBAC 状态；Go 可用 `defer initRBAC()` 或把状态放在 per-request 结构体中，避免全局变量跨请求泄漏。
- 权限检查应在敏感操作执行时再次进行，而不是只依赖请求开始时的一次性授予；`flag` 读取应独立鉴权，不能只靠字符串包含判断。
- 监控同一来源短时间内重复调用 `/execSysFunc` 且 `FuncName` 不存在、`File`/`Flag` 含 `return` 的请求；对 RBAC 状态变更做审计日志。
