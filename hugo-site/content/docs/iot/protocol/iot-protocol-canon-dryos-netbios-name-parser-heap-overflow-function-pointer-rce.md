---
id: iot-protocol-canon-dryos-netbios-name-parser-heap-overflow-function-pointer-rce
title: 佳能打印机 DryOS NetBIOS 名称解析堆溢出：标签偏移空转推高写指针，2 字节 WWW 改函数指针执行 shellcode
type: scenario
domain: iot
path: iot/protocol
technique: dryos-netbios-name-parser-heap-overflow-www-function-pointer-rce
tags:
- iot
- printer
- netbios
- heap-overflow
- write-what-where
- function-pointer
- shellcode
- dryos
- firmware
cve:
- CVE-2023-0851
- CVE-2023-0852
- CVE-2023-0853
- CVE-2023-0854
- CVE-2023-0855
- CVE-2023-0856
severity: critical
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: Canon 打印机固件 11.04（文中攻击版本）；12.03 已修复
verification:
  verified_by: verifier-V692
  verified_at: '2026-11-13T17:56:52+08:00'
  notes: 已对照原文与7张图逐张核对：图01 第一级 half-ASCII 编码（高位/低位各+0x41）；图02/03 两级名称报文与 label offset 布局；图04 netbios_internal_name_entry 内存 dump 标注 name/what/adapter/state/transaction_id；图05 溢出→伪造 adapter→WHERE/WHAT→PJCC Handler 示意图；图06 11.04 与 12.03 补丁 diff（条件改 len_remaining_255 > label_len + 1，扣减改 len_remaining_255 - v1 - 1，零长度标签也消耗预算）；图07 Pwn2Own 打印机屏幕展示。卡内链路（cmNetBiosParseName 零长度标签指针+1不扣预算→推过255字节缓冲区→溢出20×0x64 name_entry→2字节WWW→两次覆写 pjcc_dec_ope_echo 低/高2字节→BJNP 写 shellcode→PJCC ECHO 触发）与原文一致。修正/补充：组包示例去掉原文未给出的具体压缩指针字节，改为'高2位为1、低14位为偏移'；新增结构体偏移基准说明（正文称名称在0x04，图04标注的0x20/0x24/0x2c/0x3c 相对名称起始，相差0x04）；新增 CVE 归属说明（原文公告10个CVE中6个缓冲溢出CVE-2023-0851~0856 影响该设备，未逐一映射本缺陷）。affected_versions=Canon 打印机固件 11.04（原文攻击版本，12.03 已修复）为原文显式标记，保留。未验证点：无完整 PoC，利用脚本未复跑；原文未把 CVE 一一对应到本函数。
url: /docs/iot/protocol/iot-protocol-canon-dryos-netbios-name-parser-heap-overflow-function-pointer-rce/
draft: false
kb_aliases:
- 佳能打印机 NetBIOS 堆溢出
- DryOS cmNetBiosParseName
- NetBIOS 名称服务第一级/第二级编码
- netbios_internal_name_entry
- pjcc_dec_ope_echo 函数指针
- Pwn2Own 2022 Canon
---

## 一句话结论

佳能打印机 DryOS 的 NetBIOS 名称服务实现 `cmNetBiosParseName` 在第二级名称解码时，遇到"长度字段为 0 或指向 NUL 的压缩指针"会跳过 memcpy 但仍把目标指针 +1 且不扣减剩余长度，反复构造即可把写指针推过 255 字节缓冲区、溢出相邻的 `netbios_internal_name_entry` 数组；把溢出条目中的 adapter 指针/what/state/transaction_id 布置好后，配合伪造的正向名称查询响应触发 `returnNegativeRegistrationResponse`，获得 2 字节任意地址写（WWW），两次覆盖 PJCC 处理函数 `pjcc_dec_ope_echo` 的低/高 2 字节，再用 BJNP 写入 shellcode、PJCC ECHO 消息触发执行取得打印机代码执行。

## 原理

- **NetBIOS 名称编码**：第一级编码把 16 字节名称映射成 32 字节 half-ASCII（每字节拆成两个 0x41 起的字母）；第二级把域名按"长度前缀 + 标签"编码，长度字段高 2 位为 1 时其后 14 位是指向包内其它标签的压缩指针（RFC 1001/1002/833）。`cmNetBiosParseName` 先解析第一级到固定 16 字节 `first_level_name`，再循环 `resolveLabel` 逐标签把第二级名称拷入 255 字节缓冲区。
- **漏洞根因**：循环里 `if (len_remaining_255 > label_len) { memcpy(second_level_name, src, n); ... len_remaining_255 -= n; second_level_name += n + 1; }`。当标签长度 `label_len == 0`（或压缩指针指向 NUL）时条件仍成立：memcpy 拷 0 字节、`len_remaining_255 -= 0`，但 `second_level_name` 仍前进 1。重复发送多个"指向 NUL 的压缩指针"标签，就能在不消耗长度预算的情况下把目标指针推高最多 255 字节，随后再发真实标签，`memcpy` 便写到缓冲区之外——堆溢出。
- **对象布局**：NetBIOS 上下文初始化时 `ndInternalNameInit` 分配 20 个 `netbios_internal_name_entry`（每项 0x64 字节）数组，紧邻名称解析用的堆块；溢出可覆盖后续条目。由于分配顺序与调度，两个分配的相对位置在极少数情况下不连续。
- **2 字节 WWW 原语**：`netbios_internal_name_entry` 中偏移 0x04 是 16 字节名称（用于在 20 项中匹配），0x24 是 `netbios_adapter*`，0x20 是 uint16 what，0x2c 是 uint16 state（必须为 8 才进入 `returnNegativeRegistrationResponse`），0x3c 是预期 transaction id。伪造 adapter 结构（含 0x38 处的写目标指针）可通过 BJNP 协议写到固定地址。发送状态被破坏的正向名称查询响应后，系统回送负向名称注册响应，把事务 ID（2 字节受控数据）写到 adapter->0x38 指向的地址——`*(uint16*)where = what`。
- **提权到代码执行**：用两次 WWW 分别覆盖 PJCC 解码函数 `pjcc_dec_ope_echo` 的地址低 2 字节与高 2 字节（4 字节函数指针分两步写）；BJNP SessionStart 把 shellcode 存到固定地址；发送 PJCC ECHO 消息时被篡改的函数指针跳入 shellcode。
- 该实现闭源，但日志函数会泄露函数名与源文件名（如 `netcifsnqendapp/IMP/nq/nddaemon.c`），可据此定位实现；同一 DryOS 也用于佳能相机。

## 触发条件

- 目标为佳能打印机（文中固件 11.04，UDP 137 名称服务默认可达），DryOS `netcifsnqendapp` 运行 NetBIOS 名称服务（0.0.0.0:137、138、127.0.0.1:1022/1023）；
- 能向 UDP/137 发送任意 NetBIOS 名称服务报文（无认证），并能使用 BJNP 协议写固定地址、PJCC 协议发 ECHO 消息；
- 攻击者掌握 NetBIOS 报文编码（第一级 half-ASCII、第二级标签/压缩指针）：构造多个 label_len=0 的压缩指针标签推动写入指针越界；
- 需要知道（或能爆破/固定）堆布局与 PJCC 函数指针地址（非 PIE 式固定加载的嵌入式环境）。

## 利用步骤

1. 组包：NetBIOS 头部 + 第一级名称（`0x20` + 32 字节 half-ASCII）+ 若干指向包内 NUL 字节的压缩指针标签（高 2 位为 1、低 14 位为偏移），制造目的指针前进而长度预算不减；随后附真实标签触发越界拷贝，覆盖相邻 `netbios_internal_name_entry`。
2. 溢出内容按条目布局填写：0x04 处 16 字节名称、0x20 处 2 字节 WHAT、0x24 处指向伪造 adapter 的指针、0x2c 处 state=8、0x3c 处预期事务 ID。
3. 用 BJNP 把伪造 `netbios_adapter` 结构（0x38 偏移为写目标地址）写到固定内存地址。
4. 发送带损坏状态的正向名称查询响应，触发 `ndInternalNamePositiveQuery → returnNegativeRegistrationResponse`，在目标地址写入 2 字节（事务 ID）。
5. 重复步骤 1–4，第二次把 WHERE 指向 `pjcc_dec_ope_echo` 函数指针的高 2 字节，完成 4 字节指针覆写。
6. 通过 BJNP SessionStart 把 shellcode 存入固定地址；发送 PJCC ECHO 消息触发被覆盖的函数指针，执行 shellcode（Pwn2Own 演示中在打印机屏幕显示图案）。

## PoC

无完整 PoC（原文为 Pwn2Own 2022 攻击过程叙述与关键报文/结构图，未给出可直接运行的利用脚本）。最小化复现需自行构造 NetBIOS 名称服务报文、BJNP 写原语与 PJCC ECHO 触发包。

## 变体与关联

- 补丁对比：固件 12.03 在 `label_len == 0` 时执行 `len_remaining_255 -= 1`（并相应调整条件），使空转标签也消耗预算，写指针无法无成本前移，漏洞修复。
- 同类原语：其他嵌入式协议解析器的"长度检查后下标/指针前进不一致"缺陷可类比审计（先拷贝后校验、零长度不扣预算）。
- 关联：Synacktiv 前一篇打印机研究（HP/Lexmark/Canon 多款）；该链的 WWW → 函数指针覆写 → shellcode 属于嵌入式 pwn 通用套路。
- 结构体偏移基准：正文称名称字段在结构体偏移 0x04，而图 04 标注中 what/adapter/state/transaction 相对名称字段起始为 0x20/0x24/0x2c/0x3c，两种基准相差 0x04；实际利用需按目标固件结构体定义核对。
- CVE 归属：原文引用佳能 2023-04-14 公告的 10 个 CVE，其中 CVE-2023-0851～0856 为影响该设备的 6 个缓冲区溢出漏洞；原文未把具体 CVE 逐一映射到 `cmNetBiosParseName`，引用时按公告/固件版本核实。

## 检测与防御

- 升级到修复固件（文中 12.03；佳能 2023-04-14 公告，参考 CVE-2023-0851～0856 等 10 个 CVE）；
- 网络侧限制 UDP 137/138 NetBIOS 名称服务与打印协议端口暴露，打印网络与办公网分段；
- 检测异常长的 NetBIOS 名称报文、大量指向 NUL 的压缩指针、非常规 BJNP/PJCC 会话与打印设备异常重启/行为；
- 固件审计关注标签解码循环中"零长度标签"的预算扣减与指针推进是否一致。
