---
id: code-analysis-dynamic-fuzzing-boofuzz-primitive-generation-strategy-library
title: boofuzz 内置原语的生成策略集合：特殊值表、长串边界扩展、group 组合与 s_update 运行时改字段
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: boofuzz-primitive-generation-strategy-catalog
aliases:
- boofuzz 原语生成策略
- boofuzz String Bytes 特殊值
- boofuzz s_update
- boofuzz s_block group
- boofuzz s_size s_checksum 绑定块
- boofuzz 协议字段 fuzz 取值表
tags:
- boofuzz
- fuzzing
- protocol-fuzzing
- mutation
- python
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:30:33+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原语特殊值表/长串常量的具体数值仅以截图呈现，正文只有策略描述，卡内未落具体常量；PoC 为按正文 s_block group/s_size/s_checksum/s_update 语义构造的演示脚本，非原文原样 PoC；未执行文内任何命令
---

## 一句话结论

boofuzz 的每个原语（`String`/`Bytes`/`BitField`/`Delim`/`Float`/`RandomData`/`Group`/`Simple`/`FromFile`/`Mirror` 等）都自带一张**内置取值表**：`String` 里是命令注入与路径穿越的经典特殊值、把默认值重复 2/10/100 次、以及用两组长串常量（长度常量与长度增量）两两相加得到的边界长度（含在 "D" 长串里随机插 `\x00`）；想一次改多个字段必须给 `Block` 设 `group` 或走组合变异，而 `s_update(qualified_name, value)` 提供了"不重建 Request 就在两次 fuzz 之间改静态字段"的唯一官方入口——这三点共同决定了黑盒协议 fuzz 的覆盖边界。

## 原理

- **原语即字段生成器**：`Request` 用 `self.stack` 存 Block/Primitive 树，`self.block_stack` 维护当前打开的 Block 以生成 `context_path`，`qualified_name = context_path + name` 并登记进 `self.names`；fuzz 时按 `qualified_name` 到 `self.names` 里取原语、调它的 `mutations()` 生成候选值。因此"能测到什么"完全等于"各原语内置取值表里有等价载荷"。
- **String 的策略为什么危险**：它的特殊值表本身就是命令注入/模板/穿越字典（`;`、`|`、`../`、`%00`、超长串等），所以一个把 URL/命令/文件名放进 `s_string` 的 Request 天然会打到注入类缺陷；重复默认值 2/10/100 次与"边界长度"两两相加覆盖的是**长度校验类**缺陷（截断、长度字段与实际内容不一致、缓冲区边界）。
- **\x00 插空串的用途**：在全是 "D" 的长串里按 `_long_string_lengths` 相邻元素之间随机取 8 个位置插 `\x00`，专门打"按 `strlen` 计长度却用二进制比较"或"多字节/空字节截断"的实现差异。
- **Bytes/Byte/Word/Dword/Qword**：`BitField` 的 `full_range` 决定是全量枚举 0..2^width-1 还是只取边界值表；`Bytes` 用 1/2/4 字节特殊值依次**滑动覆盖**默认值的每个偏移（覆盖面靠"位置"而非"取值"），再按 `size`/`max_len` 截断或 `padding` 填充。
- **绑定块原语解决"字段之间必须自洽"**：`s_size`（按 Block 计算长度，可设 `offset`/`Length`/`endian`/`output_format`）、`s_checksum`（crc32/crc32c/adler32/md5/sha1/ipv4/udp 或自定义函数）、`s_repeat`（对 Block 重复 min..max 次）在 render 阶段重算，所以变异内容字段时长度与校验和仍然合法——这正是能穿过"先校验长度/CRC 再解析"的前置门的原因。
- **`group` 与组合变异**：默认一轮只变一个原语；给 `Block` 设 `group` 让 Block 与其绑定的 Group/Simple 同轮变化；不传 `max_depth` 时进入组合变异（depth 递增，depth=n 同时变 n 个原语）。
- **`s_update` 不只是改常量**：它按 `qualified_name` 把 `default_value` 换成新值，用于"先探测设备型号/会话 ID，再在下一轮 fuzz 里替换固定字段"，避免为每个目标重写一次 Request。

## 触发条件

- 用 boofuzz 做无源码的黑盒协议/网络服务 fuzz，且请求里存在字符串字段（URL、命令、文件名、模板、头字段）或长度/校验和字段。
- `String`、`Bytes` 未设 `size`/`max_len` 以外的额外限制，或设得足够大以容纳边界长度。
- 需要"字段之间自洽"的目标（TLV、带 CRC 的私有协议）：必须用 `s_size`/`s_checksum` 绑定 Block，否则变异后报文被目标直接丢弃，测不到深层逻辑。

## 利用步骤

1. 按协议布局用 `s_initialize` 建 Request，把可变字段全部落到 `s_string`/`s_bytes`/`s_group`，可变长度/校验和字段用 `s_size`/`s_checksum` 绑定到对应 Block。
2. 对"必须同时变化才有意义"的字段对（长度字段 + 内容、type + value）放进同一 Block 并设 `group`。
3. 先 `fuzz(max_depth=1)` 跑单字段基线，确认目标有响应；再用组合变异（不传 `max_depth`）加宽。
4. 用 `s_update` 填入在探测阶段得到的固定字段（会话 token、设备型号、序列号）后继续 fuzz，避免每轮都被鉴权拦掉。
5. 对每个命中的畸形请求，回读该原语的取值表，判断是"特殊值命中"还是"边界长度命中"，据此收敛成最小 PoC 报文。

## PoC

```python
from boofuzz import *

s_initialize("devcmd")
s_group("cmd", ["GET", "SET", "DEL"])            # 协议动作
s_delim(" ")
s_string("/api/v1/status", name="path")          # String 自带注入/穿越/长串策略
s_delim(" ")
with s_block("Body", group="Body"):              # 与 group 绑定，同轮一起变
    s_string("len", name="len_hint")             # 与真实长度不自洽的诱饵
    s_static("\r\n")
    s_size("Payload", output_format="ascii", name="clen")
    s_static("\r\n")
with s_block("Payload"):
    s_string("A" * 16, name="data")
s_checksum("Payload", algorithm="crc32", name="crc")

session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 9000)))
session.connect(s_get("devcmd"))
# 探测到设备序列号后再替换固定字段
s_update("devcmd.Payload.data", "SERIAL-000001")
session.fuzz(max_depth=1)     # 单字段基线
# session.fuzz()              # 组合变异：多字段同时变化
```

```text
判据：max_depth=1 时每轮只有单个 Mutation（group 内两个）；
去掉 max_depth 后 depth 递增；s_size/s_checksum 保证变异后长度与 CRC 始终自洽。
```

## 变体与关联

- 关联：[[code-analysis-dynamic-fuzzing-boofuzz-mutation-single-primitive-maxdepth-group]]（变异粒度与 group/max_depth 的机制）、[[code-analysis-dynamic-fuzzing-boofuzz-stateful-path-callback-session-variables]]（Paths 与回调维持会话状态）。本卡补的是"各原语的取值表本身"这一层，三张卡分别覆盖取值、粒度、状态。
- 变体：只做长度类缺陷时，可把 `String` 换成 `Bytes` + `size`，用滑动覆盖省掉大段重复串；只做注入类缺陷时，只用 `Simple(fuzz_values=[...])` 显式给字典，避免长串策略产生大量超时报文。
- 边界：`s_from_file` 依赖本地字典质量；`s_random` 的 `max_mutations` 由 `min_length`/`max_length`/`step` 推出，给不出 step 时长度随机、覆盖不可复现；`s_mirror` 只能与已存在的原语镜像，无法凭空构造；重复 100 倍默认值的策略在长度受限协议上会被 padding/截断掉，实际到不了目标。

## 检测与防御

- 检测：同一会话内出现"单字段高频变化、其余字段固定"的请求序列；或出现字段长度与长度头/CRC 不自洽、含 `;`、`|`、`../`、`%00`、超长重复串的报文；`\x00` 混在长串中间是 boofuzz 长串策略的强特征。
- 防御：每个字段独立校验并快速失败，拒收长度头与实际长度不一致的报文；对注入字符在解析前而非拼接后过滤；限速并统计单 IP 畸形报文比例；对"相同会话、只有少数字段变化"的序列做 fuzz 检测。
