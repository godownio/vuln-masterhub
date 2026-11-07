---
id: code-analysis-reverse-linux-protobuf-c-descriptor-recovery
title: protobuf-c 描述符逆向：从 stripped ELF 恢复 .proto 与 pb2
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: protobuf-c-descriptor-recovery
aliases:
- protobuf-c 逆向
- ProtobufCMessageDescriptor
- 682290937
- proto 恢复
- pb2 生成
- protobuf 字段表恢复
- 从二进制恢复 protobuf 结构
tags:
- reverse-engineering
- elf
- protobuf-c
- descriptor
- proto
- pwntools
- linux
- struct-recovery
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:43:57+08:00'
  notes: 已对照原文核对：描述符魔数0x28AAEEF9、+0x08名字/+0x20包名/+0x30字段数/+0x38字段表、字段项0x48字节及+0x08编号/+0x0C label/+0x10类型、原文2个候选选0x4c40、恢复出的giao.msgiao 4字段与bytes双槽布局均一致；与protobuf-c公开结构布局吻合。脚本约560行未在本机复跑；无组件影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

使用 protobuf-c 的 64 位 ELF 会把 `ProtobufCMessageDescriptor`（魔数 `0x28AAEEF9`）和字段描述表保留在 `.data.rel.ro` 等只读数据中；即使符号被 strip，也可以扫描该魔数、校验 name/package/字段数量/字段表，按固定偏移恢复字段名、编号、label、类型，再生成 `.proto` 和对应的 `_pb2.py`，从而构造目标程序能解析的消息。

## 原理

- **protobuf-c 的运行时描述符**：protobuf-c 不像 C++ protobuf 那样依赖代码生成后的静态表隐藏在代码里，而是在数据段保留 `ProtobufCMessageDescriptor`，其中包含消息名、包名、字段数量、字段描述表指针等元数据；`protobuf_c_message_unpack`/`pack` 运行时按这些描述符解析二进制消息。
- **x86-64 描述符布局（原文脚本使用）**：
  - `+0x00`：魔数 `0x28AAEEF9`（u32）；
  - `+0x08`：消息名 `char*`；
  - `+0x20`：包名 `char*`；
  - `+0x30`：字段数量（指针宽度整数）；
  - `+0x38`：字段描述表指针。
- **字段描述表项（每项 0x48 字节）**：
  - `+0x00`：字段名 `char*`；
  - `+0x08`：字段编号（u32）；
  - `+0x0C`：label（0=required、1=optional、2=repeated、3=proto3 singular）；
  - `+0x10`：类型（0=int32、1=sint32、2=sfixed32、3=int64、4=sint64、5=sfixed64、6=uint32、7=fixed32、8=uint64、9=fixed64、10=float、11=double、12=bool、13=enum、14=string、15=bytes、16=message）。
- **扫描与打分**：`ELF.search(p64(0x28AAEEF9))` 找所有候选；对每个候选校验 name 非空、字段数在合理范围、字段表每项名字/编号/label/type 合法；多个候选用“唯一字段编号数、字段数、是否有包名/消息名、地址顺序”打分选最优。原文二进制中有 2 个候选，脚本选择 `0x4c40`。
- **bytes 字段的双字段本质**：在 C 结构体中 `bytes` 对应 `ProtobufCBinaryData { size_t len; uint8_t *data; }`，因此在消息结构体里占两个 8 字节槽。原文恢复出的 4 字段消息实际布局为：`ProtobufCMessage base`（0x00–0x17）、`giaoid`（0x18）、`giaosize`（0x20）、`giaocontent`（len 0x28 / data 0x30）、`giaotoken`（len 0x38 / data 0x40）。这也解释了为什么内存里看到的偏移比 `.proto` 字段数多。
- **生成产物**：脚本用 `descriptor_pb2.FileDescriptorProto` 构造描述符，输出 `.proto` 文本和 `_pb2.py`，后者可直接 `from recovered_pb2 import msgiao` 构造消息并 `SerializeToString()`。
- **边界**：脚本只支持 64 位 protobuf-c；魔数可能误命中，需要完整校验；嵌套 message/enum 的类型名无法从单个描述符恢复时，脚本会把它们降级为 `bytes` 并给出 warning；字段名中的非法字符/关键字会被清洗；不同 protobuf-c 版本的偏移可能变化，需要按实际结构核对。

## 触发条件

- 目标为 64 位 ELF，使用 protobuf-c 序列化（可检查导入/字符串：`protobuf_c_message_unpack`、`protobuf_c_message_pack`、`protobuf_c_message_free_unpacked` 等）。
- 二进制被 strip 但仍保留运行时描述符数据（protobuf-c 常见）；需要恢复消息 schema 以构造/解析协议。
- 分析环境有 pwntools（ELF 读取）与 Python protobuf（生成 pb2）；目标消息类型相对简单，或嵌套类型可另行恢复。

## 利用步骤

1. **确认 protobuf-c**：`strings -a binary | grep protobuf_c`、`readelf -s`/`nm -D` 查导入；观察 `.data.rel.ro` 中的描述符指针。
2. **扫描魔数**：用 pwntools 读取 ELF，`e.search(p64(0x28AAEEF9))` 得到候选地址。
3. **校验候选**：读 `+0x08` 的 C 字符串消息名、`+0x20` 的包名、`+0x30` 的字段数、`+0x38` 的字段表；逐项校验字段名指针、编号、label、type 是否合法。
4. **解析字段表**：按 `0x48` 步长遍历，记录 `(number, name, label, type)`；处理重复编号/非法名字，按 label/type 映射为 proto 语法。
5. **生成 `.proto`**：输出 `syntax`、`package`、`message { ... }`；对无法恢复的 enum/message 类型降级为 `bytes` 并注明。
6. **生成 pb2**：用 `descriptor_pb2.FileDescriptorProto` 序列化并写 `_pb2.py`，或直接用 `protoc` 编译生成的 `.proto`。
7. **验证**：构造一个最小消息 `SerializeToString()`，用目标的解析函数/网络协议发送，确认字段偏移与类型正确；再逐步填充 shellcode/参数。
8. **处理多描述符**：若二进制有多条消息，分别恢复并建立消息类型映射；嵌套类型可通过字段 type 索引与相邻描述符交叉引用。

## PoC

原文脚本约 560 行，核心逻辑如下（精简示意，未在本机复跑）：

```python
from pwn import ELF, p64, u32, u64

MAGIC = 0x28AAEEF9
FIELD_SIZE = 0x48

e = ELF("./ez_orw", checksec=False)
def cstr(addr, limit=0x400):
    out = bytearray()
    for i in range(limit):
        ch = e.read(addr + i, 1)
        if ch == b"\0": break
        out += ch
    return out.decode(errors="replace")

for cand in e.search(p64(MAGIC)):
    name = cstr(u64(e.read(cand + 8, 8)))
    pkg  = cstr(u64(e.read(cand + 0x20, 8)))
    n    = u64(e.read(cand + 0x30, 8))
    ftab = u64(e.read(cand + 0x38, 8))
    if not name or not (0 < n < 0x200) or not ftab:
        continue
    fields = []
    ok = True
    for i in range(n):
        f = ftab + i * FIELD_SIZE
        fname = cstr(u64(e.read(f, 8)))
        num   = u32(e.read(f + 8, 4))
        label = u32(e.read(f + 12, 4))
        typ   = u32(e.read(f + 16, 4))
        if not fname or num == 0 or label not in range(4) or typ not in range(17):
            ok = False; break
        fields.append((num, fname, label, typ))
    if ok:
        print(pkg, name, fields)
        # 生成 .proto，再用 descriptor_pb2 生成 _pb2.py
```

原文恢复结果：

```text
syntax = "proto3";
package giao;
message msgiao {
   int64 giaoid = 1;
   int64 giaosize = 2;
   bytes giaocontent = 3;
   bytes giaotoken = 4;
}
```

## 变体与关联

- **布局变体**：32 位 protobuf-c 的指针宽度与偏移不同；不同版本可能有额外字段/不同 magic 校验方式；需按 `ProtobufCMessageDescriptor` 实际结构核对。
- **类型变体**：嵌套 message/enum 需要递归恢复类型名；oneof/map 在 protobuf-c 中可能以特殊描述符表示；`bytes` 字段对应 `ProtobufCBinaryData` 的 len/data 双槽。
- **无描述符变体**：若二进制只保留 wire 数据、没有描述符，可用 `protoc --decode_raw` 先看字段号/类型，再结合协议行为推断；或用动态插桩打印 `protobuf_c_message_unpack` 的 descriptor 指针。
- **关联**：[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（同一 CTF 题中利用该 schema 构造消息与 token）、其他 ELF 逆向/结构恢复卡。
- **边界**：魔数误命中、描述符被裁剪/加密、32 位布局、复杂类型、字段名清洗都可能导致恢复失败；生成 pb2 需要 Python protobuf 版本兼容。

## 检测与防御

- **对分析者**：strip 符号并不隐藏 protobuf-c 描述符；优先扫描魔数并校验字段表，再用生成的 `.proto` 构造消息；必要时结合动态调试确认偏移。
- **对开发者/防御方**：不要把 schema 当作秘密；若需隐藏协议，使用自定义序列化/加密或裁剪描述符，但客户端仍需解析逻辑，最终可通过动态分析恢复。
- **检测思路**：二进制中出现 `0x28AAEEF9` 魔数、`ProtobufCMessageDescriptor` 结构、大量字段名/包名字符串；协议流量呈现 protobuf wire format（字段 tag + varint/length-delimited）。
