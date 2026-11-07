---
id: ctf-pwn-xmlbridge-libxml2-dict-size-increment-oob-entry-valid
title: libxml2 push parser dict 表越界写网关：DTD 错误回调把 dict->size 加 1，hash%129==128 的 entry.valid 落到相邻 s_2+4
type: scenario
domain: ctf
path: ctf/pwn
technique: libxml2-dict-size-increment-oob-entry-valid-gateway-bypass
tags:
- pwn
- ctf
- libxml2
- xml
- dtd
- heap
- oob-write
- hash-table
- gateway-bypass
- uaf
- push-parser
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:55:40+08:00'
  notes: 已对照原文核对；DTD 534 回调把 s_1+0x10 当 dict->size 加到 129、entry[128].valid 落 s_2+4、D 隧道均一致
url: /docs/ctf/pwn/ctf-pwn-xmlbridge-libxml2-dict-size-increment-oob-entry-valid/
draft: false
kb_aliases:
- xmlbridge
- libxml2 dict 越界写
- dict->size 128 变 129
- xmlDictLookup entry 128
- DTD 未知元素错误回调
- 网关 s_2+4
- xmlDictCreate 堆布局
---

## 一句话结论

在 xmlbridge 题中，前端要求 `qword_60A0 && *(u32*)(qword_60A0+4) == 1` 才允许进入后端转发，而这块 `s_2` 网关缓冲只被 `memset` 清零、没有任何正常写入路径；利用 `xmlDictCreate()` 的 entry 表（128×0x20）恰好紧邻 `s_2`，先用 DTD 未知元素错误回调把复用了 `s_1` 起点的 `dict->size` 从 128 加到 129，再让 `xmlDictLookup` 插入 `hash % 129 == 128` 的名字，使越界 entry 的 `valid=1` 精确写到 `s_2+4`，网关即被打开。

## 原理

- **网关条件**：`B`（结束附件解析）与 `D`（转交归档服务）都检查 `ctxt->myDoc && ctxt->wellFormed && qword_60A0 && *(u32*)(qword_60A0+4) == 1`。`qword_60A0` 是 `A` 里 `malloc(0x420)` 出来的网关缓冲 `s_2`，只被 `memset(s_2,0,0x420)` 清零；全二进制没有写 `[s_2+4]` 的指令，因此必须靠内存破坏把该 u32 变成 1。
- **堆布局**：`A` 依次分配 `malloc(0x40)`×2、`xmlDictCreate()`（dict 结构 0x40 + 128 项 entry 表 0x1000）、`malloc(0x420)` 第一块、`malloc(0x420)` 的 `s_2`。在题目实测布局中，`E` 先把 `S` 的 0x500 快照缓冲 `s_1` free 进 unsorted bin，`A` 的 dict 结构复用 `s_1` 起点，entry 表位于 `s_1+0x5A0`，`s_2 = s_1+0x5B0`，即 `&dict->dict[128] = table+0x1000 = s_2-0x10`。entry 结构为 0x20 字节，`valid` 在 entry+0x14，因此 `entry[128].valid = *(u32*)(s_2+4)`，正好是网关条件要的字段。
- **dict->size 被加 1**：`A` 开了 `DTDVALID`，遇到未声明元素触发 `XML_DTD_UNKNOWN_ELEM(534)`，结构化错误回调 `sub_3147` 执行 `++*(u64*)([0x6098]+0x10)`。`[0x6098]` 是 `S` 的 `s_1` 快照缓冲，而 `A` 的 dict 结构恰好复用了 `s_1` 起点，于是 `s_1+0x10 == dict+0x10 == &dict->size`，128 变成 129。
- **越界 entry 写入**：`xmlDictLookup` 计算 `key = okey % dict->size`，size=129 时 key 可以取到 128；`entry = &dict->dict[128]`，随后写 `name` 到 `s_2-8`（chunk size）、`len` 到 `s_2+0`、`valid=1` 到 `s_2+4`、`okey` 到 `s_2+8`。插入前会先读 `entry->valid`（即 `s_2+4`），因为 `A` 刚 memset 过所以为 0，走插入路径，`valid=1` 落下，`B`/`D` 的网关检查通过。
- **触发与爆破**：`A` 的正文需要一段 DTD（让 `DTDVALID` 有东西可校验）+ 一个未声明元素触发 534 + 大量不同元素名让某个名字的 hash 命中 128。dict 的 hash seed 每个进程随机，所以要多开几个 TCP 连接（每次 exec 新进程、新 seed）重试；120 个名字通常比 300 个更容易在 dict grow 之前命中，因为 grow 会换掉表、越界 entry 消失。
- **过网关后的隧道**：`D` 的转发是“2 字节长度帧进、2 字节长度帧出”，而 broker/manifestvault/keeper/oracle 的协议本来就是 2 字节大端长度 + 正文，所以把后端每一帧包进一次 `D` 调用即可原样跑完四级链，无需改后端 stage 代码。

## 触发条件

- 目标为 xmlbridge 这类“前端 XML 解析 + 网关 + 多级后端服务”的题目/程序；前端使用 libxml2 push parser、`DTDVALID` 与自定义结构化错误回调。
- `A` 的分配顺序能让 dict 结构复用已释放的 0x500 缓冲，且 dict entry 表紧邻 0x420 网关缓冲（依赖 `L/I/R/C/S/E` 的前置消息把堆 groom 成题述布局）。
- 网关缓冲只被清零、没有正常写入路径；网关条件是“某相邻字段 == 1”。
- 攻击者能发送多段 XML 并多次建立连接（每次新进程、新 hash seed）。

## 利用步骤

1. 按题述顺序发送 `L`（`<sheet><item>...`，item 文本 0x20）、`I`（`<root><target>...`，target 文本 0x100）、`R="hi"`、`C`、`S`、`E="wo"`，让 `s_1` 被释放并由 `A` 的 dict 结构复用。
2. 发送 `A`（附件首段）：DTD + 未声明元素 `<zzz/>` + 120~300 个不同名字，例如：
   ```xml
   <!DOCTYPE root [<!ELEMENT root ANY>]>
   <root><zzz/>
     <n0000/><n0001/>...<n0119/>
   </root>
   ```
3. 发送 `B` 结束解析；未声明元素触发 534，回调把 `dict->size` 改为 129；后续每个新名字走 `xmlDictLookup`，若某个 `hash % 129 == 128` 则越界写 `s_2+4=1`。
4. 观察 `B` 的返回：网关通过时回 `DOC <content>` 而不是 `ERR`。hash seed 随机，失败就新开连接重试（120 个名字通常几次内命中）。
5. 过网关后，把 broker/manifestvault/keeper/oracle 的每一帧用 `D` 操作码发送（2 字节长度帧），读取 `D` 的 4 字节长度回包；复用后端的 stage 脚本依次打穿 broker（UAF + VIEW 任意读 + COMMIT 栈溢出）、manifestvault（tcache 投毒写 `.bss`）、keeper（格式化字符串 + COMMIT 栈溢出）、oracle（VM 有符号索引改寄存器），最终由 oracle 读 flag。

## PoC

网关触发的最小 XML 与前端消息序列（原文实测，未在本库复跑）：

```python
L = b"<sheet><item>" + b"L" * 0x20 + b"</item></sheet>"
I = b"<root><target>" + b"T" * 0x100 + b"</target></root>"
for op, body in [(b"L", L), (b"I", I), (b"R", b"hi"), (b"C", b""),
                 (b"S", b""), (b"E", b"wo")]:
    fe.op(op, body)

names = b"".join(b"<n%04d/>" % i for i in range(120))
A = (b'<!DOCTYPE root [<!ELEMENT root ANY>]><root><zzz/>'
     + names + b"</root>")
fe.op(b"A", A)
status, body = fe.op(b"B", b"")   # 多次新连接重试，直到 status == "OK" 且 body 以 DOC 开头
```

堆布局校验（原文实测，相对 `s_1`）：dict 结构 = `s_1`，entry 表 = `s_1+0x5A0`，`s_2 = s_1+0x5B0`；`&dict->dict[128] = s_2-0x10`，`entry[128].valid` 落在 `s_2+4`。

## 变体与关联

- **触发变体**：任何“错误回调写已释放/复用对象字段”的组合都可把 dict 的 size/count 等元数据改大；未声明元素只是本题的 534 触发点。
- **越界字段变体**：entry 的 `name/len/valid/okey` 分别落在相邻对象的不同偏移；若目标条件不是 `+4`，可调整 entry 索引或堆布局让目标字段对齐。
- **隧道变体**：只要前端转发操作能透传后端帧，就可以把多级协议原样塞进去；注意帧长上限与 seq 递增。
- **关联卡片**：[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（字节码 VM 有符号偏移越界写全局）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 堆地址编码，后续 broker/manifest 阶段会用到）。

## 检测与防御

- **代码审计**：检查 XML 结构化错误回调是否在对象释放后仍写其字段；`xmlDictCreate` 的 dict 结构与用户可控的解析选项/DTD 校验组合是否会让 `dict->size` 被外部影响。
- **对象生命周期**：错误回调持有的节点/缓冲区必须在回调期间保持有效；不要把已释放的 0x500 缓冲复用为 dict 结构而没有重新初始化边界。
- **网关设计**：网关状态不要放在与解析器堆对象相邻的可写缓冲区里；使用独立的只读/带完整性校验的状态，或在进入转发前重新校验真实条件而不是单个 u32。
- **检测**：push parser 出现大量 `XML_DTD_UNKNOWN_ELEM` 错误后仍继续解析、同一连接出现大量不同元素名、`dict->size` 异常增长；进程堆布局中出现“dict entry 表紧邻网关缓冲”的分配序列。
