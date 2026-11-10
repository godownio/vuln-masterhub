---
id: binary-pwn-heap-cjson-parse-string-unicode-escape-unbounded-overflow
title: cJSON parse_string 的 \u 转义越界：长度按字符算、写入按字节走，形成长度双算不一致的受控堆溢出
type: scenario
domain: binary
path: binary/pwn/heap
technique: cjson-parse-string-unicode-escape-heap-overflow
aliases:
- cJSON 堆溢出
- parse_string \u 溢出
- JSON 解析器长度双算
- top chunk size 改写
- cJSON 任意字节溢出
tags:
- pwn
- heap
- cjson
- json-parser
- unicode-escape
- off-by-design
- heap-overflow
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T13:36:26+08:00'
  notes: 已对照原文与图01/03/04/05核对（本篇5张，读4张，02为改写前 top size 0x8f0 基线、信息已被01/03覆盖）：parse_string 长度循环 while (*ptr!=chr34 && *ptr && ++len) 与写入循环 if (*ptr!=chr34 && *ptr) 的指针推进差异、case u 分支 parse_hex4(ptr+1) 后 ptr+=4（代理对 ptr+=6）、分配 len+1 与写入量不匹配导致越过引号后继续写到 0 或下一个引号、fake_string(chunk_size,payload,overflow_data) 构造（payload.ljust(chunk_size-2,b01) + 反斜杠u + 引号 + 5个横线 + overflow_data + 引号）、改写 top chunk size 为 0xfffffffffffffff8 并落地 This_is_fake_data_to_chunk、parse_object/parse_value 失败后 cJSON_Delete 释放被破坏 chunk（tcachebins 出现、top 恢复 0x8f0），均与原文一致。核对时把 PoC 里 ljust(chunk_size-8) 更正为原文的 chunk_size-2。未验证点：原文只演示到可控溢出+改写 top size+失败 free，未打通完整 RCE，卡内 confidence=medium 且利用步骤已注明后续 bin/泄漏属延展；原文无版本/CVE。
---

## 一句话结论

当目标用 cJSON（旧版 `parse_string`）解析攻击者可控的 JSON 时，字符串里的 `\u` 转义会绕过"以引号结尾"的写入终止条件：分配长度按 `while (*ptr!='"' && *ptr && ++len)` 计，写入循环却按 `*ptr != '"'` 才停，二者在 `\u` 分支里指针跳过 4/6 字节后可能越过引号，于是写入一直继续到遇到 `\0` 或下一个引号为止 —— 得到一段**长度与分配不匹配、内容完全可控**的堆溢出，可直接改写相邻 chunk 的 size/数据。

## 原理

- 两个 `while` 循环看似一致（`*ptr!='"' && *ptr`），但长度循环每轮执行 `if (*ptr++ == '\\') ptr++;` —— 遇到反斜杠只跳过一个字符；写入循环遇到 `\u` 时执行 `uc = parse_hex4(ptr+1); ptr += 4;`（代理对再 `ptr += 6`），一次跳过 5 个输入字符却只写 1~4 个输出字节。**两套指针推进规则不同**，是根因。
- 关键越过点：构造 `"...\u"` 使 `\u` 后面的四个字节里包含引号（例如 `\u` 紧跟一个 `"`）。`parse_hex4` 把引号当作十六进制位解析出值（非 0），`ptr` 直接跳过这个引号，于是写入循环的"遇到引号就停"条件被跳过，后续所有字节继续被写入 `out` chunk。
- 分配大小由长度循环决定（`len+1`），写入量由实际扫到的字节数决定；一旦写入量超过 `len`，就写到 `out` chunk 之外，覆盖紧随其后的堆块（在简单程序里通常是 top chunk 的 size 字段）。
- 截断条件只取决于攻击者数据：写入会一直持续到出现 `\0`（会被 `strlen`/`read` 长度限制）或再遇到引号。因此可以在一次请求里写入任意长度、任意内容的字节流（`\xff`、`\x00` 除外需注意）。
- 另一个配套性质：`parse_object`/`parse_array` 在解析失败时会 `cJSON_Delete(c)` 释放已分配的 chunk —— 攻击者可用"先溢出、再故意写坏末尾" 的方式让解析失败并释放被破坏的堆块，为后续 tcache/unsorted bin 操作提供 free 机会。
- 为什么这是"设计缺陷"而不是一次性 bug：cJSON 老版本用同一套指针推进假设长度与写入对称；任何让"跳过"与"写"不一致的转义（`\u` 尤其 6 字节代理对、非法 hex）都会打破不变式。

## 触发条件

- 目标程序使用受影响版本 cJSON 的 `cJSON_Parse`（或等价的旧 `parse_string`），并解析攻击者可控的 JSON 字符串。
- 攻击者能控制输入长度：`read(0, buf, 0x100)` 这类固定栈缓冲会限制溢出量；若能发多段/循环解析或直接用 socket 读，则可溢出更多字节。
- 程序未在解析前做严格 JSON 校验（或允许裸 `\u` 后接非 hex 字符）。
- 需要能定位/推断相邻 chunk（top chunk）位置：通常靠同一程序里可预测的分配顺序（先解析出一个固定结构，再解析字符串）。

## 利用步骤

1. 复现最小触发：构造 `"aaaa…\u"-'` 形态的字符串，观察 `out` chunk 的写入越过分配边界、覆盖到 top chunk 的 `size` 字段。
2. 计算偏移：按分配长度（`len+1` 向上对齐到 0x10/0x20）确定 `out` chunk 用户区大小，把 payload 前缀填满该大小，溢出部分紧跟 `size` 字段。
3. 改写 top chunk size（如把它改成一个可控值），为后续"延长 top chunk / House of Force 式分配"或"伪造下一个 chunk 非 top" 做铺垫。
4. 若要进入 bin：把"下一个 chunk"（伪造的）大小字段与 `PREV_INUSE` 位按目标 glibc 版本要求写好，再让解析失败触发 `cJSON_Delete` 释放该 chunk。
5. 用后续业务的 malloc/free 循环把破坏后的 chunk 取回，实现泄漏（unsorted bin 的 `fd/bk` 指向 `main_arena`）或写入（tcache 投毒）。
6. 因为字符串内容总会被 `\0` 截断，**不要指望通过 `cJSON_Print` 直接泄漏**；泄漏要在堆布局层面做（释放后由其他字段或业务回显带出）。

## PoC

```python
# 最小复现：构造 \u 后紧跟引号，使写入越过分配长度
def fake_string(chunk_size, payload, overflow_data):
    # 前缀填满分配大小，\u 后接引号跳过终止条件，'-'*5 占位使后续可控
    s = b'"' + payload.ljust(chunk_size - 2, b'\x01') + b"\\u" + b'"' + b'-' * 5
    s += overflow_data + b'"'
    return s

# 溢出 top chunk size（示意：0x8f1 -> 0x8f1 或任意目标值）
top_size = b'\xf1\x08'
data = fake_string(0x18, b'a', top_size)
print(data[:60])
```

```c
// 触发端（示意）：直接把输入交给 cJSON_Parse
char buf[0x100];
read(0, buf, sizeof(buf));
cJSON *j = cJSON_Parse(buf);   // 受影响版本内部调用 parse_string
// 结果：out chunk 之外的 top chunk size 被 payload 覆盖
```

```text
# 观察点（gdb/pwndbg）
# p/x *(size_t*)(<out_chunk> + <alloc_size>)   # 应看到被改写的 size
# 解析失败路径还会触发 free(c)，可用于制造 bin 中的破坏块
```

## 变体与关联

- 变体：`\uD800` 后缺代理对、`\u` 后接非 hex 字符、代理对第二半非法 —— 都会 `break` 出 `\u` 分支，但 `ptr` 已经前移 4/6 字节，越界条件同样成立。
- 变体：把溢出点选在 `parse_string` 用于 **key** 的场景（`parse_object` 里先解析 key 再 `child->string = child->valuestring`），可以覆盖相邻 cJSON 结构体的 `next/child/string` 指针，构造"链表/子节点"层面的任意写。
- 变体：目标开启 ASLR/堆随机化时，先用"溢出只改 size 的低字节"或相对偏移，再配合 glibc 的 bin 行为做相对写，避免直接写入绝对地址。
- 关联：[[binary-pwn-stack-cjson-unicode-byte-injection-partial-overwrite]]（同一个 `\u` 解码特性被用来在 JSON 文本中携带二进制字节打栈溢出；本卡讲的是 cJSON 自身的堆越界，触发端与 sink 不同）；[[binary-pwn-heap-custom-allocator-negative-size-alignment-overflow]]（同为"长度校验与实际写入不一致"导致堆溢出）。
- 边界：新版 cJSON 对字符串/转义做了更严格校验（例如要求合法 hex、边界检查），需先确认目标版本；不同 glibc 的 top chunk 校验、tcache 加固会改变后续利用难度。

## 检测与防御

- 检测：审计 `parse_string` 一类的"先算长度、再写缓冲"解析器，确认两个循环的指针推进规则是否一致；对 JSON 中出现 `\u` 后紧跟引号/非 hex 字符的请求做告警与拒绝。
- 修复：`\u` 分支在推进指针前校验 4/6 字节是否都是合法 hex；长度与写入使用同一套扫描逻辑；分配后按实际写入上限做边界检查（`ptr2 < out + len`）。
- 加固：开启 CANARY/ASLR、启用 glibc 的 tcache/top chunk 检测；解析器升级到修好该问题的版本；对不可信 JSON 使用隔离进程或长度上限。
- 检测（运行时）：堆块 size 出现异常（超大/非对齐）、`malloc_printerr` 的 `corrupted size vs. prev_size`、解析器进程在处理特定 JSON 后立即崩溃或堆布局突变。

## 备注

原文未标注受影响版本与 CVE 编号，本卡不填写 `affected_versions`/`cve`。原文演示只做到"改写 top chunk size + 溢出写入 + 解析失败 free"，未完成完整 RCE 链，故 confidence 标 medium，并在"利用步骤"中明确后续 bin/泄漏属于延展而非已证明部分。
