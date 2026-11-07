---
id: binary-pwn-heap-uninitialized-session-negative-fraglen-tcache
title: 未初始化 WebSocket session + 负 frag_len 下写：伪造堆头进 tcache 并覆盖 session 做 AAR/AAW
type: scenario
domain: binary
path: binary/pwn/heap
technique: uninitialized-session-negative-fraglen-tcache-poison
aliases:
- wsd
- ws_session 未初始化
- frag_len 负数
- heap underwrite
- tcache poisoning
- WebSocket 分片
- AAR AAW
tags:
- pwn
- heap
- uninitialized
- negative-length
- tcache
- websocket
- safe-linking
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:52:56+08:00'
  notes: 已对照原文 wsd 核对：ws_session_create 只初始化 state、非法握手 header value 落 tcache、seed=A*16+p64(-0x10)、continuation frag_len=-0x10 触发 memcpy(tmp-0x10) 下写、伪造 p64(0)+p64(0x91) 进 tcache、PONG 0x80 分配后偏移 0x50 覆盖 session、空 continuation AAR、tcache poison free@GOT=ret/栈 ROP 均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

WebSocket 服务创建 session 时只初始化 `state`，`frag_len`/`frag_buf` 等分片字段保留 tcache 复用 chunk 的旧内容；攻击者先用非法 HTTP 握手把可控 header value 释放进 0x20/0x30 tcache，再用合法握手让 session 复用该 chunk，使 `frag_len=-0x10`、`frag_buf=NULL`；随后一个 continuation 触发 `realloc(NULL, new_len)` + `memcpy(buf-0x10, payload, len)` 的负偏移下写，可伪造堆头、污染 tcache，并把 session 字段改成任意 `frag_len/frag_buf`，得到稳定的 AAR/AAW，最终 tcache poison 到 `free@GOT` 与栈返回地址完成 ROP。

## 原理

- session 结构近似：
  ```c
  struct ws_session {
      enum ws_state state;
      enum ws_opcode frag_opcode;
      size_t frag_len;
      uint8_t *frag_buf;
  };
  ```
  `ws_session_create()` 只写 `s->state = WS_STATE_OPEN`，其余字段未初始化；`malloc(sizeof(*s))` 若复用了此前释放的 chunk，就继承旧数据。
- HTTP 握手解析会把 header value 用堆分配保存；握手失败后释放这些 value，但连接不关闭，可以继续发下一次 HTTP 请求。攻击者控制 value 的大小和内容，就能在对应 tcache bin 中留下可控 chunk。
- 构造 seed：`b"A"*16 + p64(-0x10)`，让复用为 session 后：前 8 字节被 `state` 覆盖，`frag_opcode` 为旧值，`frag_len` 为 `-0x10`，`frag_buf` 为后续布局中的 NULL/可控值。
- continuation 处理：
  ```c
  if (frame->payload_len > 0) {
      size_t new_len = session->frag_len + frame->payload_len;
      uint8_t *tmp = realloc(session->frag_buf, new_len);
      session->frag_buf = tmp;
      memcpy(session->frag_buf + session->frag_len, frame->payload, frame->payload_len);
      session->frag_len = new_len;
  }
  ```
  当 `frag_len=-0x10`、`frag_buf=NULL` 时，`realloc(NULL, new_len)=malloc(new_len)`，`memcpy(tmp-0x10, payload, len)` 从新 chunk 前 0x10 字节开始写，覆盖 chunk header。第一次写合法 header `p64(0)+p64(0x91)`，避免后续 free 因元数据损坏 abort。
- 伪造 0x90 chunk 后，continuation 结束时 `free(session->frag_buf)` 把它放入 0x90 tcache；下一次 PONG 的 `ws_parse_frame()` 先 `malloc(payload_len)`，若 payload_len 为 0x80 就从该 tcache 取回 fake chunk，并把 PONG payload 拷进去。由于 fake chunk 用户区到 session 起始固定差 0x50，payload 偏移 0x50 处即可覆盖 session 的 `state/frag_opcode/frag_len/frag_buf`。
- 覆盖后：
  - 空 continuation（`payload_len=0`、`FIN=1`）跳过 realloc，直接 `ws_send_frame(frag_opcode, frag_buf, frag_len)`，从任意地址读任意长度 → AAR。
  - 负 `frag_len` + 精心 payload 可覆盖 tcache entry 的 fd，配合 safe-linking 把下一次分配导向 `free@GOT`/栈 → AAW。
- 泄漏链：heap 用 safe-linking 的 `stored = next ^ (chunk>>12)`；libc 用 unsorted bin 的 arena 指针；PIE 用 `environ` + auxv `AT_PHDR`；栈返回地址用 `environ-0x200`（对应 `server_handle_client` 中 `call ws_on_data` 的返回槽）。
- 最终：stage 1 把 `free@GOT` 改成 `ret`（并恢复 `write@GOT`），stage 2 把 ROP 写到栈返回地址，调用 `system("cat flag*>&4")`。

## 触发条件

- WebSocket/HTTP 服务在失败握手后保留连接并释放 header value 到 tcache。
- session 结构体未清零，且大小与可控 header value 的分配大小匹配。
- 分片处理使用有符号 `size_t`/`ssize_t` 或未检查 `frag_len + payload_len` 的负值/下溢。
- 目标使用 glibc tcache 且存在可用的 safe-linking 泄漏/绕过。
- 攻击者能建立 TCP 连接并控制 HTTP header 与 WebSocket frame。

## 利用步骤

1. 第一次发非法 WebSocket 握手，带若干特定大小的 header（如 0x20/0x30/0x50/0x70 bin），value 内容为 seed `A*16 + p64(-0x10)`；握手失败后 value 被释放进 tcache。
2. 同一连接发合法握手，服务调用 `ws_session_create()`，session 从对应 tcache 取回 seed chunk，继承 `frag_len=-0x10`。
3. 发一个带 payload 的 continuation，`realloc(NULL, new_len)` 得到新 chunk，`memcpy` 从 chunk-0x10 下写；先写入 `p64(0)+p64(0x91)` 伪造 0x90 chunk header。
4. continuation 结束触发 `free(frag_buf)`，fake 0x90 chunk 进入 tcache。
5. 发 0x80 字节 PONG，让 `ws_parse_frame()` 的 `malloc(0x80)` 取回 fake chunk；PONG payload 偏移 0x50 处写入 session 字段：`state=0, frag_opcode=1, frag_len=size, frag_buf=addr`。
6. 发空 continuation + FIN，触发 `ws_send_frame(frag_buf, frag_len)`，完成任意地址读；发非空 continuation 配合 tcache 污染完成任意写。
7. 依次 leak heap/libc/PIE/stack，stage 1 改 `free@GOT=ret`，stage 2 把 ROP 写到栈返回槽，执行 `system` 读 flag。

## PoC

```python
# 1) 非法握手留下可控 tcache chunk
seed = b"A" * 16 + p64(-0x10)
extra = b"X-Large: " + b"B" * 0x500 + b"\r\n"
for i in range(3):
    extra += b"X-Seed-%02d: " % i + seed + b"\r\n"
send_http(s, extra=extra, valid=False)
send_http(s, key=b"K" * 16, valid=True)

# 2) 伪造 0x90 chunk header
s.sendall(frame(0, p64(0) + p64(0x91) + b"A" * 0x20, fin=True))

# 3) 用 PONG payload 覆盖 session 字段（偏移 0x50）
buf = bytearray(b"P" * 0x80)
buf[0x50:0x70] = struct.pack("<QQQQ", 0, 1, size, addr)
s.sendall(frame(0xA, bytes(buf), fin=True))

# 4) 空 continuation 触发 AAR
s.sendall(frame(0, b"", fin=True))
data = ws_payload(read_ws(s))
```

完整 EXP 见原文（约 300 行 Python，含 safe-linking、unsorted bin、auxv、tcache poison、ROP）。PoC 未在本机执行；偏移依赖固定握手布局与 libc 版本。

## 变体与关联

- 变体：任何“只初始化部分字段”的结构体复用 tcache chunk，都可能继承攻击者可控数据；不限于 WebSocket session。
- 变体：`frag_len` 为负或 `frag_len + payload_len` 下溢，导致 `memcpy` 前移/后移；也可用 `realloc` 大小回绕制造超大分配。
- 变体：无 safe-linking 的旧 glibc 可直接写 tcache fd；有 safe-linking 时先 leak heap page。
- 关联卡片：[[binary-pwn-heap-uninitialized-tx-context-uaf-arbitrary-free-read]]（未初始化上下文）、[[binary-pwn-heap-house-of-botcake-tcache-poison]]（tcache poisoning）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 泄漏）、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（tcache 打 environ/栈）。
- 注意：本例为 Hackropole FCSC 2026 wsd 题；真实服务需具体分析结构体初始化、分片长度检查与分配器版本。

## 检测与防御

- 防御：结构体分配用 `calloc`/`memset` 清零，或显式初始化所有字段；不要依赖 malloc 返回值。
- 防御：分片长度使用无符号类型并检查上界、下溢与 `frag_len + payload_len` 溢出；`memcpy` 前验证目标偏移在缓冲区内。
- 防御：开启 Full RELRO（本例 Partial RELRO 使 GOT 可写）、FORTIFY_SOURCE、ASan/UBSan；使用安全的分片缓冲实现（记录容量、单独分配）。
- 检测：WebSocket 服务中出现负/超大 `frag_len`、异常 continuation 序列、同一连接多次非法握手后合法握手；堆元数据损坏告警。
- 响应：隔离服务、重启、检查 GOT/栈是否被改、修复结构体初始化与长度校验。
