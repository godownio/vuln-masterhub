---
id: binary-pwn-stack-negative-one-length-uint8-truncation-oob-copy
title: 自定义长度函数对空串返回 -1 存入 unsigned __int8 变 255：256 字节栈越界拷贝改写 file 变量读 flag
type: scenario
domain: binary
path: binary/pwn/stack
technique: negative-one-length-uint8-truncation-stack-oob-copy
tags:
- pwn
- stack
- integer-truncation
- negative-length
- uint8
- oob-copy
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:18:31+08:00'
  notes: 已对照原文与图片核对：sub_400A8D 长度函数空串返回负值、调用方 unsigned __int8 v11 截断为 255、for(i=0; v11>=i; ++i) v7[i]=s1[i] 的 256 字节越界拷贝、pingjie 对字节 ^0x30 使 0:0 得到空串、覆盖 file 后 open 读 flag，均与原文/反编译截图一致。注：IDA 中 i 声明为 unsigned int（初始 -1 即 UINT_MAX），截断到 uint8 同为 255，卡片以 -1 叙述为等价简化。未验证点：flag 落在 file 依赖具体栈布局，原文自述为调试所得，未复跑；affected_versions 已 --clear。
url: /docs/binary/pwn/stack/binary-pwn-stack-negative-one-length-uint8-truncation-oob-copy/
draft: false
kb_aliases:
- 长度返回 -1 截断 255
- unsigned __int8 长度截断
- 空串长度绕过
- 栈越界拷贝
- 自定义 strlen 返回值
- pwn_server
---

## 一句话结论

程序用自定义 strlen 风格函数求长度：空串时循环从 `i = -1` 起步直接遇到 NUL，返回 `-1`；调用方把返回值存进 `unsigned __int8` 后变成 `255`，随后 `for (i = 0; v11 >= i; ++i) dst[i] = src[i]` 从只有 32 字节的栈缓冲区复制 256 字节，越界覆盖相邻的 `file` 变量；构造 XOR 后为空的输入（如 `0:0` 经 `^0x30`）触发该拷贝，栈上残留的字符串被写进 `file`，`open(file)` 即打开 flag。

## 原理

- **长度函数返回 -1**：目标二进制中的长度函数实现为
  ```c
  int64_t len(char *s) {
      int i;
      char *p = s;
      for (i = -1; ; ++i) {
          char c = *p++;
          if (!c) break;
      }
      return i;
  }
  ```
  对空串（首字节为 `\0`），第一次判断即 break，`i` 仍为 `-1`。
- **窄类型截断**：调用方声明 `unsigned __int8 v11;` 并执行 `v11 = len(s1);`。`-1` 转为 8 位无符号是 `0xFF`（255）；C 的整型提升让循环条件 `v11 >= i` 变成 `255 >= i`，于是循环执行 256 次。
- **越界拷贝**：`s1` 指向拼接函数里的 `char v3[32]` 栈缓冲区（`sprintf("%s%s", a1, a2)` 后逐字节 `^ 0x30`）。`dst`（`v7`）是相邻的栈缓冲区，容量远小于 256 字节，复制会覆盖其后的局部变量，包括初始化为 `"msg"` 的 `file`。
- **输入构造**：`a1`、`a2` 来自 `recv` 后按 `:` 分割的两个 token（长度都 ≤ 8）。`pingjie(a1,a2)` 把二者拼接并对每个字节异或 `0x30`；发送 `0:0` 得到字符串 `"00"`，异或后为 `"\x00\x00"`，`s1` 即为空串，长度函数返回 -1。
- **为什么能读 flag**：拷贝的源是 `pingjie` 栈帧及其相邻栈数据，目标构建里该偏移处的残留字节拼出了 `"flag"`，覆盖 `file` 后 `open(file, 0)` 打开 flag 文件并把内容写回客户端。这个“栈残留刚好是 flag”依赖具体编译布局，属于该题的做题技巧；可复用的核心是**负长度截断导致的越界拷贝**。
- **根因**：长度类型不匹配（`int64` → `uint8`）、未校验空串/负值、拷贝前无边界检查；长度语义与缓冲区大小完全脱钩。

## 触发条件

- 网络服务接收 `a:b` 形式输入，两个 token 可短于/等于 8 字节。
- 拼接函数会把 token 逐字节异或一个常量（本例 `0x30`），使某些输入（`"0"` 等）得到以 NUL 开头的空串。
- 调用方把自定义长度函数的返回值存入 `uint8`/`uint16` 等窄类型，并用它作为拷贝长度/循环上界。
- 目标栈布局中存在攻击者希望写入的敏感字符串（如文件名），或越界拷贝能覆盖到可控的指针/返回地址。

## 利用步骤

1. 逆向确认长度函数对空串返回 `-1`，以及调用方把长度存入 `unsigned __int8`。
2. 找到拼接/异或函数，构造异或结果为 `\x00` 的输入：`"0" ^ 0x30 = 0`，因此 `0:0` 即可。
3. 发送 `0:0\n`；服务端进入 256 字节越界拷贝。
4. 观察返回：目标构建中 `file` 被栈残留写成 `"flag"`，随后 `open("flag")` 的内容被发回；接收十六进制/原始字节得到 flag。
5. 若目标布局不同，需要先用调试器确认 `v7` 与 `file`/返回地址的相对偏移，构造能覆盖目标字段的输入。

## PoC

```python
from pwn import *

io = remote("<host>", <port>)
io.sendline(b"0:0")          # "0"^0x30 == 0x00，拼接后为空串 -> 长度 -1 -> uint8 255
print(io.recvall(timeout=3))
```

```c
/* 核心逻辑（示意） */
unsigned __int8 n = (unsigned __int8)len(s1);   /* len("") == -1 -> n == 255 */
for (int i = 0; n >= i; ++i)
    dst[i] = s1[i];                              /* 256 字节越界拷贝 */
```

说明：PoC 按原文流程整理；依赖目标栈布局的行为未在本机复跑。

## 变体与关联

- **返回 -1 的其他函数**：`snprintf` 在编码错误时可能返回负值，若被当作 `size_t`/`uint16` 使用会造成超大长度，见 [[binary-pwn-stack-snprintf-return-length-read-overflow]]；`strlen` 结果存入 `int8`/`uint8` 是同类截断。
- **空串/空输入**：任何“空输入得到特殊长度值”的路径都值得检查调用方是否使用窄类型。
- **其他溢出目标**：若布局不允许写 `file`，可尝试覆盖函数指针、返回地址或长度字段，转为常规栈溢出。
- **边界**：编译器若把宽度截断优化掉、调用方使用 `size_t` 保存长度、或循环上界为原 `int64`，本链不成立。

## 检测与防御

- **代码审计**：长度返回值统一用 `size_t`/`int64_t` 保存；空串、负值、溢出值显式处理；拷贝前 `if (len >= sizeof(dst)) return error;`。
- **编译缓解**：`-D_FORTIFY_SOURCE=2`、stack protector、`-Wconversion` 可在编译期/运行期发现部分窄化与越界；但逻辑层漏洞仍应靠代码修复。
- **检测**：服务端日志中出现超长拷贝/异常长度、空串触发的大块内存操作；崩溃转储显示栈缓冲区被相邻局部变量覆盖。
- **防御**：对输入 token 做长度与字符白名单校验；不要依赖“空串长度 = 0”的假设。
