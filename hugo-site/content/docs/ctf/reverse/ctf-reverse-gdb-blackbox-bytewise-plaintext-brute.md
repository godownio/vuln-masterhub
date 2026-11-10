---
id: ctf-reverse-gdb-blackbox-bytewise-plaintext-brute
title: gdb Python 黑盒逐字节明文爆破：断点监控加密输出，与已知密文逐字节比对还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: gdb-blackbox-bytewise-plaintext-brute
tags:
- ctf
- reverse
- gdb
- brute-force
- breakpoint
- dynamic-analysis
- rc4
- blackbox
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-07T23:21:54+08:00'
  notes: 已对照原文核对：gdb Python 断点监视加密输出、逐字节枚举 0-127、与 not_flag 密文比对、stdin 重定向与 run<test.txt 流程均与原文脚本/截图一致；img/07-09 显示断点 2678/2679 命中并逐步得到 flag。卡内 PoC 为按原文抽象的最小骨架（未执行），原文主脚本自注『未测试』但截图证明方法跑通；CTF 题解无组件版本。
url: /docs/ctf/reverse/ctf-reverse-gdb-blackbox-bytewise-plaintext-brute/
draft: false
kb_aliases:
- gdb 黑盒爆破
- 已知密文明文爆破
- 逐字节黑盒测试
- gdb Python 脚本爆破
- 断点对比密文
- Black_Test
---

## 一句话结论

当程序把输入加密后与一段已知密文逐字节比较，且加密是逐字节独立（RC4、XOR、流密码等）时，不必逆向加密算法：用 gdb Python 在加密前后/比较处下断点，固定已恢复的前缀、按位置枚举当前明文字节（0–127），每轮运行到断点读取输出字节并与已知密文对应字节比对，命中即确定该字节；逐位推进，最多约 `128 × 明文长度` 次即可还原完整明文/flag。

## 原理

- **黑盒测试模型**：把加密函数当作黑盒，输入改变一个字节、观察输出对应字节。对 RC4 这类流密码，密钥流只与密钥和位置有关、与明文无关，因此 `C[i] = P[i] XOR KS[i]`；改变 `P[i]` 只影响 `C[i]`，不会影响已确定的前缀或后续字节，适合逐字节爆破。
- **断点取值**：在输入读入/加密开始处设断点拿到初始状态；在加密完成、与密文比较前设断点，此时输出缓冲区（或寄存器）里就是候选密文。gdb Python 用 `gdb.selected_inferior().read_memory(addr,len)` 读内存、`write_memory` 写回候选输入，`gdb.execute("b *addr")`/`c` 控制执行。
- **逐字节流程**：先构造一个占位明文（如全 `0x01`），对第 `i` 位枚举 `j=0..127`：把 `P[i]=j` 写回输入缓冲区（或临时输入文件），从初始状态运行到结束断点，读 `C[i]` 与已知 `enc[i]` 比较；相等则记录 `j` 并进入下一位。已确定的低位保持不变，作为下一次运行的固定前缀。
- **为什么省去逆向**：加密可能经过多层/混淆，静态分析成本高；而黑盒每字节最多 128 次、总次数与明文长度线性相关（双字节依赖则为 `128²×n`），对短 flag 完全可行。代价是必须能反复运行程序并控制断点，且加密不能有跨字节扩散。
- **适用边界**：流密码、RC4、简单 XOR、逐字节替换可用；AES-CBC 等分组密码一个明文字节会扩散到整块，单字节比较可能碰撞，需要按块或按多字节组合爆破（`128^block`），否则不适用。`scanf`/`gets` 等输入函数通常不接受 `\x09`、`\x0a`、`\x0d`，枚举范围常取 0–127 并跳过这些字符。

## 触发条件

- 二进制中存在已知密文数组（如 `not_flag`）或可获取的密文，且程序对输入加密后逐字节/逐块比较。
- 加密满足逐字节独立（或可按块爆破），密钥固定、无随机 IV/nonce 变化。
- 能在 gdb 下运行程序，并定位输入缓冲区地址、密文输出地址/寄存器、比较循环地址。
- 输入缓冲区地址稳定（关闭 ASLR、使用非 PIE 基址或符号），或脚本能动态解析。
- gdb 带 Python 支持（MinGW-w64 的 gdb 需含 python 组件），脚本可用 `Crypto.Util.number.long_to_bytes`/`libnum` 或自行实现字节转换。

## 利用步骤

1. 在 IDA/Ghidra 中定位：输入读取（`scanf`/`fgets`/`read`）、加密调用、逐字节比较循环（如 `cmp [rbx+rax], sil` / `jz`），记录输入缓冲区地址、密文数组地址和比较前指令地址。
2. 用 gdb 加载程序，在“输入已读入/加密开始”和“加密完成/比较前”分别下断点，确认断点命中时寄存器/内存中能看到密文。
3. 编写 gdb Python 脚本：
   - 读取已知密文数组 `enc`；
   - 初始化 `flag = b'\x01' * len(enc)`；
   - 对每个位置 `i`，枚举 `j=0..127`，把候选明文写回输入缓冲区或临时输入文件；
   - 恢复初始状态并运行到结束断点，读取输出字节 `out[i]`；
   - 若 `out[i] == enc[i]`，固定 `flag[i]=j` 并跳出内层循环。
4. 对 stdin 输入的程序，把候选明文按程序期望的字节序写入文件，`run < input.bin`；对内存输入，直接在断点处 `write_memory` 覆盖缓冲区。
5. 全部位置命中后输出 `flag`，验证程序是否打印 `Correct flag!`。
6. 若某位 0–127 都未命中，检查字节序、是否跳过 `\x09/\x0a/\x0d`、是否应按块比较，或密文是否经过额外编码。

## PoC

以下为最小脚本骨架（地址与密文需按目标替换，未在本机执行）：

```python
import gdb

ENC = [0x4A, 0x08, 0xD5, 0xF4, 0xF9, 0xD0, 0x3E, 0x1B, 0xEA, 0x46]  # 已知密文
START = 0x140002C0A   # 输入已读入 / 加密前
END   = 0x140002C12   # 加密完成、比较前
IN    = 0x5FFD50      # 输入缓冲区（示例，原地加密）

flag = bytearray(b"\x01" * len(ENC))
gdb.execute(f"b *{START:#x}")
gdb.execute(f"b *{END:#x}")
gdb.execute("run < input.bin")

for i in range(len(ENC)):
    for j in range(128):
        if j in (0x09, 0x0a, 0x0d):
            continue
        flag[i] = j
        gdb.selected_inferior().write_memory(IN, bytes(flag))
        gdb.execute("continue")
        out = int(gdb.parse_and_eval(f"*(unsigned char*)({IN}+{i})"))
        if out == ENC[i]:
            print(f"[+] byte {i} = {j:#x}")
            break
print(bytes(flag))
```

要点：脚本每轮只改一个字节；若程序用 `run` 重新启动，需重新在 START 断点停下并恢复初始寄存器/内存状态；若加密原地写回输入缓冲区，可直接读 `IN+i`，否则改读输出缓冲区或寄存器（如 `$al`/`$rax`）。

## 变体与关联

- 多字节依赖：两个字节相互影响时枚举 `128²` 组合；分组密码按块比较整块密文，避免单字节碰撞。
- 取值位置：输出在寄存器时用 `gdb.selected_frame().read_register("rax")`；在堆/栈缓冲区时用 `read_memory` 监控 `[addr, addr+len]`。
- 输入方式：stdin 重定向、argv、环境变量或网络 socket；核心都是把候选明文送到加密函数入口。
- 关联：与 Unicorn 离线模拟 oracle（只模拟加密函数）、密码学差分/选择明文攻击的区别在于：本方法完全不理解算法，只依赖可重复运行和已知密文；若加密存在随机 IV 或密钥每次变化，则黑盒比对失效。
- 工具化：可将 gdb 替换为 x64dbg 脚本、Frida 或自写 ptrace 驱动，思路相同。

## 检测与防御

- CTF/逆向：遇到“输入→加密→与硬编码数组比较”的程序，优先评估逐字节爆破；用 gdb 日志确认每次运行的密文变化只落在当前字节。
- 软件保护：不要把明文加密后的密文与输入直接逐字节比较；使用带扩散的分组密码、随机 IV/MAC、常量时间比较和反调试；对关键校验做完整性保护。
- 检测（防守方）：监控进程被调试器反复重启、断点命中频率异常、同一程序短时间内大量运行；但这些行为在 CTF 环境属正常分析手段。
- 边界：仅适用于可重复执行且加密确定性的程序；若目标有反调试、输入长度/字符集限制或每次随机密钥，需要先绕过这些前置条件。
