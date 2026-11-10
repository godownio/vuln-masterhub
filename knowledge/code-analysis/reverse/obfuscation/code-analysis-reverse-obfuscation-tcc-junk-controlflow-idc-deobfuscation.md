---
id: code-analysis-reverse-obfuscation-tcc-junk-controlflow-idc-deobfuscation
title: 魔改 Tiny C 编译器代码混淆还原：call $+5/pop eax/jmp 调用替换、leave→pop ebx;jmp ebx 返回替换、无效 jnz 与 junk 常数的 IDC 批量 patch
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: tcc-obfuscation-pattern-idc-deobfuscation
aliases:
- 魔改 TCC 代码混淆
- call $+5 获取 EIP
- call 指令等效替换
- ret 替换 pop ebx jmp ebx
- 无效条件跳转永恒不跳转
- junk code 花指令
- IDC 批量 patch 去混淆
- IDA 无法 Create Function
tags:
- reverse
- obfuscation
- deobfuscation
- ida
- idc
- junk-code
- control-flow
- call-obfuscation
- constant-obfuscation
- windows
- x86
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T21:46:53+08:00'
  notes: 已对照原文与 12 张图片逐张核对：魔改 TCC 五类混淆、call $+5/pop eax/add/push/jmp 调用替换（E8 00 00 00 00 58 83 C0 0A 50 E9）、leave/pop ebx/jmp ebx（C9 5B FF E3）返回替换、清零寄存器后无效 jnz、常数混淆与 junk code 无统一自动化方案、IDC 全段 patch 后手动 Create Function 均与 content.md 一致；为完整可复用的去混淆方法论（非未打通/理论链），路径合法，dedup 非同链、dup-scan 无 pair；未验证点：未在本机运行 IDA/IDC，该批次卡按 KB 现状不含 sources/source_url 溯源字段。
---

## 一句话结论

对由魔改 Tiny C 编译器编译的 Windows x86 程序，IDA 会因控制流混淆只识别出极少函数、把 `main` 尾部提前判为 `endp`、无法自动生成函数；按「先定位 main → 识别固定二进制模式 → IDC 脚本批量 patch → 数据流跟踪补剩余混淆」分层去混淆：把 `call $+5; pop eax; add eax,0xA; push eax; jmp xxx` 还原成 `call xxx`、`leave; pop ebx; jmp ebx` 还原成 `leave; ret`、把清零寄存器后的 `jnz` 无效跳转 NOP 掉，之后 IDA 即可手动 `Create Function` 看清主逻辑。

## 原理

- **混淆来自编译器代码生成器改造**：程序不是源级混淆，而是魔改的 Tiny C 编译器在生成机器码时自动插入五类模式——① 常数替换成一串算术求值；② 大量随机 junk 指令淹没少量有效代码；③ `call` 指令等效替换；④ `ret` 指令替换；⑤ 永恒跳转/永恒不跳转的无效条件跳转。后三者本质是控制流混淆。
- **为什么 IDA 分析失效**：反汇编器按指令流顺序识别基本块与函数边界。无效条件跳转的跳转目标被刻意设成 `loc+1`/`loc+4` 这类「破坏指令边界」的地址（`xor edx,edx` / `sub ebx,ebx` 清零后 ZF=1，`jnz` 实际永不跳转，但线性扫描仍会把目标处误当指令起点），导致后续真实代码断档、函数被错误截断；`ret` 被替换后 IDA 找不到函数结尾，`main` 无 `ret` 直接 `endp`；junk 指令里的大常数与只写寄存器的运算会干扰栈/寻址分析，阻碍生成伪代码。
- **call 替换的语义**：`call $+5` 把「下一条指令地址」压栈（`$` 为当前指令地址，call 长 5 字节，故目标恰为下一条），`pop eax` 取到该 EIP，`add eax,0xA` 把返回地址改到 `printf` 之后的 `add esp,4`，`push eax` 压回，`jmp printf`——等价于一次 `call printf`（返回地址指向调用后的堆栈清理）。固定 10 字节模式 `\xE8\x00\x00\x00\x00\x58\x83\xC0\x0A\x50`，后接 `\xE9`(jmp)。
- **去混淆可行性**：这些模式是编译器批量生成的，二进制字节固定，故可用 IDC 脚本全段搜索替换；而常数混淆与 junk code 的计算方式多样、无统一模式，无法自动化，只能用「跟踪函数参数/关键字段在寄存器与内存之间的流动方向，忽略只写寄存器不写内存的垃圾指令」的人工策略。
- **为什么分层（剥茧抽丝）**：多种混淆叠加，必须一类一类识别、一层一层 patch；先恢复控制流（让 IDA 能定义函数），再靠数据流跟踪补出被 junk 淹没的有效代码。

## 触发条件

- Windows x86 二进制，由魔改 Tiny C 编译器（对 codegenerator 做了混淆改造）编译。
- IDA 自动分析只识别出 `start` 与少量库函数、`main` 未识别或函数体异常短、TEXT View 显示 `endp` 之后还有大段代码。
- 字符串未加密（可借错误提示/格式字符串定位关键分支）、常量与 junk 指令大量出现。
- 具备 IDA + IDC（或 IDAPython）脚本修改字节的能力；patch 前备份原文件。

## 利用步骤

1. **定位 main**：看 `start`，找 `__getmainargs` 之后的「三个参数（argc/argv/env）」调用，把对应 `sub_XXX` 重命名为 `main`，IDA 会自动更新参数与原型（`int __cdecl main(int argc, const char **argv, const char **envp)`）。
2. **确认控制流混淆**：切 TEXT View，观察 `main endp` 之后是否仍有大量代码，判断函数边界被破坏而非真的结束。
3. **模式 1（调用替换）**：全段搜索 11 字节 `\xE8\x00\x00\x00\x00\x58\x83\xC0\x0A\x50\xE9`，把前 10 字节写 `\x90`（NOP）、把第 11 字节 `\xE9`(jmp) 改成 `\xE8`(call)，得到 `nop×10; call printf; add esp,4`。
4. **模式 2（返回替换）**：搜索 dword `\xC9\x5B\xFF\xE3`（`leave; pop ebx; jmp ebx`），patch 成 `\xC9\x90\x90\xC3`（`leave; nop; nop; ret`）。
5. **模式 3（无效 jnz）**：搜索三字节模式 `29|31` + `c0|db|c9|d2` + `75`（`sub/xor reg,reg; jnz`），命中即把 4 字节 patch 成 `\x90\x90\x90\x90`；这类跳转条件恒假但目标地址破坏指令边界。
6. **模式 4/5（常数混淆 + junk code）人工处理**：不写脚本，跟踪关键数据（函数参数、字符串引用、全局数据块如 `dword_41C1B4` 起始值）的流向；junk 指令只写寄存器、不写内存且常带大常数，直接忽略；优先看函数输出与上层调用逻辑，不要逐个跟进 `get_key_0..15` 之类重复函数，避免绕圈。
7. **恢复函数**：应用脚本后手动 `Create Function`，得到完整函数列表，控制流与字符串即可读，main 的整体逻辑可还原。

## PoC

调用替换 IDC 骨架：

```c
#include <idc.idc>
static cmpmem(a, s, n){ auto i; for(i=0;i<n;i++) if(byte(a+i)!=(ord(s[i])&0xff)) return 1; return 0; }
static patch_bytes(d, s, n){ auto i; for(i=0;i<n;i++) patch_byte(d++, ord(s[i])&0xff); }
static main(){
  auto pat = "\xE8\x00\x00\x00\x00\x58\x83\xC0\x0A\x50\xE9";
  auto rep = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xE8";
  auto ea, total=0;
  for(ea=MinEA(); ea<=MaxEA(); ea++)
    if(cmpmem(ea, pat, 11)==0){ patch_bytes(ea, rep, 11); ea+=10; total++; }
  msg("total=%d\n", total);
}
```

返回替换 + 无效 jnz 的 IDC 骨架（同一脚本第二段）：

```c
// leave; pop ebx; jmp ebx  ->  leave; nop; nop; ret
for(ea=start; ea<end-3; ea++)
  if(dword(ea)==0xE3FF5BC9){ patch_dword(ea, 0xC39090C9); ea+=3; }
// sub/xor reg,reg; jnz  ->  4×NOP
for(ea=start; ea<end-3; ea++){
  auto p=get_bytes(ea,3,0); if(p==0) break;
  auto a=ord(p[0])&0xff, b=ord(p[1])&0xff, c=ord(p[2])&0xff;
  if((a==0x29||a==0x31) && c==0x75 && (b==0xc0||b==0xdb||b==0xc9||b==0xd2))
    patch_dword(ea, 0x90909090), ea+=3;
}
```

（按文章脚本最小化整理，未在本机运行 IDA/IDC。）

## 变体与关联

- 变体：`call $+5` 取 EIP 是恶意软件/壳常用技巧；`pop eax; add eax,Δ` 中的 Δ 取决于被调函数返回后的堆栈平衡长度，不同目标可能不同，需按实际字节模式调整。
- 变体：无效跳转也可用 `jz`/`jne` 之外的条件跳转或「永恒跳转」，识别要点是「先清零/置标志使条件恒定 + 跳转目标落在指令中间」。
- 变体：junk code 若改为写内存，则「忽略只写寄存器」策略失效，需结合动态调试（断点/跟踪写入）区分。
- 关联：[[ctf-reverse-oep-junk-code-call-add-retn]]（OEP 识别与 call/add/retn 花指令 NOP）、[[code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair]]（jz 跳过 E8 的线性扫描花指令与 IDA 修复）、[[code-analysis-reverse-obfuscation-silverfox-vm-call-idapython-restore]]（IDAPython 识别 call 模式并常量折叠）；本卡针对「编译器批量生成的固定字节模式」做全段 IDC 替换，模式与修复手段不同。
- 局限：依赖该编译器固定的二进制模式，换编译器/版本/编译选项即失效；常数混淆与 junk 无自动化方案；patch 前必须验证模式唯一性，避免误改有效代码。

## 检测与防御

- 这是本地逆向分析方法，不产生网络攻击面；防守方关注点是增加分析成本（字符串加密、模式随机构造、控制流平坦化），但本例模式固定恰是可被批量还原的弱点。
- 使用方：patch 前备份数据库/文件；每类模式先小范围验证再全段替换；确认 hash/入口点未被破坏；对 NOP 后仍无法识别的函数用动态调试辅助。
- 检测侧（蓝队识别此类二进制）：函数调用被 `call $+5; pop reg; add reg; push reg; jmp` 模式大量替换、`leave` 后跟 `pop+jmp`、大量清零寄存器后的短条件跳转、海量只写寄存器的大常数运算，可作为「代码混淆/加壳」的静态特征。
