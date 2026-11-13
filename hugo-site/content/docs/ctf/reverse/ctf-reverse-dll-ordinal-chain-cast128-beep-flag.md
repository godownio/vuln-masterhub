---
id: ctf-reverse-dll-ordinal-chain-cast128-beep-flag
title: DLL 导出序号链逆向：IDA Python 还原 1-48 号调用顺序，按序调用改 CAST128 密钥解密内嵌 PE 与 Beep 校验输出 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: dll-export-ordinal-chain-cast128-beep
tags:
- ctf
- reverse
- dll
- export-ordinal
- ida-python
- cast128
- beep
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V581
  verified_at: '2026-11-12T12:31:33+08:00'
  notes: 已对照原文与全部17张图核对：52导出、challenge_1-48改byte_10007014密钥并返回下一序号（图06/图14）、challenge_39 'E'^']'=24汇编、SignSrch 1.6命中CAST128 sbox1-8、51号解密unk_10007060 6672字节且hex dump为MZ内嵌PE、50号Beep满18次调49号、flag f0110w_t3h_3xp0rts@flare-on.com均一致；dedup仅ctypes卡related非同链；无版本/CVE。未验证点：PoC未本机复跑；frontmatter无sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-dll-ordinal-chain-cast128-beep-flag/
draft: false
kb_aliases:
- FlareOn 2016 challenge
- flareon2016challenge.dll
- DLL 导出函数链
- 导出序号调度
- CAST128 解密
- Beep 音频 flag
- ida-python 提取返回序号
---

## 一句话结论

当 CTF 的 DLL 题目把逻辑拆成 52 个导出函数、且 1-48 号每个都在修改 16 字节密钥后返回"下一个应调用的序号"时，不要试图在 IDA 里直接调试 DLL：先用 IDA Python 扫描每个 challenge 函数内被编译器优化成两条立即数异或的返回值（如 `'E' ^ ']' = 24`）还原完整调用顺序，再写一个 loader（C 的 `LoadLibraryA`+`GetProcAddress(MAKEINTRESOURCE(ord))` 或 Python `ctypes`）按顺序逐个调用，让 51 号用被正确修改过的密钥做 CAST128 解密、dump 内嵌 PE；最后按导出 50 号 `Beep(freq,dur)` 的 18 组频率/时长参数播放"歌曲"，触发 49 号解密并打印 flag。

## 原理

- **DLL 无法像 exe 一样直接调试**：IDA 的调试器插件对 DLL 常报 "The file can't be loaded by the debugger plugin"，因为 DLL 需要宿主进程加载；标准做法是写一个 exe（或 Python ctypes）`LoadLibrary` 目标 DLL，再 `GetProcAddress` 取导出函数调用。
- **导出序号链（ordinal dispatcher）**：DLL 导出表有 52 项，其中 `flareon2016challenge_1` 到 `_48` 每个形如 `byte_10007014[dword_10007010 % 0x10] ^= 0xNN; --dword_10007010; return next;`——即"改 16 字节密钥中的一字节，然后返回下一个要调用的导出序号"。必须按特定顺序把 48 个函数全部调用一遍，密钥才会被修正成 51 号解密所需的正确值；顺序错/漏调则 CAST128 解出的数据是乱的。
- **静态还原调用顺序**：每个 challenge 的返回值被编译器优化成两条立即数异或（如 challenge_39 的 `mov [ebp+var_4], 45h ('E')` 与 `mov [ebp+var_8], 5Dh (']')`，最后 `eax = [ebp+var_4] ^ [ebp+var_8] = 0x18 = 24`）。IDA Python 遍历函数区间 `0x10001C70-0x10002E10`，对每个 `flareon2016challenge_*` 取偏移 `+0x7` 与 `+0xe` 处的立即数做异或即得返回序号，去重排序后即可得到调用链；文中还发现 30 号是 base call（起点），最终链以 51 结尾。
- **CAST128 识别**：用 IDA SignSrch 插件（Signsrch 1.6 by Sirmabus）扫描 `.rdata`，命中 `CAST128 / CAST256 sbox1..sbox8` 与 `CAST_S`，从而确认 `sub_10001000` 是 CAST128 解密函数（密钥 `byte_10007014` 16 字节，输入/输出/长度由调用方给出）。
- **两处调用**：导出 51 调用 `sub_10001000(v1, &unk_10007060, &unk_10007060, 6672)` 解密 `0x1A10` 字节数据——hex dump 显示 `unk_10007060` 以 `MZ`/`This program cannot be run in DOS mode` 开头，是一段内嵌 PE，dump 后可继续分析；导出 49（被 50 调用）用 32 字节 `asc_1000703C` 解密并 `printf("%s")` 输出 flag。
- **Beep 校验作为答案判定**：导出 50 `int __cdecl flareon2016challenge_50(DWORD dwFreq, DWORD dwDuration)` 先 `Beep(dwFreq, dwDuration)`，再把参数与 `byte_10007028` 序列比对（`== dwFreq`、`^= dwDuration`），计数到 18 次时调用导出 49 解密打印 flag——因此按正确频率/时长调用 18 次 Beep（即"把曲子弹对"）就得到 flag。
- **为什么可行**：题目把"正确答案"编码进序号链与音频序列，静态还原顺序 + 动态按序调用即可绕过对 CAST128 内部实现与 Beep 语义的完全理解。

## 触发条件

- 目标为 Windows DLL（本题 32 位），导出表暴露大量可疑函数，且每个导出存在"改密钥 + 返回下一序号"的固定模式。
- 能用 IDA/Ghidra 定位函数区间与返回值常量（或动态逐个调用观察返回值）。
- 分析机为 Windows（`LoadLibrary`/`Beep`/ctypes 可用），或能在 Wine/虚拟机中加载 DLL。
- 题目最终输出依赖调用顺序/参数（密钥链、音频校验），而不是单函数静态常量。

## 利用步骤

1. IDA 打开 DLL，查看 Exports 共 52 个导出；逐个阅读 `flareon2016challenge_*`，确认 1-48 号都修改 `byte_10007014[...]` 并返回下一个序号，51 号调用 `sub_10001000` 解密 `unk_10007060`（长度 6672），50 号是 `Beep` 包装并调用 49 号。
2. 用 SignSrch 扫描加密常量，确认 `sub_10001000` 为 CAST128（`.rdata` 中 sbox1-8 命中）。
3. 用 IDA Python 扫描函数区间，提取每个 challenge 函数内两条立即数的异或作为返回序号，去重排序，得到从 base call（30 号）到 51 号的调用顺序（文中顺序如 48,20,1,21,33,25,...,30）。
4. 写 loader exe：`LoadLibraryA(dll)`，从起点 30（或 48）开始循环 `GetProcAddress(h, MAKEINTRESOURCE(cur))` 调用并把返回值作为下一次序号，直到 51；调用 51 完成 CAST128 解密。
5. 从 51 号函数体内取解密数据指针（如 `*(uint32_t*)((uint32_t)exp + 0x2e)`）与长度 `0x1A10`，`WriteFile` dump 出内嵌 PE 供进一步分析。
6. 用 Python ctypes（`mydll[30]()` 起循环到 51）或 C loader 调用导出 50，按正确频率/时长重复 18 次 Beep（如 440/500、349/350、523/150...），第 18 次后 49 号解密并打印 flag。
7. 记录 flag（本题 `f0110w_t3h_3xp0rts@flare-on.com`）。

## PoC

IDA Python 提取返回序号（原文脚本骨架）：

```python
startaddr = 0x10001C70
endaddr   = 0x10002E10
funcs = idautils.Functions(startaddr, endaddr)
for i in funcs:
    m = re.match(rptn, idc.get_func_name(i))
    if m and m.group(1) != "51":
        # 返回值为函数内两处立即数异或
        nextordinal = int(idc.print_operand(i+0x7, 1).replace("h", ""), 16) \
                    ^ int(idc.print_operand(i+0xe, 1).replace("h", ""), 16)
        ret.append(nextordinal)
ret = sorted(set(ret))
```

C loader 按序调用（原文章节修正了 `ret`/`nextord` 变量笔误）：

```c
HMODULE hLib = LoadLibraryA(argv[1]);
uint32_t nextord = 30;                       // base call
while (nextord != 51) {
    EXP exp = (EXP)GetProcAddress(hLib, MAKEINTRESOURCE(nextord));
    nextord = exp();
}
EXP exp = (EXP)GetProcAddress(hLib, MAKEINTRESOURCE(51));
exp();                                       // CAST128 解密 unk_10007060
uint32_t plaintxt = *(uint32_t *)((uint32_t)exp + 0x2e);
HANDLE hFile = CreateFile("out", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
WriteFile(hFile, (LPCVOID)plaintxt, 0x1A10, 0, 0);  // dump 内嵌 PE
```

Python ctypes 播放 Beep 序列：

```python
from ctypes import *
mydll = cdll.LoadLibrary("./flareon2016challenge.dll")
i = 30
while True:
    i = mydll[i]()
    if i == 51: break
mydll[51]()
mydll[50](0x1B8, 0x1F4); mydll[50](0x1B8, 0x1F4); mydll[50](0x1B8, 0x1F4)
mydll[50](0x15D, 0x15E); mydll[50](0x20B, 0x96);  # ... 共 18 组，频率/时长见原文
```

原文在真机拿到 flag `f0110w_t3h_3xp0rts@flare-on.com`；本库未复跑。

## 变体与关联

- 变体：序号链不一定用"返回值异或"实现，也可能是全局计数器、数组索引、状态机；可用动态方式逐个调用每个导出记录返回值来构建有向图。
- 变体：CAST128 换成别的对称算法；用 SignSrch/FindCrypt/常数扫描识别，再决定静态逆或直接调用原函数。
- 关联：[[ctf-reverse-ctypes-load-pe-call-internal-functions]]（Python ctypes 按偏移调用 PE/DLL 内部函数，与本卡的导出序号调用互补）；[[ctf-reverse-peloader-dump-custom-arx-round-inverse]]（dump 内嵌 PE 后逆向自定义轮函数）；[[ctf-reverse-multistage-pe-vm-modified-sm4]]（多层 PE/VM 逆向）。
- 边界：DLL 依赖缺失/有反调试时需补环境或换模拟执行；导出序号在 32/64 位下 `GetProcAddress` 传序号的写法不同（`MAKEINTRESOURCE`）；调用顺序错会得到乱码且不会报错，需以"能否解出 MZ/PE 头"或"Beep 计数到 18"作为校验。

## 检测与防御

- CTF 分析：先用导出表与函数模式识别"序号链"，静态提取返回值比逐个动态尝试更快；dump 内嵌 PE 后优先确认 MZ/PE 头再继续逆。
- 出题/防御视角：这类题依赖分析者能加载 DLL 并调用导出；可通过 `DllMain` 反调试、导出函数依赖初始化状态、加密密钥分散在多函数副作用中等方式提高难度，但无法阻止有本地执行权限的分析者按序调用。
- 现实软件：DLL 导出序号滥用/被第三方直接调用的风险可用导出白名单、调用方校验与签名验证缓解；本卡仅用于授权 CTF/逆向学习。
