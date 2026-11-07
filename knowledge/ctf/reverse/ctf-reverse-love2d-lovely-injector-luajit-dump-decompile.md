---
id: ctf-reverse-love2d-lovely-injector-luajit-dump-decompile
title: Love2D 游戏 lovely-injector 注入逆向：改 dump_all 标志导出 LuaJIT 字节码并反编译
type: scenario
domain: ctf
path: ctf/reverse
technique: love2d-lovely-injector-luajit-dump-decompile
aliases:
- SpeedMino-Warlock
- lovely-injector
- Love2D 逆向
- LÖVE LuaJIT
- dump_all
- luajit_decompile
- version.dll 劫持
tags:
- ctf
- reverse
- love2d
- luajit
- lovely-injector
- dll-hijack
- bytecode
- decompile
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:17:10+08:00'
  notes: 已对照原文与图14-21核对；version.dll lovely-injector、dump_all_bool改写、LuaJIT字节码反编译与素数/R4解密链均一致；domain修正为ctf；PoC未复跑
---

## 一句话结论

Love2D（LÖVE）游戏把 Lua 代码打包在 exe/zip 中；本题的 `version.dll` 是改过的 lovely-injector，用于在运行时向 LÖVE 注入 Lua 补丁。原版 `main.lua` 只做假 flag 校验，真正的校验在注入的 LuaJIT 字节码里。lovely-injector 的 `Lovely::init(..., dump_all)` 带一个 `dump_all` 布尔参数，原程序只在命令行有 `--dump-all` 时才置 1；调试时在 DLL 里把该布尔改成 1，即可让注入器输出即将注入的 LuaJIT 字节码，再用 `luajit_decompile` 反编译得到真实校验逻辑。

## 原理

- **Love2D 打包结构**：LÖVE 游戏通常把 `main.lua` 等资源打进 exe（zip 结构），右键用压缩包打开或 `unzip` 可得到 Lua 源码/字节码；但本题的 `main.lua` 解出来是假 flag。
- **lovely-injector**：一个通过 `version.dll` 劫持注入 LÖVE 的项目，能在运行时打 Lua 补丁；其 `crates/lovely-core/src/lib.rs` 的 `Lovely::init(loadbuffer, lualib, dump_all)` 中 `dump_all: bool` 控制是否把注入的字节码 dump 出来。原版会读命令行 `--dump-all` 并把 `dump_all_bool` 置 1；本题作者修改后去掉了输出/日志。
- **定位真实校验**：用 Cheat Engine 搜索 `result_table` 的引用，发现有两处；其中一处在未见过的 Lua 代码里，从 `NEURO` 字节加载了 LuaJIT 函数并调用 `Check(result_table)`，输出 `PERFECT!`——这就是真实校验函数。
- **dump 注入字节码**：在 `version.dll` 的 `DllMain`/`lovely_init` 调用处下断，找到给 `dump_all_bool` 赋 0 的指令，单步/改寄存器（如把 `rsi`/布尔参数改为 1），让 `dump_all` 生效；运行后注入器会输出 LuaJIT 字节码（可能弹窗/日志/内存）。
- **反编译**：把字节码保存为文件，用 `luajit_decompile`（weaweawe01/luajit_decompile）反编译成 Lua；本题得到：
  - `slot1(slot0, slot1)`：从 `0 + slot0*384 + slot1` 开始找满足“是素数且 `(n-1)%5 != 0`”的数；
  - 主函数：对每个输入字节，检查 `(64 + byte)^5 % (p_i * p_{i+1}) == Enc[i]`，并用 `slot1` 生成下一对素数；
  - 解出字节后还要过一层 RC4（`calcData`）才是 flag。
- **为什么可行**：lovely-injector 的补丁字节码最终要交给 LuaJIT 执行，`dump_all` 是现成的调试开关；修改布尔/绕过命令行检查即可拿到与运行时一致的字节码，避免从混淆的 Lua 源码硬猜。

## 触发条件

- 目标为 Love2D/LÖVE 游戏，使用 lovely-injector（`version.dll` 或类似劫持 DLL）注入 Lua 补丁；DLL 中可找到 `lovely-injector`/`dump_all` 字符串。
- 原版 `main.lua` 是假逻辑，真实校验在注入的 LuaJIT 字节码中；需要拿到该字节码。
- 能调试 DLL/游戏进程（x64dbg/IDA），定位 `Lovely::init` 的参数与 `dump_all_bool` 赋值；能修改寄存器/内存或打补丁。
- 有 LuaJIT 字节码反编译工具（luajit_decompile）与对应版本的 LuaJIT 字节码格式。
- 字节码未被额外加密/压缩；若被加密，需先还原解密逻辑。

## 利用步骤

1. 确认游戏框架：解包 exe/zip，看到 `main.lua`、`conf.lua`、`lovely` 相关文件；`version.dll` 中出现 `lovely-injector` 字符串。
2. 阅读 lovely-injector 源码，确认 `Lovely::init` 的 `dump_all` 参数与 `dump_all_bool` 全局；原版在 `--dump-all` 时置 1。
3. 在 IDA 中看 `DllMain`/`lovely_init` 调用，找到比较 `--dump-all` 与给 `dump_all_bool` 赋值的分支；下断点。
4. 运行游戏，断在赋值处，把布尔参数/寄存器改为 1（或 patch 掉判断），继续运行；注入器应输出/暴露 LuaJIT 字节码。
5. 保存字节码，用 `luajit_decompile` 反编译；阅读真实校验逻辑（本题为素数/五次方取模 + RC4）。
6. 按反编译逻辑写解密脚本：先按模素数方程解字节（中国剩余定理/模逆），再过 RC4 的 `calcData`（密钥 `Speedmino Created By MrZ and modified by zxc`），得到 flag。
7. 同系列 Misc 题若只给密文，可直接按 `calcData`：先用 55 个空格初始化 RC4 状态，再对 `youwillget` 调用 2600 次，输出 flag。

## PoC

```python
import math

Enc = [36506,88774,438822,666001,109051,2124674,2767204,2610244,
       3272321,8662979,5131975,1034228,6712315,12760199,20058866,
       6854477,6126314,3871829,13815442,15034520,38884726,10742135,
       26199509,45230422,46725610,7627278,21052590,68432885,48719842,
       94974872,55215219,113201828,86070272,153897959,136736481,
       88243015,108020790,71691707,157143593,22399026,41588356,
       220309217,86844145,129645965,240111657,257783827,92900284,
       52969902,27539801,275411785,364406385,253200306,389008554,
       359199685,337450915]

def is_prime(n):
    if n < 2: return False
    if n in (2,3): return True
    if n % 2 == 0 or n % 3 == 0: return False
    for i in range(5, int(math.isqrt(n))+1, 6):
        if n % i == 0 or n % (i+2) == 0: return False
    return True

def next_prime(index, byte_val):
    n = index*384 + byte_val
    while not (is_prime(n) and (n-1) % 5 != 0):
        n += 1
    return n

def dec1():
    primes = [359, 383]
    out = []
    for i, c in enumerate(Enc):
        p, q = primes[i], primes[i+1]
        xp = pow(c, pow(5, -1, p-1), p)
        xq = pow(c, pow(5, -1, q-1), q)
        h = ((xq - xp) * pow(p, -1, q)) % q
        b = xp + p*h - 64
        out.append(b)
        primes.append(next_prime(i+1, b))
    return out

def ksa(key):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s

def dec2(cipher):
    key = b"Speedmino Created By MrZ and modified by zxc"
    s = ksa(key); i = j = 0; out = []
    for d in cipher:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append((d - s[(s[i] + s[j]) % 256]) % 256)
    return bytes(out)

print(dec2(dec1()).decode())
# NepCTF{Y0u_c4n_M0dDing_LOVE2D_g@mE_By_l0vely_iNjector!}
```

```bash
# LuaJIT 字节码反编译
python3 luajit_decompile.py dumped.luajit > out.lua
```

原文截图显示 `Lovely 0.8.0` 崩溃转储中包含 `result_table` 检查的字节码、CE 搜索到两处 `result_table`、以及 `--dump-all` 分支/DLL 中 `dump_all_bool` 赋值；本卡未复跑。

## 变体与关联

- **dump 方式变体**：改 `dump_all_bool`、patch 命令行判断、hook `Lovely::init` 参数、或直接读内存中的字节码；不同 lovely-injector 版本参数名/偏移不同。
- **字节码版本**：LuaJIT 字节码格式与 LuaJIT 版本相关，反编译工具要与目标版本匹配；否则会失败/乱码。
- **同系列 Misc**：SpeedMino 的 `calcData` 是 RC4 变体，先用 55 个空格初始化，再对密文迭代 2600 次；可直接用上面的 `calcData` 逻辑解出 `NepCTF{You_ARE_SpeedMino_GRAND-MASTER_ROUNDS!_TGLKZ}`。
- **关联**：`[[ctf-reverse-android-native-luajit-xor-keystream-cancel]]`（LuaJIT 字节码/keystream 逆向）、`[[ctf-reverse-godot-pck-gdc-decompile-patch-repack]]`（其他游戏引擎解包/反编译）、`[[pentest-c2-dll-sideload-export-forwarding-host-whitelist]]`（DLL 劫持/注入基础）。
- **边界**：若注入字节码被加密/签名，dump 出来仍是密文；需要先还原解密；若游戏有反调试/完整性校验，需先绕过。

## 检测与防御

- **对逆向方**：先确认框架（LÖVE/lovely-injector）与注入点；用现成 `dump_all` 开关降低逆向成本；反编译后按数学/密码层逐步还原；注意 LuaJIT 版本与字节码格式。
- **对防守方（游戏保护）**：不要把核心校验放在客户端 Lua/字节码中；服务端校验/加密通信；对 DLL 劫持/注入做完整性校验（签名、加载路径、KnownDLLs）；对 `version.dll` 等易劫持 DLL 使用安全加载。
- **检测**：游戏目录出现非官方 `version.dll`/`lovely` 文件、进程加载异常 DLL、`--dump-all` 参数、LuaJIT 字节码被写入磁盘；EDR 监控 DLL 侧加载与进程注入。
