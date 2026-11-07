---
id: code-analysis-reverse-unity-il2cpp-ce-trigger-embedded-pe
title: Unity IL2CPP CTF 链：CE 改内存触发内嵌资源释放 + 十六进制 PE 还原与凯撒/XOR 逆推
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: unity-il2cpp-ce-trigger-embedded-pe
tags:
- reverse
- unity
- il2cpp
- cheat-engine
- game-hacking
- ctf
- pe
- caesar
- xor
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T10:07:26+08:00'
  notes: V165 指出“凯撒 20 轮”表述与 sub_14000144B(Str,20) 单次偏移不符；已改为凯撒 +20
url: /docs/code-analysis/reverse/code-analysis-reverse-unity-il2cpp-ce-trigger-embedded-pe/
draft: false
kb_aliases:
- IL2CPP CE 改金币
- Cheat Engine 触发 SYC
- Data.txt hex PE
- 内嵌资源释放
- 凯撒 +20 + XOR GEEK
- 玩就行了
- 2024极客大挑战
---

## 一句话结论

当 IL2CPP 游戏的 C# 逻辑只有在某个内存数值（如金币）达到阈值时才调用资源释放方法时，可以用 Cheat Engine 搜索并修改该数值满足条件，让游戏把内嵌的十六进制 PE 写到磁盘；再把 hex 还原为 exe，用 IDA 分析其“凯撒 +20 → XOR `GEEK` → 十六进制比较”逻辑并逆推出 flag。

## 原理

- **条件触发的资源释放**：DummyDll 中可见 `hOOK.Update()` 比较 `this.money >= int.Parse(this.targetMonty.text)`，满足后调用 `GAME.SYC()`；`SYC()` 从资源加载十六进制字符串并 `File.WriteAllText` 到 `Application.dataPath` 的父目录下的 `Data.txt`。因此不必逆向全部游戏逻辑，只要让内存中的 money 达到阈值即可触发。
- **CE 动态定位**：IL2CPP 虽然把代码编译成机器码，但金币这类普通字段仍是内存中的整数；用精确值搜索 + 多次“Next Scan”（改变金币后搜新值）可收敛到地址，直接改写即可。若字段被加密/指针间接，可用 “Find out what writes/accesses this address” 找到读写指令，再到 IDA 中定位函数。
- **十六进制 PE 还原**：`Data.txt` 以 `4D5A` 开头，即 PE 的 `MZ` 魔数；整文件是无分隔的十六进制字符串，`bytes.fromhex` 即可还原为可执行文件。
- **静态逆推**：IDA 分析还原出的 PE，可见主函数读取输入 → `sub_14000144B` 凯撒 +20（字母循环移位）→ `sub_140001596` 与 `"GEEK"` 循环 XOR → `sub_14000161C` 格式化为 `%02X` 十六进制 → 与硬编码密文比较。解密顺序相反：hex 解码 → XOR `GEEK` → 凯撒 -20。
- **为什么有效**：动态修改绕过了“必须正常游玩攒够金币”的前置条件，把题目从“玩到 666 金币”降维成“改一个整数”；释放出的 PE 才是真正的密码学检查程序，动态触发 + 静态分析组合大幅缩短路径。

## 触发条件

- 目标为 Unity IL2CPP 游戏，且关键逻辑由客户端内存数值门控（金币、等级、分数、物品数等）。
- 游戏未使用强反作弊/反调试，CE 可附加并读写进程内存；字段不是强加密类型（若为 `CryptInt` 等需先定位 Set/Get）。
- 释放的资源可读（文件写到游戏目录/用户可读路径），且未被加密/压缩。
- 有 Il2CppDumper 生成的 DummyDll/dump.cs/script.json 辅助定位类与方法；有 IDA/Ghidra 分析释放的 PE。

## 利用步骤

1. 按 [[code-analysis-reverse-unity-il2cpp-dumper-symbol-recovery]] 用 Il2CppDumper 恢复符号，dnSpy 打开 `DummyDll/Assembly-CSharp.dll`，找到条件判断与 `SYC`/资源释放方法。
2. 启动游戏，记下界面显示的金币值；CE 附加游戏进程，输入该值做 First Scan。
3. 在游戏中改变金币（购买/获得），用新值做 Next Scan；重复直到候选地址只剩一个或几个。
4. 双击地址加入列表，把值改为远大于阈值的数（如 1000000），回到游戏触发条件，等待 `Data.txt` 生成。
5. 确认 `Data.txt` 开头为 `4D5A`；用 Python `bytes.fromhex` 还原为 `final.exe`。
6. IDA 打开 `final.exe`，定位主函数与三个加密函数，提取密文、key（`GEEK`）和凯撒偏移（20）。
7. 写解密脚本：hex 解码 → 逐字节 XOR key → 凯撒 -20，得到 flag。
8. 若不想改数值，也可在 CE 中用 `script.json` 查到 `SYC` 地址，通过 “Call function” 直接调用（需正确设置 `this` 指针，否则可能崩溃）。

## PoC

```text
CE 操作：
1) 附加游戏进程
2) 当前金币 13 → First Scan 13
3) 游戏内使金币变化 → Next Scan 新值
4) 重复至剩少量地址 → 双击加入地址列表
5) 将值改为 1000000 → 回游戏，金币达到目标 666
6) 游戏目录生成 Data.txt（内容为十六进制 PE）
```

```python
import os

def read_hex(path):
    with open(path, "r") as f:
        return f.read().strip()

def hex_to_bin(hex_data, out):
    with open(out, "wb") as f:
        f.write(bytes.fromhex(hex_data))

hex_to_bin(read_hex("Data.txt"), "final.exe")
```

```python
def xor_decrypt(ciphertext: bytes, key: str) -> bytes:
    kb = key.encode()
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(ciphertext))

def caesar_decrypt(data: bytes, shift: int) -> str:
    out = []
    for b in data:
        c = chr(b)
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
        elif '0' <= c <= '9':          # 原加密函数也处理数字（%10）
            out.append(chr((ord(c) - ord('0') - shift) % 10 + ord('0')))
        else:
            out.append(c)
    return ''.join(out)

hex_enc = "0A161230300C2D0A2B303D2428233005242C2D26182206233E097F133A"
enc = bytes.fromhex(hex_enc)
intermediate = xor_decrypt(enc, "GEEK")     # 凯撒 +20 后的中间文本
print(caesar_decrypt(intermediate, 20))
```

## 变体与关联

- 变体：门控字段可能是等级、分数、物品数量、天数等；同样用精确值/变化值搜索。
- 变体：字段为加密类型（如 `CryptInt`）时，需先定位其 `Set/Get` 或结构体偏移，再用 Hook/调用方式写入，见 [[mobile-android-unity-il2cpp-frida-gadget-infinite-revival]]。
- 变体：释放的资源可能是压缩包、加密数据或另一段 IL2CPP 代码；先识别 magic（MZ、PK、ELF 等）再决定后续分析。
- 变体：释放路径可能不可见或需要管理员权限，可在 CE 中 hook `File.WriteAllText` 或直接调用资源加载方法取回内存数据。
- 关联：[[code-analysis-reverse-unity-il2cpp-dumper-symbol-recovery]]（前置符号恢复）；[[code-analysis-reverse-obfuscation-xor-charcode-js-kit-static-regex-deobfuscation]]（XOR 类解密的通用思路）。
- 边界：强反作弊/内核保护、服务端校验、数值加密且不可 hook 时，动态修改可能失败；释放的 PE 若被 VM/混淆保护，静态逆推难度上升。

## 检测与防御

- 防御方（游戏）：关键资源不要在客户端由可改内存的数值门控；服务端校验进度/金币；对内存修改做完整性/反作弊检测；释放的资源加密并做签名校验。
- 分析方：只在授权/CTF 环境使用 CE；修改前备份存档与进程快照；记录地址、指令与释放文件哈希。
- 检测：进程内存被外部工具读写、`Data.txt`/临时 PE 落盘、游戏目录新增可执行文件；对 `File.WriteAllText` 与资源加载调用做监控。
