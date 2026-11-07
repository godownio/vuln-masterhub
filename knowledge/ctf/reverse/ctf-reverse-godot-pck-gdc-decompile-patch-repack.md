---
id: ctf-reverse-godot-pck-gdc-decompile-patch-repack
title: Godot 游戏逆向：pck/gdc 解包反编译、12 位十进制编码还原与补丁重打包
type: scenario
domain: ctf
path: ctf/reverse
technique: godot-pck-gdc-decompile-patch-repack
aliases:
- go^go=?
- Godot pck 逆向
- gdre_tools 解包
- gdc 反编译
- Godot 补丁重打包
tags:
- reverse
- godot
- pck
- gdc
- gdscript
- gdre-tools
- game
- repack
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:02:38+08:00'
  notes: 已通读全文并核对图01-03：GD1.exe/GD1.console.exe/GD1.pck 的 Godot 发布结构、gdre_tools --recover 解包反编译 main.gdc、main.gd 中 12 字符分组（3×4位二进制→三个 0-15 nibble→百/十/个位加权→异或33→String.chr）、score==177906 触发、修改 main.gd 后 --compile --bytecode=4.5.0 与 --pck-patch 替换 res://main.gdc、图03 补丁包显示 sdpcs ec{d235abf6-f773-43ba-a110-13d87da3e600}（字体渲染有间隙）均一致。已用卡片 PoC 离线复算得到 sdpcsec{d235abf6-f773-43ba-a110-13d87da3e600}，与补丁包输出对应。未在本机运行补丁包；CTF 题无组件版本。
---

## 一句话结论

拿到 `GD1.exe + GD1.console.exe + GD1.pck` 可判定为 Godot 导出游戏；用 gdre_tools 的 `--recover` 解包并反编译 `main.gdc` 得到 GDScript 源码，按其中的 12 字符分组编码（4 位二进制→十进制→百/十/个位加权→异或 33）可离线算出 flag；也可以修改 `main.gd` 降低触发条件，再用 `--compile` 编译回 `.gdc`、`--pck-patch` 替换包内脚本，生成可运行补丁包。

## 原理

- **Godot 发布结构**：Windows 导出目录通常包含 `game.exe`、`game.console.exe`（控制台版）与 `game.pck`（资源包）；`.pck` 内含场景、贴图、音频、配置和脚本。
- **gd/gdc/pck 关系**：`.gd` 是 GDScript 源码，`.gdc` 是编译后的字节码（运行时实际加载），`.pck` 是资源总包；只改 `.gd` 塞回包里无效，必须编译成 `.gdc` 再替换包内 `res://main.gdc`。
- **gdre_tools 恢复**：`gdre_tools.exe --headless --recover=GD1.pck --output=gdre_recover` 解包并尽量把 `.gdc` 还原为 `.gd`；重点看 `main.gd`。
- **编码逻辑**：本题 `main.gd` 中 `var a = "000010..."`、`var xor_key = 33`；当 `score == 177906` 时，把 `a` 每 12 个字符分组，每组再分 3 段 4 位二进制，`bin_to_int` 后按 `百位*100 + 十位*10 + 个位` 合成十进制数，再与 33 异或，`String.chr` 转字符拼接。
- **为什么这样编码**：12 位二进制恰好可拆成三个 0–15 的 nibble，作者把每个 nibble 当十进制位（0–9 有效）拼成 0–999 的数值，再异或 33 映射到可打印字符；这不是标准编码，必须按源码逻辑复现。
- **补丁思路**：把 `score == 177906` 改成 `score == 0`（或直接调用 `$HUD.show_message(result)`），编译回 `.gdc` 并 patch 进 `.pck`，运行补丁包即可让游戏自己吐出 flag，无需手工解码。

## 触发条件

- 目标为 Godot 导出的游戏，含 `.pck` 与 `.gdc`/`.gd` 脚本。
- gdre_tools（或 GDRE Tools）能识别对应 Godot 版本并反编译/编译字节码（本题 4.5.x）。
- 关键逻辑（flag 解码/校验）在 GDScript 中，未被强混淆/加密。
- 允许修改并重新打包 `.pck`（CTF 本地运行场景）。

## 利用步骤

1. 识别 Godot：目录中出现 `*.exe` + `*.console.exe` + `*.pck`；用 `file`/Exeinfo 确认。
2. 解包与反编译：`gdre_tools.exe --headless --recover=GD1.pck --output=gdre_recover`，查看 `main.gd` 等脚本。
3. 定位 flag 逻辑：搜索 `flag`、`xor`、`score ==`、`show_message`、长二进制/十六进制字符串。
4. 离线复现：按源码把长字符串分组、转数值、异或、转字符，得到明文。
5. 或走补丁路线：修改 `main.gd` 的触发条件/直接输出，保存。
6. 编译回字节码：`gdre_tools.exe --headless --compile=main.gd --bytecode=4.5.0 --output=repack_build`。
7. 替换包内脚本：`gdre_tools.exe --headless --pck-patch=GD1.pck --patch-file=repack_build\main.gdc=res://main.gdc --output=GD1_patched.pck`。
8. 用原 exe 加载 `GD1_patched.pck` 运行，游戏在低条件下直接显示 flag。

## PoC

离线解码：

```python
a = "000010000010000001101001000010000001000001100110000010000010000001101000000001100110000010010000000001101001000000011001000000011000000000100000000001100100000001100111000001110001000000100011000000010010000001110001000000100010000000100010000000011000000000010010000000100001000000011000000001100111000001100100000000010010000001100100000000010110000000010110000000010111000000010010000000010110000000011000000001101001000000100101000000100010000001101001000001100100000000011000000001101000000000100011000000010111000000010111000010010010"

result = ""
for i in range(0, len(a), 12):
    b, c, d = a[i:i+4], a[i+4:i+8], a[i+8:i+12]
    e = int(b, 2) * 100 + int(c, 2) * 10 + int(d, 2)
    result += chr(e ^ 33)
print(result)
```

补丁重打包：

```bash
gdre_tools.exe --headless --compile=gdre_recover/main.gd --bytecode=4.5.0 --output=repack_build
gdre_tools.exe --headless --pck-patch=GD1.pck --patch-file=repack_build/main.gdc=res://main.gdc --output=GD1_patched.pck
```

原文通过补丁包运行后，游戏直接显示 `sdpcs ec{d235abf6-f773-43ba-a110-13d87da3e600}`（渲染空格为字体/换行效果）；未在本机复跑。

## 变体与关联

- **引擎变体**：Godot 3.x/4.x 的 pck 格式、字节码版本不同；`--bytecode` 必须与目标版本对齐，否则编译出的 `.gdc` 不兼容。
- **脚本变体**：关键逻辑可能在 `main.gd`、自动加载脚本、`res://` 其他 `.gdc`、或加密 pck（需要密钥）；先枚举所有脚本。
- **补丁变体**：改条件、改返回值、直接 `print` flag、跳过校验；也可用 Godot 编辑器打开恢复项目后重新导出。
- **关联**：[[ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation]]（游戏资源包逆向）、[[ctf-reverse-z3-constraint-equation-solve]]（编码/约束还原）；本卡强调 Godot pck/gdc 的解包、反编译与重打包。

## 检测与防御

- 游戏发行方：对 pck 加密/签名，关键校验放服务端，避免把 flag/密钥直接编码进客户端脚本。
- 逆向方：先确认引擎与版本，再选对应 gdre_tools/Godot 版本；编译字节码必须匹配版本，patch 路径必须是 `res://` 逻辑路径。
- 检测：目录中的 `.pck`/`.console.exe`、脚本中出现长二进制串 + `bin_to_int`/`String.chr`、`score ==` 常量、补丁包的修改时间/哈希异常。
