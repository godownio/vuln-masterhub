---
id: ctf-misc-rpgmaker-rvdata2-selfextract-cab
title: RPG Maker VX Ace .rvdata2 取证：自解压 CAB 提取 + Ruby Marshal 字符串定位 flag
type: scenario
domain: ctf
path: ctf/misc
technique: rpgmaker-rvdata2-marshal-forensics
tags:
- ctf
- misc
- forensics
- rpgmaker
- rvdata2
- ruby
- marshal
- cab
- self-extracting
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:48:43+08:00'
  notes: 已对照原文与images 17-23核对：MSCF定位CAB(0x10eb4)、RPG Maker VX Ace目录、Weapons.rvdata2 strings前半flag、游戏退出脚本报错后半flag、Ruby Marshal读取均与原文一致。未验证点：未复跑提取/拼接。
url: /docs/ctf/misc/ctf-misc-rpgmaker-rvdata2-selfextract-cab/
draft: false
kb_aliases:
- rvdata2 解析
- RPG Maker 取证
- Ruby Marshal 数据提取
- 自解压 CAB 提取
- MSCF 附加数据
---

## 一句话结论

CTF 杂项给出“游戏 exe”时，可先按文件尾部的 `MSCF` 头切出内嵌 CAB 并解包，识别出 RPG Maker VX Ace 工程；其 `Data/*.rvdata2` 是 Ruby `Marshal` 序列化数据，用 `strings` 或 `Marshal.load` 遍历对象/实例变量即可取出藏在武器名等字段中的 flag 片段，与游戏运行时泄露的另一段拼接。

## 原理

- 自解压/捆绑程序常把 CAB 追加在 PE 文件末尾；`MSCF` 是 CAB 的签名，直接在字节流中搜索 `MSCF` 并从该偏移截断即可得到 `payload.cab`，无需运行 exe。
- RPG Maker VX Ace 工程目录包含 `Game.exe`、`Game.rvproj2`、`Data/*.rvdata2`、`Audio/Graphics/System` 等；`Data` 下的 `MapXXX.rvdata2`、`Scripts.rvdata2`、`Weapons.rvdata2`、`Items.rvdata2` 等是游戏资源。
- `.rvdata2` 是 Ruby `Marshal` 序列化后的二进制对象图；字符串（武器名、描述、对话）以明文或长度前缀形式存在，`strings` 可直接捞出，`Marshal.load` 后可进一步枚举对象类与实例变量。
- 本题把 flag 拆成两段：一段藏在 `Weapons.rvdata2` 的字符串中（`strings` 可见 UUID 前半），另一段在游戏运行/退出时的脚本报错里出现（报错信息包含剩余字符），拼接即得完整 flag。
- 之所以成立：`Marshal` 只做序列化不做加密；游戏资源为了运行时读取必须保留明文/可反序列化结构。

## 触发条件

- 给定 Windows 可执行文件或游戏目录，文件末尾含 `MSCF` 或目录含 `Data/*.rvdata2`。
- 资源未使用 RGSSAD/RGSS2A 等加密归档（或已解包）。
- 攻击者/分析者可运行 `strings`、Ruby、7z 等工具。

## 利用步骤

1. 读取 exe 字节流，搜索 `b"MSCF"`，从该偏移写出 `payload.cab`。
2. 用 7z/`expand.exe` 解包 CAB，查看目录结构，确认 `Game.rvproj2`、`Data/*.rvdata2`，识别为 RPG Maker VX Ace。
3. 对 `Data/Weapons.rvdata2`、`Items.rvdata2`、`MapXXX.rvdata2`、`Scripts.rvdata2` 执行 `strings`，搜索 `flag`、`DASCTF{`、UUID 片段等。
4. 或用 Ruby 读取 Marshal 对象，枚举实例变量与字符串字段，定位隐藏片段。
5. 运行游戏到退出/触发脚本错误，记录报错信息中的另一段 flag，按题目提示拼接。

## PoC

```python
# 1) 从自解压 exe 提取 CAB
data = open("gamego.exe", "rb").read()
pos = data.find(b"MSCF")
assert pos != -1
open("payload.cab", "wb").write(data[pos:])
print(hex(pos))
```

```bash
# 2) 解包并检索字符串
7z x payload.cab -o game
strings game/Data/Weapons.rvdata2 | grep -E 'flag|DASCTF|[0-9a-f]{8}-'
```

```ruby
# 3) 用 Ruby Marshal 查看对象结构
data = Marshal.load(File.binread('Data/Weapons.rvdata2'))
obj = data.compact.first
p obj.class
p obj.instance_variables
```

## 变体与关联

- 变体：flag 藏在 `MapXXX.rvdata2` 的地图事件、`Scripts.rvdata2` 的自定义脚本、`Items/Actors` 的名称/描述字段。
- 变体：资源被 RGSSAD/RGSS2A 加密时，需先按对应格式解密归档再解析 `rvdata2`（本题未涉及）。
- 变体：自解压包不是 CAB，而是 7z/zip/NSIS 附加数据；同样可用签名字节定位后解包。
- 关联：Ruby Marshal 反序列化、PE 附加数据/覆盖层取证、游戏资源逆向。

## 检测与防御

- 取证侧：先做文件签名扫描（`MSCF`、`PK\x03\x04`、`7z\xBC\xAF`）定位附加数据；不要直接运行未知 exe。
- 取证侧：对 `.rvdata2` 同时使用 `strings` 和 `Marshal.load`，前者快速命中明文，后者还原结构与隐藏字段。
- 防御侧（出题/游戏发布）：敏感数据不应只依赖序列化/资源打包隐藏；需要加密与完整性校验时使用受支持的归档加密，并避免把秘密放入客户端资源。
- 检测：终端/沙箱对释放 CAB、调用 `expand.exe`、读取游戏资源目录的行为可告警；CTF 场景下属于预期分析流程。
