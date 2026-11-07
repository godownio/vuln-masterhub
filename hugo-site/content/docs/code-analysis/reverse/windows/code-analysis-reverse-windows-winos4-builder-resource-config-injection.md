---
id: code-analysis-reverse-windows-winos4-builder-resource-config-injection
title: Winos4 远控平台载荷生成：资源段插件与 codemark/xiugaishiyong 配置追加
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: winos4-builder-resource-config-injection
tags:
- windows
- malware-analysis
- reverse
- winos4
- silverfox
- builder
- resource-section
- shellcode
- dll2shellcode
- config-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:01:33+08:00'
  notes: 已对照 content.md 与全部 52 张图核对：Quick.exe 38,798KB/v4.0、资源 PLUGINS 512-531 与 PLUGINS64、生成界面、codemark/xiugaishiyong 配置追加、DLL2SHELLCODE 以 E9 92 04 00 00 55 8B EC 开头、DLL/EXE 尾部 xiugaishiyong 标记均一致。原文为静态/资源分析，未执行样本或平台，未给出受影响版本区间，未设 versions；未逐项复算资源表全部 MD5。frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-winos4-builder-resource-config-injection/
draft: false
kb_aliases:
- Winos4 控制端
- Winos4 载荷生成
- codemark 配置追加
- xiugaishiyong 标记
- DLL2SHELLCODE
- 上线模块.dll
- Winos4 资源段 PLUGINS
- 银狐系 Winos4 平台
---

## 一句话结论

Winos4 控制端 `Quick.exe`（约 38MB，版本 4.0）把 32/64 位插件、shellcode、UPX 与 IP 数据库放在资源段 `PLUGINS`/`PLUGINS64` 中；生成 EXE/DLL 时，它直接在内置 `上线模块.dll`/`上线模块.exe` 的 `xiugaishiyong` 标记后追加配置；生成 shellcode 时在 `codemark` 标记后追加配置；DLL2SHELLCODE 则是在 DLL 前拼接一段自加载 shellcode。识别这两个标记和资源段即可还原载荷来源与配置注入方式。

## 原理

- **资源段就是插件仓库**：控制端资源树中 `PLUGINS` 下编号 512-531、`PLUGINS64` 下 533-552 存放大量 DLL/EXE/shellcode 资源，包括播放监听、查注册表、差异屏幕、代理映射、高速屏幕、后台屏幕、键盘记录、上线模块、视频查看、文件管理、系统管理、语音监听、远程交谈、远程终端、娱乐屏幕、压力测试、登录模块、驱动插件等 32/64 位版本，另有纯真 IP 数据库与 UPX 加壳工具。生成载荷时无需外部文件，直接从资源段取内置模块。
- **EXE/DLL 的配置追加**：内置 `上线模块.dll` 与 `上线模块.exe` 中都含有 ASCII 标记 `xiugaishiyong`（“修改使用”的拼音）。控制端按该字符串定位追加点，把用户配置（C2 地址、端口、分组、备注等）追加到标记之后；内置样本与生成样本的差异集中在文件尾部，PE 主体不变。
- **shellcode 的配置追加**：内置 shellcode 资源末尾含 `codemark` 标记；生成时把配置追加在 `codemark` 之后。运行 shellcode 时先从配置解析外联地址，连接控制端；按目标系统位数请求 32 位或 64 位载荷；用内置算法解密收到的数据；解密结果中携带 `上线模块.dll` 并自加载。
- **DLL2SHELLCODE**：该选项不是在 DLL 末尾追加，而是在 DLL 文件前拼接一段自加载 shellcode（生成文件以 `E9 92 04 00 00 55 8B EC ...` 一类跳转/序言开头），由这段 shellcode 在内存中加载后面的 DLL。这样同一个 DLL 可以变成可直接注入/执行的 shellcode。
- **为什么标记法可行**：控制端把配置当数据追加到固定标记后，解析端只需搜索标记即可定位配置起点，不依赖 PE 结构或额外节表；这也给分析/取证留下稳定特征——生成样本尾部出现 `xiugaishiyong` 或 `codemark` 及随后的非 PE 数据，基本可判定为 Winos4 平台产物。
- **平台与家族**：控制端界面版本 4.0，插件与 `上线模块` 的注册表/通信行为与银狐系 Winos4 木马一致；本文分析的是该平台生成的最早版本形态，后续变体可能更换标记、加密方式或插件集合。

## 触发条件

- 分析对象是 Winos4 控制端（`Quick.exe`，约 38MB，v4.0）或其生成的 EXE/DLL/shellcode 样本。
- 样本尾部包含 `xiugaishiyong` 或 `codemark` 标记，或资源段存在 `PLUGINS`/`PLUGINS64` 编号资源。
- 具备 PE 资源查看/提取工具（Resource Hacker、PE-bear、7-Zip、Python pefile 等）与十六进制对比工具。
- 生成样本需要配置解析：配置位于标记之后，可能是明文/简单编码，具体字段随平台版本变化。

## 利用步骤

1. **确认控制端**：检查 `Quick.exe` 大小约 38MB、版本 4.0，界面含“客户生成”页与 SHELLCODE/生成DLL/生成EXE 按钮。
2. **提取资源段**：用资源工具查看 `PLUGINS`（32 位，512-531）与 `PLUGINS64`（64 位，533-552），导出插件、`上线模块.bin`/`上线模块.dll`、shellcode、`登录模块.dll` 等；记录资源 ID 与 MD5。
3. **对比内置与生成样本**：分别取内置 `上线模块.dll`/`上线模块.exe` 与生成的 `output_86.dll`/`output_86.exe`，十六进制对比；差异应集中在 `xiugaishiyong` 标记之后。
4. **解析配置**：在生成样本中搜索 `xiugaishiyong`（DLL/EXE）或 `codemark`（shellcode），提取标记之后的字节；按平台字段解析 C2 地址、端口、分组等（不同版本字段顺序可能不同，需动态验证）。
5. **识别 DLL2SHELLCODE**：若生成文件开头是跳转/自加载 shellcode 序言而不是 `MZ`，且在中后部出现 `MZ`/PE 头，则为 DLL2SHELLCODE；提取后部 PE 可还原原 DLL。
6. **运行链还原**：shellcode 连接 C2 → 按位数请求载荷 → 解密 → 加载 `上线模块.dll`；`上线模块` 解析配置 → 检查 `HKCU\Console\IpDate` → 加载 `登录模块.dll`（优先从注册表 `HKCU\Console\0\d33f351a4aeea5e608853d1a56661059`，否则从 C2 下载解密）。

## PoC

无利用 PoC（控制端与样本未公开执行，仅做静态/资源分析）。可用于定位的标记与资源名：

```text
ASCII 标记：xiugaishiyong（上线模块 DLL/EXE 配置追加点）
ASCII 标记：codemark（shellcode 配置追加点）
资源目录：PLUGINS（32 位，512-531）、PLUGINS64（64 位，533-552）
关键资源：519/540 上线模块.bin、520/541 上线模块.dll、531/552 shellcode、529/550 登录模块.dll
```

```python
# 在样本中定位标记并打印其后的配置片段（只读分析）
data = open('output_86.dll', 'rb').read()
for marker in (b'xiugaishiyong', b'codemark'):
    i = data.find(marker)
    if i != -1:
        print(marker, hex(i), data[i+len(marker):i+len(marker)+64].hex())
```

## 变体与关联

- 变体：控制端可能更换资源编号、标记字符串、插件集合或配置编码；DLL2SHELLCODE 的自加载 stub 也可能变化。
- 关联：[[defense-forensics-winos4-plugin-registry-residency-extraction]]（生成样本运行后的插件注册表驻留）、[[defense-forensics-winos4-c2-frame-xor-decrypt]]（通信解密）、[[pentest-c2-silverfox-inno-dlclr-vmprotect-png-zlib-chain]]（银狐另一条加载链）。
- 同家族：[[pentest-c2-silverfox-hellogpt-installer-dropper-chain]]、[[pentest-c2-silverfox-sogou-sideload-inflation-aes-reflective-chain]]。

## 检测与防御

- **文件特征**：生成样本尾部出现 `xiugaishiyong`/`codemark` 及随后的高熵/非 PE 数据；文件大小比内置模块略大；DLL2SHELLCODE 样本以非 `MZ` 的 shellcode 序言开头、中后部含 `MZ`。
- **资源特征**：控制端 `Quick.exe` 资源段含 `PLUGINS`/`PLUGINS64` 编号资源与多个中文插件名；可对控制端样本做 YARA/哈希匹配。
- **网络与行为**：shellcode 先连接配置中的 C2，再按位数请求载荷并解密；`上线模块` 读写 `HKCU\Console\IpDate` 与 `HKCU\Console\0\d33f...`；这些行为可与注册表/流量检测联动。
- **处置**：发现生成样本后提取配置与插件集合，封禁 C2，按注册表/协议卡片清理插件与配置；控制端样本仅用于分析，不在生产环境运行。
