---
id: code-analysis-reverse-windows-cybergate-rat-config-resource-xor-extract
title: 'CyberGate RAT 配置提取：Delphi RCDATA 资源 CG-CG-CG-CG、0xBC 单字节 XOR 与 ####@#### 字段映射'
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: cybergate-rat-config-resource-xor-extract
tags:
- windows
- delphi
- rat
- malware-analysis
- config-extraction
- xor
- resource
- idr
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T20:47:55+08:00'
  notes: '已对照原文与22张图核对：FindResourceA 资源名 CG-CG-CG-CG/type 0xA（图08）、Resource Hacker 394,235字节与 ####@#### 分隔（图09）、XOR 0xBC 汇编循环（图15）、CyberChef XOR bc 解出 192.168.153.130:999（图11）、Go 脚本字段索引与 0x9C 空字段判定（正文+图16输出）、CreateProcessA explorer.exe + VirtualAllocEx + WriteProcessMemory 500B + CreateRemoteThread（图12/13/14）均一致；与 Remcos/Quasar 等既有配置提取卡为不同家族不同算法，dedup 除自匹配外 top 候选 related/new，非重复。原文未标受影响版本（恶意样本分析），affected_versions 留空正确。未验证点：未在本机对样本运行提取脚本（原文仅展示运行结果截图）。frontmatter 无 sources/source_url。'
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-cybergate-rat-config-resource-xor-extract/
draft: false
kb_aliases:
- CyberGate RAT 配置解密
- CG-CG-CG-CG 资源
- CyberGate XOR 0xbc
- CyberGate 配置提取脚本
- Delphi 木马配置提取
- '####@#### 分隔符'
---

## 一句话结论

CyberGate RAT 的 Delphi 木马端把全部配置放在 PE 的 RCDATA 资源 `CG-CG-CG-CG` 中，每个字段单独用单字节 `0xBC` 异或、字段之间用明文 `####@####` 分隔；导出该资源、按分隔符切分并逐字段 XOR，即可在不运行样本的情况下还原 C2 地址/端口、安装选项、注入目标、持久化方式、Keylogger 与 FTP 外传凭据、互斥体等全部配置。

## 原理

- **配置载体**：外层木马调用 `FindResourceA(hModule, "CG-CG-CG-CG", (LPCSTR)0xA)`、`SizeofResource`、`LoadResource`、`LockResource` 取资源数据；资源类型 `0xA` 即 `RT_RCDATA`，名称固定为 `CG-CG-CG-CG`，可直接用 Resource Hacker 定位并导出（示例资源大小约 394,235 字节）。
- **加密方式**：IDA 中可见逐字节循环 `*(_BYTE *)(UniqueString() + v4 - 1) = *(_BYTE *)(v11 + v4 - 1) ^ 0xBC`——只做单字节 XOR，密钥固定 `0xBC`，无 IV、无链式、无密钥派生。CyberChef 选 XOR、key=`bc`、HEX、Standard，即可在资源数据中直接看到首个字段还原为 `192.168.153.130:999`。
- **字段分隔**：资源内字段用明文 ASCII `####@####`（9 字节）分隔，XOR 只作用于各字段内容、不加密分隔符，因此可以先 split 再逐字段解密；空字段解密后为单字节 `0x9C`，脚本以十六进制 `"9c"` 判定为空。
- **字段布局**（按配置生成顺序，索引从 0 起）：0–18 为多个 C2 `domain:port`（示例 `192.168.153.130:999`、`127.0.0.1:81`）；20 ServerID；21 Password；22 Install Flag；25 安装目录；26 安装文件名；27 ActiveX 启动项；28/29 HKLM/HKCU 注册表键；30–34 安装弹窗（开关/图标/按钮/标题/内容）；35–37 Keylogger（开关/退格删除/FTP 上传）；38–44 FTP 地址/目录/用户名/密码/端口/间隔；57 进程注入类型（0 禁用、1 默认浏览器、2 自定义）；58 自定义注入进程；59 持久化；60 隐藏文件；61 修改创建时间；62 Mutex；63 Melt 自删除；67 版本；69 启动策略；70 USB 传播；71 P2P 传播；73 Chrome 密码窃取。
- **外层 stager 架构**：解密配置后按 57/58 选择注入目标；IDA 中可见 `CreateProcessA("explorer.exe"` 或配置进程, `..., CREATE_SUSPENDED`) → `VirtualAllocEx(0x1F4, PAGE_EXECUTE_READWRITE)` → `WriteProcessMemory(500 字节 sub_408A00 shellcode)` → `CreateRemoteThread`。实际功能木马为 UPX 加壳，在内存中运行并回连配置中的 C2。
- **Delphi 分析技巧**：IDR（Interactive Delphi Reconstructor）对 Delphi 库函数（如 `LStrSetLength`、`UniqueString`）的识别率高于 IDA，可先生成 MAP 与 IDC 文件，再辅助 IDA/OllyDbg 定位资源加载与解密循环。
- **版本稳定性**：2010–2012 年的 CyberGate v3.4.2.2 破解版与 2024 年仍在活跃、被伪装成 Dork 工具投递的样本，在核心配置结构与通信模块上基本一致，因此该字段布局可复用于新样本分析。

## 触发条件

- 取得 CyberGate RAT 木马端样本（Delphi 编译的 PE，常见为外层 stager）；静态分析即可，无需运行。
- 样本资源段中存在名为 `CG-CG-CG-CG` 的 RCDATA 资源（Resource Hacker、pefile 或 7z 可查看）。
- 生成器未修改资源名、分隔符或 XOR key（同家族默认配置如此）。

## 利用步骤

1. 用 Resource Hacker 打开样本，展开 RCDATA，找到 `CG-CG-CG-CG`，导出为二进制文件。
2. 或脚本读取资源：用 pefile 遍历 `RT_RCDATA`，取名称为 `CG-CG-CG-CG` 的字节。
3. 按 `####@####` 切分，得到字段数组。
4. 每个字段逐字节 XOR `0xBC`；结果为单字节 `0x9C` 视为空字段。
5. 按索引映射输出配置（C2、密码、安装目录/文件名、注入类型与目标、持久化、Keylogger、FTP、Mutex 等）；存在多个 C2 时逐个记录。
6. 用 IDR 生成 MAP/IDC，在 IDA 中核对 `FindResource`/`LoadResource`、XOR 循环与进程注入分支，验证字段语义。
7. 将配置中的 C2/FTP 地址与 Mutex 作为 IOC，用于流量与主机排查。

## PoC

最小提取脚本（Python，等价于原文 Go 版逻辑）：

```python
data = open("CG-CG-CG-CG", "rb").read()          # Resource Hacker 导出的 RCDATA
fields = data.split(b"####@####")
dec = [bytes(b ^ 0xBC for b in f) for f in fields]

for i, d in enumerate(dec[:19]):                 # 0..18: domain:port
    if d != b"\x9c":
        print("domain_port:", d.decode(errors="replace"))
for idx, name in [(20, "ServerID"), (21, "Password"), (25, "InstallDir"),
                  (26, "FileName"), (62, "Mutex"), (57, "InjectType")]:
    print(name + ":", dec[idx].decode(errors="replace"))
```

CyberChef 也可直接验证：Input 选 Raw Bytes，Recipe 选 XOR（key `bc`，HEX，Standard），即可肉眼看到 `192.168.153.130:999` 等字段。

## 变体与关联

- **版本差异**：字段索引随 CyberGate 版本略有变化（如进程注入 57/58、FTP 用户名 41/端口 43、Mutex 62）；以 IDA 中 `####@####` 引用与实测结果为准，不要硬编码单一版本。
- **改版变种**：资源名、分隔符或 XOR key 可被重新生成器修改；遇到变种先定位 `FindResource`/`LoadResource` 调用与 XOR 常量，再重建字段表。
- **同模式家族**：Quasar、Remcos、Xeno 等 RAT 的配置提取都遵循“定位配置载体 → 解密 → 字段映射”的同一分析模式。
- 通信侧解密见 [[defense-forensics-cybergate-rat-traffic-rc4-zlib-custom-base64]]；Delphi 调试技巧见 [[code-analysis-dynamic-debugging-delphi-dialog-getdlgitem-windowtext-locate]]。
- 边界：CyberGate 为破解版商业 RAT，配置提取仅限授权取证与恶意样本研究。

## 检测与防御

- **样本检测**：PE 资源段出现 `CG-CG-CG-CG` RCDATA；含 `FindResourceA` 与 `0xBC` XOR 循环；解密配置中出现多个 `domain:port`、FTP 凭据、Mutex。
- **主机行为**：配置文件决定的安装目录、注册表 Run/Active Setup 键、Melt/隐藏文件行为；`CreateProcessA(CREATE_SUSPENDED)` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` 注入链；内存中的 UPX 解压镜像。
- **防御**：拦截伪装成工具/文档的样本；限制不可信程序执行；监控异常远程线程与 C2 外联；用配置中的 IOC 做全网排查。
