---
id: code-analysis-reverse-windows-dridex-c2-table-signature-extraction
title: Dridex C2 静态提取：RC4 配置串定位 + IP/端口表特征码与 VA→RVA 解析
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dridex-c2-config-extraction
aliases:
- Dridex C2 提取
- Dridex 配置解密
- IP 端口表解析
- 0x1BB 443
- pefile C2 提取
- 银行木马 IOC 提取
tags:
- windows
- malware-analysis
- dridex
- c2
- config-extraction
- rc4
- pefile
- ioc
- static-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V101
  verified_at: '2026-11-05T22:27:08+08:00'
  notes: 已对照原文与图60/61核对：表基址+0xB处数量=3、+0xC起每条6字节(IPv4+小端端口)、首条67 2A 38 0F BB 01=103.42.56.15:443、BB imm32特征码及pefile VA→RVA换算均一致；未对样本执行PoC。
---

## 一句话结论

Dridex 的 C2 列表以“1 字节数量 + N 组（4 字节 IPv4 + 2 字节小端端口）”的明文表存在数据区，代码用 `mov ebx, imm32` 指向表基址并在 `+0xB` 读取数量；先按同族 RC4 布局解密配置串定位网络模块，再用该指令特征码找到表地址，配合 pefile 把 VA 换算为文件偏移，即可一次性静态提取全部 C2。

## 原理

- **配置加密布局**：与载荷块相同，配置串也是“前 `0x30` 字节倒序 key + RC4 密文”；对 `mw_rc4_decrypt` 的交叉引用逐个解密，可得到 `SELECT * FROM Win32_Fan`、`*.dll`、`*.exe`、`ntdll.dll`、`GET`、`POST`、`Progman`、`AdvApi32~PsApi~shlwapi~shell32~WinInet`、计划任务命令行等字符串。网络相关字符串（HTTP 方法、WinInet 模块名、计划任务）附近通常就是 C2 解析代码。
- **C2 表结构**：表基址 `+0xB` 处 1 字节为条目数量；从 `+0xC` 开始每条 6 字节：4 字节 IPv4（按字节顺序直接点分十进制）+ 2 字节端口（小端）。示例表数量为 3，首条 `67 2A 38 0F BB 01` 解析为 `103.42.56.15:443`，其中 `0x01BB = 443` 是识别该表的强提示；后续两条同样按 6 字节步进解析。
- **定位特征码**：解析代码形如 `BB <imm32>`（`mov ebx, 表基址`）、`89 45 00`、`0F B7 53 04`、`89 10`、`0F B6 4B 0B`、`83 F9 0A`（读取 `[ebx+0xB]` 的数量并与 10 比较，说明样本最多支持 10 条 C2）。用这段字节序列在文件中搜索，`BB` 后的 4 字节就是表 VA。
- **为什么必须 VA→RVA→文件偏移**：`mov ebx, imm32` 里的地址是按 `ImageBase` 计算的 VA，而磁盘文件按节表 `PointerToRawData` 存放；必须用 `pefile` 的 `get_offset_from_rva(va - ImageBase)` 换算，不能直接在文件中按 VA 偏移读取。
- **为什么静态提取优于只抓流量**：样本运行时可能只随机选一个 C2，动态流量只能看到其中一个；静态解析配置表能一次拿到完整列表，便于封锁与影响面评估。

## 触发条件

- 目标为 Dridex 家族 Windows PE（示例为 32 位 DLL），存在可疑 RC4 配置块与大量网络相关解密字符串。
- `.data`/`.rdata` 中能找到上述 `mov ebx, imm32` 解析特征，且表地址落在某个节内、可正常换算。
- 样本未加壳到代码段不可读；若加壳需先脱壳或从内存 dump 中定位。
- 分析环境有 Python 与 `pefile`；不需要运行样本。

## 利用步骤

1. 在 IDA 中定位 `mw_rc4_decrypt` 的交叉引用，导出每个调用点附近的数据块，按“前 `0x30` 字节倒序 key + RC4”解密。
2. 从解密结果中筛选网络相关字符串（`GET`/`POST`、`WinInet`、计划任务命令行、User-Agent 等），回溯其数据引用，锁定 C2 解析函数。
3. 在解析函数中找 `mov ebx, imm32` 的表基址，或直接用特征字节 `BB ?? ?? ?? ?? 89 45 00 0F B7 53 04 89 10 0F B6 4B 0B 83 F9 0A` 在文件中搜索。
4. 取 `BB` 后 4 字节按小端解析为表 VA；用 `pefile` 计算文件偏移：`off = pe.get_offset_from_rva(table_va - ImageBase)`。
5. 读取 `data[off + 0xB]` 作为 C2 数量；从 `off + 0xC` 起每次读 4 字节 IP 与 2 字节小端端口，循环数量次。
6. 用 `0x01BB = 443`、已知端口分布或动态流量交叉验证解析结果；把完整 C2 列表写入 IOC。
7. 若样本有多个表/版本字段，检查 `table_va + 4` 处的 WORD（示例脚本保留为版本字段但未参与解析），避免把版本头误当成条目。

## PoC

```python
import re
import struct
import pefile

SIG = rb'\xbb(....)\x89\x45\x00\x0f\xb7\x53\x04\x89\x10\x0f\xb6\x4b\x0b\x83\xf9\x0a'

def extract_c2(path: str):
    data = open(path, 'rb').read()
    pe = pefile.PE(data=data)
    m = re.search(SIG, data, re.DOTALL)
    if not m:
        return []
    table_va = struct.unpack('<I', m.group(1))[0]
    off = pe.get_offset_from_rva(table_va - pe.OPTIONAL_HEADER.ImageBase) + 0xB
    count = data[off]
    off += 1
    c2 = []
    for _ in range(count):
        ip = '.'.join(map(str, data[off:off + 4]))
        port = struct.unpack('<H', data[off + 4:off + 6])[0]
        c2.append(f"{ip}:{port}")
        off += 6
    return c2

print(extract_c2("sample.bin"))
```

示例数据（表数量 3）首条解析为 `103.42.56.15:443`；PoC 未在本机对样本执行。

## 变体与关联

- **架构/版本变体**：64 位样本可能使用 `mov rbx, imm64` 或 RIP 相对寻址，特征码需相应调整；表头长度、数量偏移（`+0xB`）和条目大小可能随版本变化，必须用同版本样本核对。
- **加密变体**：部分版本会把 C2 表本身加密或改成域名/URL 列表；先确认解密后的表是否为明文 IP+端口，不要硬套。
- **多表/备用 C2**：样本可能有主备表或多个版本字段，分别在代码中交叉引用；把同一函数内所有 `mov reg, imm32` 指向的数据都检查一遍。
- **关联卡片**：[[code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract]]（同一样本的载荷解码链）、[[code-analysis-reverse-windows-remcos-settings-config-extraction]]（另一家族的 RC4 配置提取与字段映射）。
- **边界**：本卡只解析明文 IP/端口表；若 C2 使用 DGA/域名或表被二次加密，需结合字符串解密与动态流量分析。

## 检测与防御

- **静态检测**：YARA 匹配 `BB` 表地址特征序列、RC4 KSA/PRGA 例程、`WinInet`/HTTP 方法字符串与高熵配置块；对解析出的表做结构校验（数量 ≤ 10、端口非零、IP 非保留地址）。
- **网络检测**：封锁提取出的 C2 `ip:port`；监控 443 等常见端口的异常 TLS/HTTP 流量、计划任务创建与 `WinInet` 调用。
- **防御**：EDR 监控进程注入、计划任务持久化与异常外连；邮件网关拦截含宏/PDF/嵌套可执行文件的钓鱼附件；对银行木马常用白加黑链做加载监控。
- **取证**：保存样本、解密脚本、完整 C2 列表与提取时间；分析在隔离环境进行，不执行样本。
