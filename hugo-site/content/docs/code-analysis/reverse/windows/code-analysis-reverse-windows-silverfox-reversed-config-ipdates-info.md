---
id: code-analysis-reverse-windows-silverfox-reversed-config-ipdates-info
title: 银狐样本配置还原：反转管道串 + denglupeizhi 标记 + IpDates_info 注册表
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silverfox-reversed-config-ipdates-info
tags:
- windows
- malware-analysis
- reverse
- silverfox
- winos4
- config-extraction
- registry
- c2
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T23:17:26+08:00'
  notes: 已对照原文及图01-11核对：wcsrev反转串、denglupeizhi标记、HKCU\Console IpDate/IpDatetime、HKLM\SOFTWARE\IpDates_info(REG_BINARY,UTF-16LE)、C2 115.190.102.32:6000均一致；知识库正文已修正截图日期为(9-27-1-25-18)并注明IpDatetime值名差异。未动态运行样本。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-silverfox-reversed-config-ipdates-info/
draft: false
kb_aliases:
- 银狐配置解析
- wcsrev 反转字符串
- denglupeizhi
- IpDates_info
- HKCU Console IpDate
- 管道分隔配置
- 银狐 C2 配置提取
---

## 一句话结论

该银狐样本把配置藏在一条被 `wcsrev` 反转的管道分隔字符串里（形如 `|0:db|...|9 .11.5202:zb|0.1:bb|`），启动时反转后按 `p1:/o1:/t1:`、`p2:/o2:/t2:` 等字段解析功能开关；同时用 `denglupeizhi` 标记在缓冲区中定位配置块，并读取 `HKCU\Console\IpDate`、把更新后的配置写进 `HKLM\SOFTWARE\IpDates_info`（REG_BINARY、UTF-16LE）。反转字符串、按标记切分、解码注册表三步即可还原 C2 IP/端口、本地监听端口、版本与配置日期。

## 原理

- **反转字符串混淆**：`wcsrev` 把整条配置字符串倒序，静态看到的是 `|0:db|0:lk|...|9 .11.5202:zb|0.1:bb|`；反转后变回 `|bb:1.0|bz:2025.11. 9|...|db:0|` 形式，`bb:` 是版本、`bz:` 是配置日期、`db:`/`lk:` 等是功能开关。
- **管道分隔与键值对**：配置以 `|` 分隔，每段是 `键:值`；`p1/o1/t1`、`p2/o2/t2`、`p3/o3/t3` 是三组 C2/上线参数（不同版本含义可能不同），`dd/cl/fz/bb/bz/jp/sx/bh/ll/dl/sh/kl/bd` 是下载、代理、分组、端口等字段。解析函数先找 `tN:`，再读该段最后一个字符是否为 `'1'` 来置位对应全局开关（如 `dword_14005F6A8`）。
- **`denglupeizhi` 标记**：`sub_140007500` 在缓冲区中逐字节匹配 ASCII `denglupeizhi`（“登录配置”的拼音），返回偏移；`sub_140006D20` 用该偏移把新配置 `Src` 覆盖进配置块，并写入注册表。这个标记是定位配置块的稳定锚点。
- **注册表双位置**：启动时 `sub_140008750` 打开 `HKCU\Console`，查询 `IpDate` 值；若长度大于 `0xA`，读取并再次解析（原文截图里实际值名为 `IpDatetime`，REG_BINARY、UTF-16LE 解码为 `(9-27-1-25-18)`，可覆盖内置配置；代码查询名与截图值名可能因样本版本不同）。更新配置时 `sub_140006D20` 打开 `HKLM\SOFTWARE`，先 `RegDeleteValueW` 再 `RegSetValueExW` 写入 `IpDates_info`（类型 3 = REG_BINARY，长度 0x12A0），因此该值既是配置持久化也是取证点。
- **为什么成立**：字符串反转、管道分隔、标记定位都是可逆/可静态还原的弱混淆；注册表值类型和编码（UTF-16LE，大量 `00` 空字节）固定，导出后按 UTF-16LE 解码即可读明文。
- **不确定性**：原文只给出部分反编译和配置截图，`p1/o1/t1` 各字段的完整语义、`5202` 反转成 `2025` 的规则、`IpDates_info` 更新后的完整布局未逐字段验证；卡内按可见字段与通用 Winos4/银狐配置格式描述，具体样本需动态/多版本对照。

## 触发条件

- 拿到银狐/Winos4 系样本，静态字符串中出现 `|0:db|`、`denglupeizhi`、`IpDates_info`、`IpDate` 等特征。
- 样本可静态反编译（IDA/Ghidra），能看到 `wcsrev`、`RegQueryValueExW`、`RegSetValueExW`、`sub_140007500` 等调用。
- 有主机注册表导出/内存镜像，可读取 `HKCU\Console\IpDate` 与 `HKLM\SOFTWARE\IpDates_info`。
- 配置未强加密（仅反转/分隔/UTF-16LE）；若新版本改为 AES/XOR，需先解密。

## 利用步骤

1. 在 IDA 字符串窗口搜索 `denglupeizhi`、`IpDates_info`、`IpDate`、`|0:db|`；对 `|0:db|...` 字符串交叉引用，确认 `wcsrev` 调用点。
2. 取反转后的字符串：`wcsrev` 的结果应为 `|bb:1.0|bz:2025.11. 9|...|db:0|`；按 `|` 切分，再按第一个 `:` 拆键值。
3. 解析 `p1/o1/t1`、`p2/o2/t2`、`p3/o3/t3` 与 `dd/cl/fz/bb/bz/jp/sx/bh/ll/dl/sh/kl/bd`；记录 C2 IP/端口、本地监听、版本、日期、功能开关。
4. 在样本/主机上读取 `HKCU\Console\IpDate`（原文截图值名为 `IpDatetime`）：若长度 > 0xA，按 UTF-16LE 解码（示例 `(9-27-1-25-18)`），判断是否覆盖内置配置。
5. 导出 `HKLM\SOFTWARE\IpDates_info`（REG_BINARY），按 UTF-16LE 解码；过滤 `00` 空字节后读取 C2 IP、端口、本地监听、版本、日期等明文字段。
6. 用动态沙箱/Wireshark 验证：样本启动后应连接配置中的 C2（示例 `115.190.102.32:6000`）与外联域名；阻断后观察重试间隔。
7. 记录 IOC：C2 IP/端口、域名、注册表键值、配置日期/版本；与已知银狐/Winos4 配置格式比对。

## PoC

反转为可读配置（结构示意）：

```python
s = "|0:db|0:lk|0:hs|0:ld|0:ll|0:hb|0:pj|9 .11.5202:zb|0.1:bb|"
plain = s[::-1]
print(plain)  # |bb:1.0|bz:2025.11. 9|jp:...|...

cfg = {}
for part in plain.strip("|").split("|"):
    if ":" in part:
        k, v = part.split(":", 1)
        cfg[k] = v
print(cfg)
```

读取注册表配置（只读，PowerShell）：

```powershell
$v = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE" -Name "IpDates_info"
[Text.Encoding]::Unicode.GetString($v) -replace "`0", ""
```

说明：字段顺序/含义随版本变化；`IpDates_info` 是二进制配置块，可能含非字符串字段，先原样导出再解析，避免破坏证据。

## 变体与关联

- 变体：Winos4 控制端用 `codemark`/`xiugaishiyong` 标记追加配置，与本文的 `denglupeizhi` 不同；参见 [[code-analysis-reverse-windows-winos4-builder-resource-config-injection]]。
- 变体：配置可能再套 Base64/XOR/AES，或拆成多个注册表值；先找解密函数再解析。
- 变体：注册表位置可能改为 `HKCU\Console\IpDate`/`IpDatespecial` 或 `HKCU\Network` 的 `GROUP/REMARK`；参见 [[defense-forensics-winos4-plugin-registry-residency-extraction]]、[[defense-forensics-silverfox-winos4-file-registry-artifact-dump]]。
- 关联：[[defense-forensics-python-malware-reversed-base64-url-config]]（反转 + Base64 配置的另一种实现）；[[pentest-c2-staged-downloader-multi-target-injection-veh-fallback]]（Winos4 配置字段 `p1/o1` 的另一案例）；[[defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt]]（ValleyRAT 通信解密）。

## 检测与防御

- 检测：样本字符串含 `denglupeizhi`、`IpDates_info`、`|0:db|`、`wcsrev` 调用；注册表 `HKLM\SOFTWARE\IpDates_info`、`HKCU\Console\IpDate` 被写入。
- 检测：进程启动后外联配置中的 C2 IP/端口；阻断后按固定间隔重试；配置日期与样本编译时间接近。
- 防御：监控上述注册表键值写入；对银狐/Winos4 已知配置特征做 YARA/EDR 规则；限制普通用户写 `HKLM\SOFTWARE`（需管理员）。
- 防御：发现感染后先导出配置与注册表值留证，再按银狐清理卡顺序删除服务/插件/配置并轮换可能泄露的凭据。
