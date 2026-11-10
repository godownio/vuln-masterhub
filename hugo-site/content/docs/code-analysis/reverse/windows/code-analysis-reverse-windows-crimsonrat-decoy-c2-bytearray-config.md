---
id: code-analysis-reverse-windows-crimsonrat-decoy-c2-bytearray-config
title: CrimsonRAT C# 配置提取：可见诱饵 C2 字符串 + 十进制字节数组隐藏真实 C2 与端口
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: crimsonrat-config-extraction
tags:
- windows
- crimsonrat
- apt36
- transparent-tribe
- rat
- config-extraction
- dotnet
- csharp
- byte-array
- c2
- malware-analysis
- ioc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V301
  verified_at: '2026-11-08T12:17:42+08:00'
  notes: 已对照原文与 17 张图核对（本卡图 01-04）：图03 配置类中 maisdwtp 为可见字符串默认值 221.120.112.150、ports={11248,16896,18868,22245,26424}、minsbnfdsns 为十进制 byte[]；图04 CyberChef From Charcode Base10 解码为 waqers.duckdns.org?94.72.105.227；图05 systerAons 先 DIFRVFSEF.maisdwtp=this.servsIuPD()[0] 再 Connect，局部变量 [0]=waqers.duckdns.org、[1]=94.72.105.227，证实诱饵字段被覆盖。卡片字节数组解码 PoC、端口数组与数据流解释均与原文一致。无 affected_versions（样本分析，无版本）。dedup top1 为自身 exact，其余 new（同文另两卡与 Obfuscar/AdaptixC2 等均不同原子）。未验证点：未接触样本本体，仅按文章截图核对。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-crimsonrat-decoy-c2-bytearray-config/
draft: false
kb_aliases:
- CrimsonRAT 配置提取
- 透明部落 CrimsonRAT
- APT36 C2 配置
- 诱饵 C2 变量
- 字节数组隐藏 C2
- C# 远控配置分析
- minsbnfdsns
- servsIuPD
---

## 一句话结论

CrimsonRAT（透明部落/APT36 使用的 C# 远控）在配置类里放了一个一眼可见的假 C2 字符串字段（`maisdwtp`，默认值如 `221.120.112.150`），真实外链 C2 却以十进制 ASCII 字节数组（`minsbnfdsns`）存放，解码后得到 `waqers.duckdns.org` 与 `94.72.105.227`（以 `?` 分隔）；端口另行放在 `int[] ports`（11248、16896、18868、22245、26424）。连接函数实际从 `servsIuPD()` 返回的数组取值，并在运行中覆盖 `maisdwtp`，因此只看字段默认值会把诱饵当成真 C2。

## 原理

- **反编译可见性与诱饵**：.NET 程序用 dnSpy 等反编译器可直接看到静态字段和常量。样本配置类中 `maisdwtp` 是普通字符串字段，赋值形如 `"221.120.112.150"`；若分析者停在字段初始化处，会把它登记为 C2。
- **真实值走数据流**：上线函数先执行 `DIFRVFSEF.maisdwtp = this.servsIuPD()[0]`，再用 `this.mainVdket.Connect(DIFRVFSEF.maisdwtp, DIFRVFSEF.port)` 建连。局部变量显示 `servsIuPD()` 返回 `["waqers.duckdns.org", "94.72.105.227"]`，即字段默认值在建连前被真实地址覆盖，`maisdwtp` 只是诱饵/占位。
- **字节数组编码**：`minsbnfdsns` 是 `byte[]`，元素为可打印字符的十进制 ASCII 码（如 119 97 113 …）；按 ASCII 解码得到 `waqers.duckdns.org?94.72.105.227`，`0x3F`（`?`）是两个 C2 的分隔符。字符串常量另用 `"A.F_0.7".Replace("_","")` 这类去下划线手法做浅层混淆，变量名无意义。
- **端口数组**：`public static int[] ports = new int[] {11248, 16896, 18868, 22245, 26424}`，与地址数组解耦，供上线失败时轮换（见关联卡）。
- **为什么容易漏**：真实 C2 既不是明文常量，也不在连接调用现场直接出现，而是“字节数组 → 解码函数 → 临时数组 → 覆盖字段 → Connect”这条链；不跟踪 `servsIuPD()` 的返回与字段写入顺序，就会漏掉真实 IOC。原文作者正是先看到诱饵，进一步分析才发现字节数组。

## 触发条件

- 样本为 .NET/C# 编写的 CrimsonRAT（透明部落/APT36 常用），配置以内嵌静态字段/数组形式存在；
- 具备反编译能力（dnSpy、ILSpy 等），可静态分析，无需运行样本；
- 需要从样本中提取 C2、端口等 IOC 用于溯源、封禁或流量检测。

## 利用步骤

1. 用 dnSpy 打开样本，定位配置类（大量 `public static` 字段、无意义命名、含 `.Replace("_","")` 的字符串初始化）。
2. 记录所有字符串字段作为候选 C2，但不要直接采信；标记其中被后续代码重新赋值的字段为可疑诱饵。
3. 找出 `byte[]` 静态数组，按十进制 ASCII 解码；观察是否存在域名/IP 特征及分隔符（本例 `?`）。
4. 跟踪 `Connect(host, port)` 调用点，回溯 host 实参来自哪个方法/数组（本例 `servsIuPD()[0]`/`[1]`），确认真正使用的地址。
5. 提取端口数组与地址数组的对应关系，形成完整 C2 列表；与公开情报/沙箱结果交叉验证。
6. 将解码脚本与样本哈希一并记录，便于同家族其他样本批量提取。

## PoC

从反编译结果抄出字节数组后的最小解码脚本（原文用 CyberChef 的 From Charcode/Base 10 完成等价操作）：

```python
vals = [119, 97, 113, 101, 114, 115, 46, 100, 117, 99, 107, 100,
        110, 115, 46, 111, 114, 103, 63, 57, 52, 46, 55, 50, 46,
        49, 48, 53, 46, 50, 50, 55]  # minsbnfdsns 片段示例
s = bytes(vals).decode("ascii")
print(s)                 # waqers.duckdns.org?94.72.105.227
hosts = [h for h in s.split("?") if h]
print(hosts)             # ['waqers.duckdns.org', '94.72.105.227']
```

端口数组直接读取：`[11248, 16896, 18868, 22245, 26424]`。

## 变体与关联

- **变体**：其他构建可能更换分隔符（`?`、`|`、`\0`）、改用 UTF-16/Base64/XOR 后再存字节数组，或把诱饵字段真正用于某条备用路径；提取时以数据流为准，不能只看字段名。
- **关联**：同文章中的“CrimsonRAT 明文 C2 协议”卡说明拿到地址/端口后如何与样本交互；“多 C2 地址与端口轮换”卡说明两个地址和端口数组的使用顺序。
- **同类**：Remcos `SETTINGS` 资源提取、Quasar/NjRAT 配置解密等 RAT 配置提取卡；本卡是 .NET 静态字段 + 字节数组这一具体形态。
- **边界**：这是恶意样本分析/配置提取技术，不是漏洞利用链；不同家族、不同构建的字段布局不能直接套用。

## 检测与防御

- **静态检测**：对 .NET 样本扫描“十进制字节数组 + `Encoding.ASCII`/`BitConverter` 解码 + 域名/IP 拼接 + `TcpClient.Connect`”组合；关注 `duckdns.org` 等动态 DNS 域名和高位端口常量。
- **IOC 使用**：把解码出的域名、IP 与端口整体封禁，不要只封诱饵地址；同时监控 DNS 查询 duckdns 子域后紧跟高位端口 TCP 连接的行为。
- **分析规范**：任何“唯一可见 C2”都要通过交叉引用确认是否被覆盖或真正使用；将诱饵地址登记为假 IOC，避免误封。
- **防御**：限制终端对动态 DNS 与非常用端口的出站访问；对 C# 远控常见静态字段/字节数组特征做 YARA 与内存扫描；样本仅在隔离环境静态分析，不执行。
