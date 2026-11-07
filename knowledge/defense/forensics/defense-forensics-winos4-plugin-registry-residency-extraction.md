---
id: defense-forensics-winos4-plugin-registry-residency-extraction
title: Winos4 插件注册表驻留与提取：HKCU\Console\0|1\<MD5> 三段式二进制载荷
type: scenario
domain: defense
path: defense/forensics
technique: winos4-plugin-registry-residency-extraction
aliases:
- Winos4 注册表插件
- HKCU Console 0 插件驻留
- Winos4 插件提取
- MD5 注册表名
- 登录模块.dll 注册表
- IpDate 配置
- 银狐 Winos 注册表
tags:
- windows
- forensics
- registry
- winos4
- silverfox
- plugin
- fileless
- persistence
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:01:36+08:00'
  notes: 已对照 content.md 与图 17-28/37-50 核对：HKCU\Console\0|1 的 MD5 值名、文件管理.dll 的 UTF-16LE+末尾 00 00 计算得 f81702de...、三段式（UTF-16LE 插件名+MD5+PE）、登录模块固定值名 d33f351a...、IpDate/IpDatespecial 均一致。截图示例 MZ 头约在 0x4A/0x1000，卡片写 0x42/0x5C/0x1000 为多插件示例偏移，导出时需按实际 MZ 位置截取。未在本机导出注册表或运行样本。frontmatter 无 sources/source_url。
---

## 一句话结论

Winos4 把插件以 `REG_BINARY` 存放在 `HKCU\Console\0\<MD5>`（32 位）和 `HKCU\Console\1\<MD5>`（64 位）下，值名是插件文件名的 MD5（登录模块使用特殊名 `d33f351a4aeea5e608853d1a56661059`），值内容是“插件名 + 原始插件 MD5 + 插件 PE”三段式二进制；运行配置放在 `HKCU\Console\IpDate`。这使插件不落盘即可驻留，取证时可直接从注册表导出还原。

## 原理

- **注册表当插件仓库**：`登录模块.dll` 的 0x00/0x01 指令用于加载插件，0x01 还会把插件写入 `HKCU\Console\0\xxx`。32 位插件写 `HKCU\Console\0\`，64 位插件写 `HKCU\Console\1\`；值类型为 `REG_BINARY`，值名不是明文插件名。
- **值名生成规则**：值名是插件文件名的 MD5。分析中把 `文件管理.dll` 按 UTF-16LE 编码并在末尾补 `00 00` 后计算 MD5，得到 `f81702de02285733e8700972e9ea6b04`，与注册表值名一致。登录模块是例外：其实际值名为 `d33f351a4aeea5e608853d1a56661059`，与按插件名计算的 MD5 不同，说明作者对登录模块做了特殊处理或使用了固定名。
- **值内容三段式**：导出的二进制开头是插件名（UTF-16LE，可解码出 `文件管理.dll`、`登录模块.dll_bin`、`{vU_!jWW.dll_bin` 等），随后是原始插件文件的 MD5（例如 `7b23eef15f75a0ec66a1725a616a8c5d`），再往后是实际的 PE 文件（在偏移 0x42/0x5C/0x1000 等位置可见 `MZ` 头）。三段式设计让加载器可以校验插件完整性并识别插件类型。
- **加载顺序**：`上线模块` 解析硬编码配置后，若 `HKCU\Console\IpDate` 存在则用其内容替换运行配置；随后加载 `登录模块.dll`：若 `HKCU\Console\0\d33f351a4aeea5e608853d1a56661059` 存在，直接从注册表提取并加载；否则外联 C2 获取加密载荷、解密后加载。因此注册表既是插件缓存也是持久化位置。
- **配置项**：`HKCU\Console\IpDate` 保存当前运行配置，0x12 指令会更新它；`HKCU\Console\IpDatespecial` 由 0x64/0x65 指令更新/删除。它们与插件值同在 `Console` 键下，容易与正常控制台配置混淆。
- **为什么难发现**：插件不落盘，常规文件扫描看不到；值名是 32 位 MD5，肉眼看不出插件名；`HKCU\Console` 是系统正常键，管理员通常不会逐值审查；只有导出 `REG_BINARY` 并按三段式解析才能还原插件。

## 触发条件

- 目标 Windows 主机感染 Winos4 系木马，且已执行过插件加载/下发。
- 攻击者拥有当前用户权限（`HKCU` 是当前用户 hive；若木马以其他用户运行，对应其他用户 hive）。
- 注册表未被清理工具删除；`HKCU\Console\0`/`1` 或 `IpDate` 仍存在。
- 取证者可用 `regedit`、PowerShell、`reg query` 或离线 hive 挂载读取 `REG_BINARY`。
- 需要还原插件 PE 时，需按三段式定位 `MZ` 头并截取到文件末尾。

## 利用步骤

1. **枚举键**：检查 `HKCU\Console\0`、`HKCU\Console\1`、`HKCU\Console\IpDate`、`HKCU\Console\IpDatespecial`；`Console\0` 下通常有大量 32 位 MD5 命名的 `REG_BINARY` 值。
2. **记录值名/大小**：值名对应插件 MD5；记录每个值的数据长度与写入时间（若可获取）。
3. **导出二进制**：用 PowerShell 读取 `Get-ItemPropertyValue`，按字节写入 `.bin`（示例见 PoC）；或用 `reg export` 导出后解析。
4. **解析三段**：在导出数据中搜索 UTF-16LE 插件名（如 `文件管理.dll`、`登录模块.dll_bin`），随后查找 32 位十六进制 MD5 字符串，再查找 `MZ`/`PE` 头；从 `MZ` 偏移到数据末尾截取即为插件 PE。
5. **校验**：对截取的 PE 计算 MD5，与第二段 MD5 比对；与资源段/已知插件 MD5 表比对确认插件类型（文件管理、键盘记录、查注册表等）。
6. **关联配置**：读取 `IpDate` 的二进制内容，按平台字段解析 C2/分组；检查 `IpDatespecial` 是否存在。
7. **清理**：先导出留证，再删除相关值/键；同时按其他卡片清理 `Console` 下的持久化与 C2 连接。

## PoC

以下为只读取证脚本（防御研究用，未在本机执行）：

```powershell
$key = "HKCU:\Console\0"
$valueName = "f81702de02285733e8700972e9ea6b04"
$data = Get-ItemPropertyValue -Path $key -Name $valueName
$data | Set-Content -Path "C:\evidence\$valueName.bin" -Encoding Byte -NoNewline
```

```powershell
# 枚举 Console\0 下所有 REG_BINARY 值名与长度
Get-Item "HKCU:\Console\0" | Select-Object -ExpandProperty Property | ForEach-Object {
    $v = Get-ItemPropertyValue -Path "HKCU:\Console\0" -Name $_
    [PSCustomObject]@{ Name = $_; Length = $v.Length }
}
```

解析思路：在导出文件中搜索 `MZ`，截取到末尾；对截取 PE 计算 MD5，与第二段 MD5 比对；UTF-16LE 解码第一段可还原插件名。

## 变体与关联

- 变体：64 位插件在 `HKCU\Console\1\`；登录模块使用固定/特殊值名；不同版本可能改变值名算法、三段式顺序或配置键。
- 变体：插件也可能被写入 `HKCU\Network` 或 `HKCU\AppEvents` 下的 `REMARK`/`GROUP` 值（0x07 指令），用于更新分组/备注而非插件本体。
- 关联：[[code-analysis-reverse-windows-winos4-builder-resource-config-injection]]（插件来源与生成机制）、[[defense-forensics-winos4-c2-frame-xor-decrypt]]（插件通信解密）、[[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]]（银狐主机清理顺序）。

## 检测与防御

- **注册表监控**：监控 `HKCU\Console\0`、`HKCU\Console\1` 下新增 `REG_BINARY` 值，尤其是 32 位十六进制 MD5 名称；监控 `HKCU\Console\IpDate`/`IpDatespecial` 的写入。
- **值内容检测**：对 `Console\0/1` 的二进制值做 `MZ`/`PE` 头与 UTF-16LE 插件名扫描；对 `REG_BINARY` 值计算哈希并与已知 Winos4 插件 MD5 表比对。
- **行为检测**：`登录模块.dll` 从注册表读取自身、加载其他插件；插件加载后各自建立网络连接；`0x01` 指令写入注册表、`0x12` 更新 `IpDate`。
- **取证/清理**：先导出所有值再删除；检查其他用户 hive；重启后复查，防止 C2 重新下发插件。
- **加固**：限制普通用户对 `HKCU\Console` 的异常写入（正常应用很少写入该位置）；启用注册表审计与 EDR 注册表规则；对已知插件名/MD5 做威胁狩猎。
