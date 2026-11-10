---
id: code-analysis-reverse-windows-sfc-verifyfile-deriveddata-s256-tiworker-hash
title: SFC /VERIFYFILE 校验链逆向：COMPONENTS\DerivedData 组件键 S256H、TiWorker.exe 与 FileHashAlgorithmToDigest
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: sfc-verifyfile-deriveddata-s256-tiworker-hash
tags:
- windows
- sfc
- wrp
- reverse-engineering
- tiworker
- components
- hash-verification
- cbs
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T02:57:33+08:00'
  notes: 已对照原文与图片核对：组件名 x86_microsoft-windows-kernel32_31bf3856ad364e35_10.0.19041.1202_none_ac5f76a753246f13、COMPONENTS\DerivedData\Components 下 S256H/identity/f!kernel32.dll、TiWorker 读取并调用 FileHashAlgorithmToDigest、在 S256H 前插 00 后 CBS.log 报 Manifest hash does not match expected value(Expected 33 字节/Found 32 字节)与 sfc 控制台完整性冲突输出均与原文/截图一致。原文正文写 S256、截图为 S256H，卡以截图为准正确。未验证点：自定义哈希算法原文未逆出，卡已如实标注边界；FileHashAlgorithmToDigest 与 manifest SHA256 两层校验的精确分工原文表述模糊。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-sfc-verifyfile-deriveddata-s256-tiworker-hash/
draft: false
kb_aliases:
- sfc /VERIFYFILE
- S256H
- DerivedData Components
- TiWorker 完整性校验
- FileHashAlgorithmToDigest
- SFPIntegrityCheckAndRepair
---

## 一句话结论

`sfc /VERIFYFILE=<文件>` 在文件名保护判定之后，会按系统版本/架构/地区拼出组件名并在 `HKLM\COMPONENTS\DerivedData\Components\<组件名>` 读取 `S256H`（清单哈希）等值，由 COM 激活的 `TiWorker.exe` 调用 `Windows::Cms::Rtl::FileHashAlgorithmToDigest`（自定义哈希，不是 SHA256）校验目标文件、并校验 `C:\Windows\WinSxS\Manifests` 下 `.manifest` 的 SHA256；把 `S256H` 的字节改掉再执行 `/VERIFYFILE`，会在 CBS.log 报 `Manifest hash ... does not match expected value`，sfc 输出“Windows 资源保护找到了完整性冲突”。

## 原理

- **组件寻址**：sfc 先完成 `IsFileProtected` 判断，然后读取当前系统版本、架构、地区等属性，计算唯一组件名，例如 `x86_microsoft-windows-kernel32_31bf3856ad364e35_10.0.19041.1202_none_ac5f76a753246f13`，再到 `HKLM\COMPONENTS\DerivedData\Components\<组件名>` 读取该组件的校验数据。案例键下可见 `S256H`（REG_BINARY）、`identity`（REG_BINARY）、`f!kernel32.dll`（REG_DWORD）等值。
- **进程与接口**：sfc.exe 通过 `CoCreateInstance` 激活 COM 类：`CLSID_SFPIntegrityCheckAndRepair = {8F5DF053-3013-4dd8-B5F4-88214E81C0CF}`（注册表名 “SFP Repair Class”，AppID `{752073A2-23F2-4396-85F0-8FDB879ED0ED}`），IID `ISFPIntegrityCheckAndRepair = {90ED9FAA-A6E5-4671-8E50-1C060F8B9C47}`，其 `InprocServer32` 指向 `%systemroot%\servicing\wrpintapi.dll`（ThreadingModel=Both）。真正执行校验的 `TiWorker.exe` 由 svchost.exe 创建（`TiWorker.exe -Embedding`），Process Monitor 中可见其读取 `COMPONENTS\DerivedData\Components\...` 与 `WinSxS\Manifests\*.manifest`。
- **哈希算法**：TiWorker 调用链为 `Windows::Cms::Rtl::FileHashAlgorithmToDigest` → `wcp!RtlReplicateSystemPatMappings` → `NtReadFile`。该函数不是标准 SHA256，S256H 中存放的是清单哈希的期望值；同时 SFC 还会对 `WinSxS\Manifests` 下的清单文件计算 SHA256 并与注册表值比对，两条校验并存。
- **篡改效果（已验证）**：把 `S256H` 的二进制数据前插入一个 `0x00` 字节后重跑 `sfc /VERIFYFILE=c:\windows\system32\kernel32.dll`，CBS.log 记录 `Manifest hash for component ... does not match expected value`（Expected 33 字节 `00 c9 83 64 ...`，Found 32 字节 `c9 83 64 ...`），sfc 控制台输出“Windows 资源保护找到了完整性冲突”，并提示查看 `C:\Windows\Logs\CBS\CBS.log`。改动只改变了期望值，不改变文件本身。
- 边界：原文未逆出 `FileHashAlgorithmToDigest` 的算法，也没有完成“伪造受保护文件并通过校验”的整链；本卡记录的是校验链结构与“改 S256H 使校验失败”这一已验证原语，不构成完整绕过。

## 触发条件

- Windows 10/11（案例 10.0.19041）；以管理员或具备 `HKLM\COMPONENTS` 写权限的上下文操作（默认该键由 TrustedInstaller 控制，普通管理员也常需先取得所有权）。
- 目标文件存在对应的组件键（DerivedData\Components 下按版本/架构/语言命名的键）。
- 运行 `sfc /VERIFYFILE=<完整路径>` 触发校验；CBS 日志位于 `C:\Windows\Logs\CBS\CBS.log`。

## 利用步骤

1. 运行 `sfc /VERIFYFILE=c:\windows\system32\kernel32.dll` 触发一次完整校验。
2. 用 Process Monitor 过滤 `TiWorker.exe`：观察 `RegOpenKey/RegQueryValue` 落在 `HKLM\COMPONENTS\DerivedData\Components\x86_microsoft-windows-kernel32_...`（读取 `identity`、`S256H`），以及 `CreateFile/ReadFile` 落在 `C:\Windows\WinSxS\Manifests\x86_microsoft-windows-kernel32_....manifest`。
3. 记录组件名构成：`<arch>_microsoft-windows-<组件>_<版本哈希>_<版本>_none_<部署哈希>`，后续按目标文件替换对应字段即可定位其它组件的键。
4. 验证篡改效果：编辑目标组件键的 `S256H`（案例在数据前插入 `0x00`），重新执行 `/VERIFYFILE`，确认 sfc 报告完整性冲突、CBS.log 出现 manifest hash mismatch。
5. 如需定位哈希计算：附加 `TiWorker.exe`，在 `Windows::Cms::Rtl::FileHashAlgorithmToDigest` 下断，栈回溯可见 `ReadFile`/`NtReadFile`，据此确认哈希输入与比对值来源。

## PoC

组件键与值（示例组件为 kernel32）：

```text
HKLM\COMPONENTS\DerivedData\Components\x86_microsoft-windows-kernel32_31bf3856ad364e35_10.0.19041.1202_none_ac5f76a753246f13
  S256H      REG_BINARY  c9 83 64 04 42 3b f3 08 ...
  identity   REG_BINARY  4d 69 63 72 6f 73 6f 66 74 2e 57 69 6e 64 6f ...
  f!kernel32.dll  REG_DWORD  0x00001010
```

篡改后执行：

```cmd
reg 编辑 S256H，在数据最前插入 00
sfc /VERIFYFILE=c:\windows\system32\kernel32.dll
```

CBS.log 结果片段：

```text
Manifest hash for component [l:85 ml:140]'x86_microsoft-windows-kernel32_31bf3856ad364e35_10.0.19041.1202_none_ac5f76a753246f13' does not match expected value.
Expected:{l:33 b:00c9836404423bf308ce428c2177f4936f1e343937f4ab3f70567ac643ea8d1d}
Found:{l:32 b:c9836404423bf308ce428c2177f4936f1e343937f4ab3f70567ac643ea8d1d}
```

控制台输出：

```text
Windows 资源保护找到了完整性冲突。
有关联机修复，位于 windir\Logs\CBS\CBS.log ...
```

## 变体与关联

- 变体：`identity` 等值同样参与校验；`f!kernel32.dll` 这类 DWORD 可能是组件内文件属性/标志，修改后也可能影响判断，原文未逐一验证。
- 变体：manifest 校验是并行的第二层（SHA256）；即使绕过 S256H 的清单哈希比对，仍需处理 `.manifest` 文件的 SHA256 校验。
- 关联：前置的文件名保护判定见 [[code-analysis-reverse-windows-sfc-isfileprotected-filemaps-pnp-lockdown]]；TiWorker 的捕获方法见 [[code-analysis-reverse-windows-com-activation-child-process-createprocessinternalw-capture]]。
- 边界：自定义哈希算法未还原，无法构造与 S256H 匹配的恶意文件；修改 S256H 只能让校验失败，不能替换受保护文件。原文亦未完成该整链。

## 检测与防御

- 监控 `HKLM\COMPONENTS`（尤其 `DerivedData\Components\*\S256H`）的写入与 ACL 变更；该键应由 TrustedInstaller 严格保护，普通管理员取得所有权本身即高风险事件。
- 采集 CBS.log：出现 `Manifest hash ... does not match expected value`、`Store corruption detected`、`Unable to load manifest` 等记录时，结合同一时间窗口内对 COMPONENTS 的写操作判断是否为人为篡改。
- 对 `sfc /VERIFYFILE` 的异常使用（短时间内批量校验、校验后立即修改注册表）建立关联检测；SFC 修复失败的系统应检查 WinSxS 清单与组件键完整性。
- 防御重点是 TrustedInstaller 服务与 WRP 资源的 ACL，而不是依赖 SFC 自身；SFC 是事后检测/修复工具，篡改其期望值只会造成误报或修复失败。
