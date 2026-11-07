---
id: code-analysis-reverse-windows-wdigest-logsesslist-key-decrypt-logoncredential
title: WDigest 凭据提取：从 LSASS 定位 l_LogSessList 与 h3DesKey/hAesKey/IV 解密密码，改 g_fParameter_UseLogonCredential 强制明文缓存
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: wdigest-logsesslist-key-decrypt-force-plaintext-cache
aliases:
- Sekurlsa::Wdigest
- WDigest 明文凭据
- l_LogSessList
- h3DesKey hAesKey InitializationVector
- g_fParameter_UseLogonCredential
- LsaEncryptMemory
- WdigestGrab
- mimikatz sekurlsa::wdigest
tags:
- windows
- lsass
- wdigest
- mimikatz
- credential-access
- reverse-engineering
- pattern-scanning
- 3des
- aes
- lsasrv
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:17+08:00'
  notes: 已对照原文与41张图核对：SpAcceptCredentials 断点明文、l_LogSessList/KIWI_BCRYPT_HANDLE_KEY(UUUR)/KIWI_BCRYPT_KEY81(MSSK)/KIWI_HARD_KEY(0x18)、LsaInitializeProtectedMemory 生成 h3DesKey/hAesKey/IV、LsaEncryptMemory 的 cbInput&7→AES(16) 否则 3DES(8)、Win11 pattern、XPN IV_OFFSET 61→71、g_fParameter_UseLogonCredential 改写与三平台验证均一致；卡片已注明原文文字把 AES/3DES 条件写反。未验证点：未运行 WdigestGrab。frontmatter 无 sources/source_url。
---

## 一句话结论

WDigest 在 Windows Server 2008 R2 之后默认不再缓存明文口令，但在用户输入凭据（锁屏、`runas`）时 `wdigest!SpAcceptCredentials` 仍会被调用，`wdigest!l_LogSessList` 链表中保存账户与加密后的口令；定位 `lsasrv!h3DesKey`/`hAesKey`/`InitializationVector` 后，按 `LsaEncryptMemory` 的 AES/3DES 分支解密即可还原明文。若口令字段为 NULL，则可定位并改写 `wdigest!g_fParameter_UseLogonCredential` 为 1，触发一次认证后强制 WDigest 重新以明文缓存。

## 原理

- **调用链**：用户输入凭据时进入 `wdigest!SpAcceptCredentials`；它调用 `wdigest!LogSessHandlerPasswdSet`，把账户信息和加密后的口令写入 `wdigest!l_LogSessList` 指向的双向链表。断在 `SpAcceptCredentials` 上可以直接看到账户名与明文口令，但离线提取需要遍历链表并解密。
- **密钥来源**：`lsasrv!LsaInitializeProtectedMemory` 在 LSASS 启动时生成 `h3DesKey`、`hAesKey` 和 `InitializationVector` 三个全局变量；`lsasrv!LsaEncryptMemory` 在加密/解密时使用它们。
- **AES/3DES 分支**：反编译 `LsaEncryptMemory` 可见：`v3 = h3DesKey; cbIV = 8;`，若 `cbInput & 7` 为真则 `v3 = hAesKey; cbIV = 16;`，随后调用 `BCryptEncrypt/BCryptDecrypt`。即**长度不能被 8 整除时用 AES（16 字节 IV），能被 8 整除时用 3DES（8 字节 IV）**；原文文字把这一条件写反，实际应以反编译代码为准。
- **密钥对象结构**：`h3DesKey`/`hAesKey` 是 `KIWI_BCRYPT_HANDLE_KEY` 指针，结构为 `{ULONG size; ULONG tag('UUUR'); PVOID hAlgorithm; PKIWI_BCRYPT_KEY81 key; PVOID unk0;}`；`key` 指向 `KIWI_BCRYPT_KEY81`（`tag='MSSK'`），其尾部是 `KIWI_HARD_KEY { ULONG cbSecret; BYTE data[60]; }`。用 tag 校验可避免误读；原文示例 `cbSecret=0x18`（3DES 24 字节密钥）。
- **l_LogSessList 定位**：mimikatz 用 `PTRN_WIN6_PasswdSet`（字节 `48 3b d9 74`）在 wdigest.dll 中匹配 `l_LogSessList` 的引用，在 Win10/Server2016 可用；Win11 的 wdigest.dll 指令布局变化，需改用另一段 pattern，例如 `lea rcx, l_LogSessList; lea rbx, [r14+4]; cmp rsi, rcx; jz` 对应 `49 8d 5e 04 48 3b f1 74`。
- **密钥/IV 定位**：XPN 的代码用一段 pattern 找到 `LsaInitializeProtectedMemory` 附近的 `hAesKey`/`h3DesKey`/`InitializationVector` 引用，并硬编码 `IV_OFFSET`。不同系统上 `lea` 的位移不同，硬编码会读到错误值；原文把偏移改为 71 后成功。更稳的做法是从 `lea rdx, [InitializationVector]` 指令中读取 4 字节 RIP 相对位移，再计算目标地址，而不是硬编码偏移。
- **强制明文缓存**：`SpAcceptCredentials` 中检查 `g_fParameter_UseLogonCredential` 与 `g_IsCredGuardEnabled`：若 `g_fParameter_UseLogonCredential == 0` 或 Credential Guard 开启，则把 `v11` 置 1，走 `LogSessHandlerNoPasswordInsert`（不保存口令）；否则走 `LogSessHandlerPasswdSet`。把 wdigest 模块中的 `g_fParameter_UseLogonCredential` 全局 DWORD 改为 1，再触发一次登录，就会重新缓存明文。注册表 `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=1` 也可开启，但需要新登录/重启，且部分系统默认没有该键。
- **为什么可行**：加密密钥与 IV 由 LSASS 在启动时生成并常驻内存；攻击者有 LSASS 读写权限时，既能读取密钥，也能改写控制缓存策略的全局变量。WDigest 的设计把“是否需要明文缓存”的决策放在可写内存中，而不是只依赖不可变的策略。

## 触发条件

- 目标 Windows 主机启用了 WDigest（`wdigest.dll` 已加载），且攻击者能以本地管理员/SYSTEM 读取（最好也能写入）LSASS 内存，或拿到可离线解析的 minidump。
- 目标未启用 Credential Guard / LSASS PPL / VBS 等保护；若启用，读取/改写 LSASS 会失败，需先绕过（不在本卡范围）。
- 能触发一次凭据输入（锁屏解锁、`runas`、`mstsc` 保存凭据等）以调用 `SpAcceptCredentials`。
- 有对应版本的 pattern 或符号；不同 Windows 版本的 wdigest.dll/lsasrv.dll 指令布局会变化，需要重新定位。
- 有编译/运行环境（C/C++、ReadProcessMemory/WriteProcessMemory 或 mimikatz 插件）。

## 利用步骤

1. **获取 LSASS 访问**：以管理员/SYSTEM 打开 `lsass.exe` 进程句柄（`SeDebugPrivilege`），或先用 `procdump`/`comsvcs.dll`/mimikatz `sekurlsa::minidump` 拿到 dump 离线分析。
2. **定位 wdigest 与 l_LogSessList**：加载 `wdigest.dll` 到本地或读取目标模块基址；用 `48 3b d9 74`（Win10/Server2016）或 Win11 的 `49 8d 5e 04 48 3b f1 74` 匹配 `l_LogSessList` 引用，计算全局地址。
3. **定位密钥与 IV**：在 `lsasrv.dll` 中匹配 `LsaInitializeProtectedMemory` 附近的 pattern（如 `83 64 24 30 00 48 8d 45 e0 44 8b 4d d8 48 8d 15`），从 `lea rdx, [InitializationVector]` 读取位移，分别算出 `h3DesKey`、`hAesKey`、`InitializationVector` 的地址；也可用 XPN 的硬编码偏移，但必须先在本机验证（原文 61 失败、71 成功）。
4. **提取密钥对象**：读取 `KIWI_BCRYPT_HANDLE_KEY`，校验 `tag='UUUR'`；读取 `key` 指针指向的 `KIWI_BCRYPT_KEY81`，校验 `tag='MSSK'`；读取 `KIWI_HARD_KEY.cbSecret` 与 `data`，得到 3DES/AES 密钥。
5. **遍历 l_LogSessList**：把 `l_LogSessList` 当作 `LIST_ENTRY` 头，沿 `Flink` 遍历；对每个节点读取用户名、域名与加密口令块；按 `cbInput & 7` 选择 AES（16 字节 IV）或 3DES（8 字节 IV），用 BCrypt/OpenSSL 解密。
6. **强制明文缓存（可选）**：若口令为 NULL，定位 `g_fParameter_UseLogonCredential`（在 `SpAcceptCredentials+0xcc` 附近的 `f7 47 50 00 08 00 00 0f 85` 引用之后，或通过 `cmp cs:g_fParameter_UseLogonCredential, ebx` 交叉引用），用 `WriteProcessMemory` 写入 DWORD 1；触发锁屏/`runas` 登录，再回到第 5 步。
7. **验证**：用 mimikatz `sekurlsa::wdigest` 或自研工具确认 `Password` 字段出现明文；在 Win10/Server2016/Win11 上分别验证 pattern 与偏移。

## PoC

```c
// 关键结构（x64）
typedef struct _KIWI_BCRYPT_HANDLE_KEY {
    ULONG size;
    ULONG tag;              // 'UUUR'
    PVOID hAlgorithm;
    struct _KIWI_BCRYPT_KEY81 *key;
    PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY;

typedef struct _KIWI_HARD_KEY {
    ULONG cbSecret;         // 原文示例 0x18
    BYTE data[60];
} KIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY81 {
    ULONG size;
    ULONG tag;              // 'MSSK'
    ULONG type, unk0, unk1, unk2, unk3, unk4;
    PVOID unk5;
    ULONG unk6, unk7, unk8, unk9;
    KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81;

// pattern 示例（原文）
unsigned char logSessListSigWin10[] = { 0x48, 0x3b, 0xd9, 0x74 };
unsigned char logSessListSigWin11[] = { 0x49, 0x8d, 0x5e, 0x04, 0x48, 0x3b, 0xf1, 0x74 };
unsigned char keyIVSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0,
                             0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
unsigned char useLogonCredentialSig[] = { 0xf7, 0x47, 0x50, 0x00, 0x08, 0x00, 0x00, 0x0f, 0x85 };

// 解密分支（以 LsaEncryptMemory 反编译为准）
// if (cbInput & 7) { key = hAesKey; ivLen = 16; }
// else             { key = h3DesKey; ivLen = 8;  }
```

原文的完整实现见 WdigestGrab 仓库；核心流程是：`SearchPattern(wdigest, logSessListSig)` 得到 `l_LogSessList` 偏移，遍历链表；`SearchPattern(lsasrv, keyIVSig)` 后读取 4 字节位移得到 `h3DesKey/hAesKey/InitializationVector`；读取 `KIWI_BCRYPT_HANDLE_KEY` → `KIWI_BCRYPT_KEY81` → `KIWI_HARD_KEY`；最后按 `LsaEncryptMemory` 分支解密。若口令为 NULL，则在 wdigest 中找到 `g_fParameter_UseLogonCredential` 并写入 1。

## 变体与关联

- **Win11 pattern 变体**：原文的 `48 3b d9 74` 在 Win11 上找不到，需用 `49 8d 5e 04 48 3b f1 74`；不同 build 可能再变，建议同时保留多组 pattern 并用 `l_LogSessList` 符号/交叉引用校验。
- **硬编码偏移 vs 位移解析**：XPN 代码用 `IV_OFFSET=61` 失败、改为 71 成功；更稳的是从 `lea` 指令读取 RIP 相对位移，避免 build 差异。
- **注册表开启**：`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=1`（DWORD）可让 WDigest 重新缓存明文，但需要新的登录/重启；内存改写 `g_fParameter_UseLogonCredential` 可立即生效但需 LSASS 写权限。
- **Credential Guard**：`g_IsCredGuardEnabled` 为真时即使 `g_fParameter_UseLogonCredential=1` 也走 NoPasswordInsert；需要先绕过 VBS/Credential Guard，或改走其他凭据（Kerberos/DPAPI）。
- **离线分析**：拿到 minidump 后可在 Linux 用 pypykatz 解析 WDigest 结构，避免在目标上运行工具；参考 [[pentest-ad-lsass-minidump-pypykatz-offline]]。
- 关联：[[code-analysis-reverse-windows-mimikatz-24h2-lsasrv-offset-struct-adaptation]]（mimikatz 在 24H2 的 lsasrv 偏移/结构适配，本卡是 wdigest.dll 的对应适配）、[[pentest-ad-lsass-minidump-pypykatz-offline]]（LSASS dump 离线解析）。

## 检测与防御

- **阻断 LSASS 读写**：启用 Credential Guard / LSASS PPL（RunAsPPL）/ VBS，限制 `SeDebugPrivilege`，用 EDR 监控对 `lsass.exe` 的 `OpenProcess(PROCESS_VM_READ|PROCESS_VM_WRITE)`、`ReadProcessMemory`/`WriteProcessMemory`、minidump 调用。
- **禁用 WDigest 明文缓存**：确保 `UseLogonCredential=0`（或删除该值），优先使用 Kerberos/智能卡，减少可被 WDigest 缓存的凭据；监控该注册表键的创建/修改。
- **监控全局变量改写**：对 `wdigest!g_fParameter_UseLogonCredential` 的写入没有现成事件，需结合 LSASS 内存完整性/EDR 行为检测；拦截未知 SSP 加载与 `wdigest.dll` 异常 patch。
- **检测特征**：`sekurlsa::wdigest`/WdigestGrab 类工具访问 lsass；`SpAcceptCredentials` 附近被断点/改写；`l_LogSessList` 被遍历；`h3DesKey/hAesKey/InitializationVector` 被读取；短时间内多次锁屏/`runas` 触发认证后出现凭据读取。
