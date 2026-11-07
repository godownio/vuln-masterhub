---
id: defense-forensics-locked-browser-sqlite-handle-duplication
title: 运行中浏览器 SQLite 被独占锁：句柄枚举 + DuplicateHandle + 文件映射复制
type: scenario
domain: defense
path: defense/forensics
technique: locked-file-handle-duplication-copy
aliases:
- 复制被占用文件
- 借用浏览器文件句柄
- NtQuerySystemInformation 句柄枚举
- DuplicateHandle 复制句柄
- CreateFileMapping 读取锁定文件
- Cookies 被锁复制
tags:
- windows
- forensics
- file-lock
- handle-duplication
- sqlite
- browser
- live-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:28:49+08:00'
  notes: 已对照原文与7张图核对：ERROR_SHARING_VIOLATION(32)、SystemHandleInformation=0x10 的 x64 24字节句柄条目布局、PROCESS_DUP_HANDLE/DUPLICATE_SAME_ACCESS、PAGE_READONLY+FILE_MAP_READ+RtlMoveMemory、路径归一化与 WAL/SHM 伴生文件均一致；图04 日志显示 locked file duplicating browser handle。未验证点：未实际运行句柄复制；frontmatter 无 sources/source_url。
---

## 一句话结论

浏览器以独占共享模式打开 `Cookies`、`Login Data` 等 SQLite 时，普通复制会报 `ERROR_SHARING_VIOLATION(32)`；枚举系统句柄、把浏览器持有的文件句柄 `DuplicateHandle` 到当前进程，再用文件映射读取，即可在不干扰浏览器文件指针的情况下复制数据（含 WAL/SHM 伴生文件）。

## 原理

- Windows 共享模式：Chrome/Edge 用严格的共享模式打开 SQLite，外部进程 `CreateFile` 请求共享读写时被拒绝，错误码为 `ERROR_SHARING_VIOLATION(32)`。
- `NtQuerySystemInformation(SystemHandleInformation=0x10)` 返回全系统句柄表。64 位布局：偏移 0 为 `NumberOfHandles`，偏移 8 开始是条目数组，每条 24 字节：`UniqueProcessId`(u16)、`CreatorBackTraceIndex`(u16)、`ObjectTypeIndex`(u8)、`HandleAttributes`(u8)、`HandleValue`(u16)、`Object`(uptr)、`GrantedAccess`(u32)。
- 缓冲区从 4 MiB 起步，收到 `STATUS_INFO_LENGTH_MISMATCH(0xC0000004)` 时按系统返回的所需长度扩容重试，上限 512 MiB；跳过 pid 0（System Idle）、pid 4（System）和 `HandleValue==0`。
- `OpenProcess(PROCESS_DUP_HANDLE=0x40)` 打开持有进程，`DuplicateHandle(..., DUPLICATE_SAME_ACCESS=0x2)` 把句柄复制到当前进程。复制得到的是同一个 `FILE_OBJECT`，浏览器能读，当前进程就能读，共享模式限制被绕开。
- `GetFileType` 必须等于 `FILE_TYPE_DISK(0x1)`，排除管道、字符设备；`GetFinalPathNameByHandle` 取真实路径。
- **不用 `ReadFile`**：复制来的句柄与浏览器共享文件指针，`ReadFile` 会移动指针、干扰浏览器；改用 `CreateFileMapping(PAGE_READONLY)` + `MapViewOfFile(FILE_MAP_READ)` 按页读取，再用 `RtlMoveMemory` 拷贝到缓冲区，无副作用。
- SQLite WAL 模式下最新数据在 `-wal`，索引在 `-shm`；只复制主文件会丢最新事务，需要一起复制。

## 触发条件

- Windows 目标上浏览器正在运行，`Cookies`/`Login Data`/`History`/`Web Data` 被独占锁定；
- 当前进程有权限打开浏览器进程（同用户或管理员）并获得 `PROCESS_DUP_HANDLE`；
- 目标文件是磁盘文件句柄，路径可归一化匹配；
- 文件大小不超过工具上限（示例 512 MiB）；
- 取证/应急场景需注意：复制过程可能被 EDR 视为句柄窃取或凭据访问。

## 利用步骤

1. 先尝试普通复制；若失败且错误为 `ERROR_SHARING_VIOLATION(32)`，进入锁定回退。
2. 调用 `NtQuerySystemInformation(0x10, buf, len, &ret)` 枚举句柄；按 4 MiB 起步，遇 `0xC0000004` 扩容重试。
3. 遍历条目，跳过 pid 0/4 与 `HandleValue==0`；对每个候选进程 `OpenProcess(PROCESS_DUP_HANDLE)`，失败则跳过。
4. `DuplicateHandle` 到当前进程，`DUPLICATE_SAME_ACCESS`；`GetFileType` 不是 `FILE_TYPE_DISK` 则关闭并继续。
5. `GetFinalPathNameByHandle` 取路径，按规则归一化：`/`→`\`；去掉 `\\?\`、`\??\`、`\\.\` 前缀；去尾部 `\`；转小写。匹配策略：全路径相等、互为后缀、或 `stableSuffix` 相等（从 `\appdata\`、`\programdata\`、`\users\public\` 之后截取）。
6. `GetFileSizeEx` 取大小（超过上限拒绝）；`CreateFileMapping(h, nil, PAGE_READONLY, 0, 0, nil)`，`MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0)`；`RtlMoveMemory` 拷贝到 Go 切片；写目标文件（0600）。
7. 对 `Cookies`、`Login Data`、`History`、`Web Data` 顺带复制 `-wal`/`-shm`；例如 `Network/Cookies` → `Network/Cookies` + `Network/Cookies-wal` + `Network/Cookies-shm`。
8. 校验输出文件的 SQLite 头与大小，必要时在分析机用只读方式打开并跑 `PRAGMA integrity_check`。

## PoC

```go
func copyFileSmart(src, dst string) error {
    if err := copyNormal(src, dst); err == nil {
        return nil
    } else if !isLockError(err) {
        return err
    }
    h, err := findFileHandle(src)   // 枚举 + DuplicateHandle
    if err != nil { return err }
    defer windows.CloseHandle(h)

    data, err := readLockedFile(h)  // CreateFileMapping + MapViewOfFile + RtlMoveMemory
    if err != nil { return err }
    return os.WriteFile(dst, data, 0o600)
}
```

```text
句柄条目（64 位，24 字节）：
0x00 UniqueProcessId u16
0x02 CreatorBackTraceIndex u16
0x04 ObjectTypeIndex u8
0x05 HandleAttributes u8
0x06 HandleValue u16
0x08 Object uptr
0x10 GrantedAccess u32

读取参数：
CreateFileMapping: PAGE_READONLY (0x2)
MapViewOfFile:     FILE_MAP_READ (0x4)
RtlMoveMemory:     ntdll 导出，接收映射地址
```

## 变体与关联

- 卷影复制（VSS）或 SQLite backup API 也能拿到一致副本，但需要管理员/服务配合，且不如句柄复制轻量。
- 不同进程的句柄枚举 API 也可用 `NtQueryObject` 辅助判断对象类型；跨会话/受保护进程可能拒绝 `OpenProcess`。
- 文件映射读取同样适用于其它被独占锁定的日志、数据库文件。
- 关联卡片：[[defense-forensics-chromium-artifact-offline-decrypt]]、[[pentest-privilege-escalation-chromium-v10-dpapi-credential-decrypt]]。

## 检测与防御

- 检测：EDR 对 `NtQuerySystemInformation` 全系统句柄枚举、`PROCESS_DUP_HANDLE`、对浏览器进程的句柄复制、`CreateFileMapping` 读取浏览器数据库的行为告警；监控非浏览器进程读取 `Cookies`/`Login Data`。
- 防御：浏览器数据目录 ACL 限制；启用 Credential Guard/App-Bound Encryption 等凭据保护；EDR 规则拦截可疑句柄复制；对高价值主机减少本地保存凭据。
- 注意：本技术是双用途的——取证人员可用于在线提取，攻击者也可用于绕过文件锁窃取凭据；检测与处置应结合上下文判断。
