---
id: code-analysis-reverse-windows-self-delete-ads-wtfbbq
title: 运行中可执行文件自删除：SetFileInformationByHandle 把自身重命名为 :wtfbbq 备用数据流，再 FileDispositionInfo 删除原路径
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: self-delete-running-image-ads-rename
aliases:
- delete-self-poc
- :wtfbbq
- ADS 自删除
- FileRenameInfo 重命名自身
- FileDispositionInfo 删除运行中文件
- 运行中 EXE 删除
- LATRODECTUS 自删除
tags:
- windows
- anti-forensics
- self-deletion
- alternate-data-stream
- ntfs
- setfileinformationbyhandle
- malware-analysis
- latrodectus
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:34:41+08:00'
  notes: 已对照图18核对：SetFileInformationByHandle(FileRenameInfo) 重命名为 <path>:wtfbbq，重新 CreateFileW(DELETE,OPEN_EXISTING) 后 FileDispositionInfo DeleteFileA=1 删除；原文明确引用 delete-self-poc 与 :wtfbbq；已修正'重命名后原路径已不存在'的矛盾表述为'原路径成为承载该流的基文件'；与 Process Ghosting/Doppelganging 机制不同，非重复；原文无版本；未在样本上复现
---

## 一句话结论

运行中的程序可以对自身文件路径执行：以 DELETE 权限打开自身 → `SetFileInformationByHandle(FileRenameInfo)` 把文件重命名为 `C:\path\self.exe:wtfbbq`（变成自身所在卷上的一个备用数据流）→ 再用原路径 `CreateFileW(..., OPEN_EXISTING)` 打开并用 `SetFileInformationByHandle(FileDispositionInfo, DeleteFileA=1)` 删除；由于进程映像的节对象已映射、且原文件名已被“让出”，删除成功后磁盘上不再有该可执行文件，进程仍继续运行，从而干扰取证与响应（LATRODECTUS 用该技术自删除，标记串 `:wtfbbq` 来自公开的 delete-self-poc）。

## 原理

- **NTFS 备用数据流把文件名与数据分离**：`file.exe:wtfbbq` 表示 `file.exe` 的一个命名数据流。把运行中的 `file.exe` 重命名为 `file.exe:wtfbbq` 后，`file.exe` 这个目录项指向的对象变成了一个带 ADS 的文件；进程已经映射的 image section 与文件对象仍持有数据，执行不受影响。
- **为什么能删除运行中的文件**：重命名后原路径 `file.exe` 成为承载 `:wtfbbq` 流的基文件，原文件数据由该命名流承载；此时重新用 `CreateFileW(lpFileName, DELETE, ..., OPEN_EXISTING)` 仍可打开原路径，再 `SetFileInformationByHandle(..., FileDispositionInfo, DeleteFileA=1)` 标记删除；关闭句柄后基文件连同流从目录中消失，而已建立的 image section 仍持有数据，进程继续运行。整个过程中内核不会因为“image 正在执行”而拒绝，因为删除发生在重命名后的对象上。
- **代码特征**：`SetFileInformationByHandle(hFile, FileRenameInfo, &fRename, ...)`，其中新名字为原路径追加 `:wtfbbq`；随后 `CreateFileW(lpFileName, DELETE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)`，`FileInformation.DeleteFileA = 0 → 1`，`SetFileInformationByHandle(hFile, FileDispositionInfo, &FileInformation, 1)`。
- **用途**：LATRODECTUS 在感染初始阶段和 handler #15 更新自身时执行该流程——先下载/执行新副本，再删除旧运行文件并退出，使磁盘上只留新文件或干脆无文件，增加样本捕获与溯源难度。
- **前提**：文件系统为 NTFS、进程对自身映像有 DELETE 权限（普通用户可操作自己的文件）、Windows Vista/7+ 支持 `SetFileInformationByHandle` 的文件信息类。

## 触发条件

- Windows + NTFS，样本以普通进程权限运行，能够打开自身映像路径。
- 样本包含 `:wtfbbq` 一类流名标记与上述 API 组合；常见于加载器/更新逻辑、反取证与反分析模块。
- 用于分析时需在支持 ADS 的 NTFS 卷上复现（FAT/exFAT 上 `:` 不是流语法）。

## 利用步骤

1. `GetModuleFileNameW` 取得自身路径 `lpFileName`。
2. `CreateFileW(lpFileName, DELETE | SYNCHRONIZE, FILE_SHARE_* , OPEN_EXISTING, ...)` 打开自身。
3. 构造 `FILE_RENAME_INFO`：`ReplaceIfExists = TRUE`，`FileName = lpFileName + L":wtfbbq"`（长度按字节算），调用 `SetFileInformationByHandle(hFile, FileRenameInfo, ...)`。
4. 关闭句柄；重新 `CreateFileW(lpFileName, DELETE, ..., OPEN_EXISTING, ...)` 打开原路径（此时指向重命名后的对象）。
5. `FILE_DISPOSITION_INFO.DeleteFileA = TRUE`，`SetFileInformationByHandle(hFile, FileDispositionInfo, ...)`，关闭句柄完成删除。
6. 进程继续运行；后续可执行“下载新副本 → 启动 → 退出”的更新流程。

## PoC

```c
// 核心调用序列（省略错误处理）
HANDLE h = CreateFileW(selfPath, DELETE | SYNCHRONIZE, 0, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
WCHAR newName[MAX_PATH];
swprintf(newName, L"%s:wtfbbq", selfPath);
DWORD nameLen = (wcslen(newName) + 1) * sizeof(WCHAR);
DWORD size = sizeof(FILE_RENAME_INFO) + nameLen;
PFILE_RENAME_INFO fri = (PFILE_RENAME_INFO)malloc(size);
fri->ReplaceIfExists = TRUE;
fri->FileNameLength = nameLen;
wcscpy(fri->FileName, newName);
SetFileInformationByHandle(h, FileRenameInfo, fri, size);
CloseHandle(h);

h = CreateFileW(selfPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
FILE_DISPOSITION_INFO fdi = { .DeleteFile = TRUE };
SetFileInformationByHandle(h, FileDispositionInfo, &fdi, sizeof(fdi));
CloseHandle(h);
```

（公开实现见 delete-self-poc；LATRODECTUS 的标记串为 `:wtfbbq`。以上为机制复刻，未在原文样本上执行。）

## 变体与关联

- 关联：该技术出现在 LATRODECTUS 的初始化与更新流程（handler #15）中，家族全貌见 [[code-analysis-reverse-windows-latrodectus-loader-behavior-c2]]。
- 变体：`FileDispositionInfoEx` + `FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS` 可在不重命名的情况下强制删除；Process Ghosting/Doppelganging 则通过 Section 与 delete-on-close 达到类似“无文件”效果，见 [[pentest-c2-windows-process-ghosting-delete-on-close-section]]。
- 变体：自删除的另一路线是批处理 `del` 自身/`ping` 延时删除，但会被杀软重点监控；ADS 重命名法更隐蔽。
- 检测关联：Elastic 行为规则 “Potential Self-Deletion of a Running Executable”、CAPA `self-delete-using-alternate-data-streams`。

## 检测与防御

- 检测：Sysmon/EDR 文件重命名事件中出现目标为可执行文件且新名字含 `:`（ADS 流）；紧接对同一路径的 DELETE 打开与删除；运行中 image 路径消失（进程仍存活但磁盘找不到文件）。
- 检测：内存扫描仍可捕获进程映像（`.text` 等节在内存中），磁盘取证需结合进程内存 dump、USN journal 与卷影副本恢复。
- 防御：对可执行文件所在目录启用受控文件夹/写保护；限制普通用户对自身映像的 DELETE 权限（较难，Windows 默认允许）；EDR 对“重命名自身到 ADS + 删除”的组合行为告警；保留 USN/卷影作为事后恢复手段。
