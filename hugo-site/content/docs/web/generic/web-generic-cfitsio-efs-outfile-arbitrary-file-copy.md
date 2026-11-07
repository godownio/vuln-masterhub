---
id: web-generic-cfitsio-efs-outfile-arbitrary-file-copy
title: CFITSIO EFS outfile 在格式校验前复制任意文件到任意可写路径
type: scenario
domain: web
path: web/generic
technique: cfitsio-efs-outfile-arbitrary-file-copy
tags:
- web
- file-processing
- cfitsio
- fits
- efs
- arbitrary-file-read
- arbitrary-file-write
- local-file
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:32+08:00'
  notes: 已对照原文与 25 张截图核对：input(outfile) 在 FITS 头校验前完成复制、/etc/passwd 到 passwd.copy 实测、fits_open_diskfile 语义边界均一致。未验证点：未复跑；原文仅以 4.6.3 实验环境验证，无受影响版本区间。
url: /docs/web/generic/web-generic-cfitsio-efs-outfile-arbitrary-file-copy/
draft: false
kb_aliases:
- CFITSIO EFS 任意文件复制
- fits_open_file outfile
- 文件名 outfile 语法
- FITS 副作用先于格式校验
- CFITSIO 任意文件写入
---

## 一句话结论

当应用把用户可控的完整字符串传给 `fits_open_file()` 且未关闭 EFS 时，文件名中的 `输入(输出)` 语法会让 CFITSIO 在验证 FITS 头之前把任意可读文件复制到任意可写路径；即使调用最终返回“不是 FITS 文件”，副本也已经生成。

## 原理

- `fits_open_file()` 不把参数直接当普通路径，而是交给 `ffopen()` 按 Extended Filename Syntax 解析。`ffifile2()` 把字符串拆成 `urltype`、`infile`、`outfile`、`extspec` 等控制字段；`urltype2driver()` 根据协议选择 Driver，Driver 的 `open()` 执行真实 I/O。
- 关键时序是“先执行 I/O，后校验格式”：`ffopen()` 先调用 Driver 的 `open()`，`file_open()` 在该阶段创建 outfile 并复制输入数据；之后才调用 `ffldrc()`/`ffrhdu()` 读取并校验 FITS Header。校验失败只返回错误状态，不会回滚已经创建的 outfile。
- 因此危害不是“复制功能本身”，而是外部输入同时决定了“读哪个文件”和“把副本写到哪里”。读取范围受进程权限限制，写入范围也只受进程文件系统权限限制；若 outfile 指向 Web 目录、共享目录或任务产物目录，任意文件复制就升级为文件内容泄露；若指向配置、计划任务、授权文件等可写目标，则构成任意文件写入。
- `fits_open_diskfile()` 是安全语义边界：它通过 `OPEN_DISK_FILE` 直接把完整输入当作字面磁盘路径，强制 `file://`，清空 outfile/extspec 等控制字段，且不调用 `ffifile2()`。它不是黑名单过滤，而是取消文件名中的解释器语义。

## 触发条件

- 应用把外部可控字符串（文件名、上传名、任务参数、URL 参数等）完整传给 `fits_open_file()`，且未在调用前拒绝 EFS 元字符。
- CFITSIO 进程对源文件有读权限、对目标路径有写权限。
- 目标路径可被攻击者取回（Web 根目录、共享目录、下载接口读取的目录），或可被用于覆盖敏感文件。
- 受影响的 EFS 解析行为在实验环境 CFITSIO 4.6.3 上复现；原文未给出明确的受影响版本区间。

## 利用步骤

1. 确认目标接口把用户输入直接交给 `fits_open_file()`，而不是 `fits_open_diskfile()`。
2. 构造 EFS：`<源文件>(<目标路径>)`。源文件选择进程可读的敏感文件（如 `/etc/passwd`、应用配置、密钥文件）。
3. 触发接口；CFITSIO 会先创建目标文件并复制内容，随后才因非 FITS 内容返回格式错误。
4. 忽略返回的错误状态，检查目标路径；若目标位于可下载/可读取位置，直接取回内容。
5. 若目标路径可写敏感位置，可尝试覆盖配置或脚本，进一步扩大影响（需结合目标进程权限与文件用途）。

## PoC

```text
/etc/passwd(/var/www/html/passwd.copy)
```

```c
int status;
fitsfile *fptr;
/* 返回 status=108（不是 FITS 文件），但 passwd.copy 已写入 */
fits_open_file(&fptr, "/etc/passwd(/tmp/passwd.copy)", READONLY, &status);
```

验证方式：调用返回 FITS 读取错误（如 status 108）后，`/tmp/passwd.copy` 仍存在且内容与源文件一致。合法 FITS 对照可使用 `sample.fits(sample-copy.fits)`，哈希一致可证明 outfile 是真实复制。

## 变体与关联

- 远程输出变体：outfile 还可指向 `root://` 等可写 Driver，把本地文件转换后外传，见 [[web-generic-cfitsio-efs-root-driver-local-file-exfiltration]]。
- HTTP 输入变体：输入使用 `http://` 时同时形成 SSRF 并把响应落盘，见 [[web-generic-ssrf-cfitsio-efs-http-outfile-response]]。
- 关联：文件名被后续组件解释为协议、参数、路径或语法的通用问题，还包括 ImageMagick/FFmpeg 的伪格式与 Coder 调用、ZIP/TAR 条目名路径、以 `-` 开头的文件名被当作命令行参数等。
- 边界：进程无读/写权限时不成立；只使用 `fits_open_diskfile()` 时括号与方括号只是普通文件名字符，不触发 EFS。

## 检测与防御

- **检测（输入）**：文件名/参数中出现 `(`、`)`、`[`、`]`、`root://`、`http://` 等 EFS 元字符；调用返回 104/108 但磁盘出现新文件。
- **检测（主机）**：CFITSIO 进程在业务目录或 Web 根目录创建非预期副本；源文件与目标文件内容一致。
- **修复（首选）**：业务只需本地普通文件时，改用 `fits_open_diskfile()`，从入口取消解释器语义。
- **加固**：必须使用 EFS 时，在解析后、Driver 调度前对 `urltype` 和 `outfile` 做强类型白名单，拒绝外部指定输出路径；以低权限、隔离临时目录运行解析任务；对失败调用产生的中间文件做清理。
- **纵深防御**：用 Seccomp/AppArmor 限制解析进程的文件读写与网络连接范围；对 SAST 规则把 `fits_open_file()` 标记为危险 Sink，追踪外部输入是否未经校验流入。
