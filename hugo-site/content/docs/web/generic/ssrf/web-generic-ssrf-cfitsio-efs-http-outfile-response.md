---
id: web-generic-ssrf-cfitsio-efs-http-outfile-response
title: CFITSIO EFS HTTP Driver SSRF 并把响应落盘为可读文件
type: scenario
domain: web
path: web/generic/ssrf
technique: cfitsio-efs-http-outfile-ssrf
tags:
- web
- ssrf
- cfitsio
- fits
- efs
- http
- outfile
- non-blind
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:34+08:00'
  notes: 已对照原文与截图核对：http 输入加 outfile 落盘、服务端收到 GET /probe.txt、本地文件含 CFITSIO-EFS-SSRF-LAB 标记均一致。未验证点：未复跑；outfile 不可读时退化为盲 SSRF。
url: /docs/web/generic/ssrf/web-generic-ssrf-cfitsio-efs-http-outfile-response/
draft: false
kb_aliases:
- CFITSIO SSRF
- EFS HTTP 响应落盘
- fits_open_file SSRF
- 非盲 SSRF 文件响应
- http:// 输入 outfile
---

## 一句话结论

当用户可控文件名传给 `fits_open_file()` 时，`http://内网地址/路径(输出文件)` 会让 CFITSIO 主动请求任意 HTTP 目标，并把响应内容写入本地 outfile；即使随后因内容不是 FITS 而报错，响应已经落盘，形成可读取响应体的非盲 SSRF。

## 原理

- `ffifile2()` 解析出 `urltype=http` 后，`urltype2driver()` 选择 HTTP Driver。Driver 解析主机、端口和路径，建立连接，发送 `GET <path> HTTP/1.0`，读取响应并写入输入流。
- 同一 EFS 中括号内的 outfile 会让 Driver 把读取到的内容保存到本地文件。即“远程输入 + 本地输出”两个正常能力被一个字符串组合。
- 与常见 SSRF 一样，网络请求由服务端发起，可访问回环地址、内网段、云元数据等外部不可达目标；不同点在于 outfile 让响应体可被持久化，攻击者只要能读取该文件，就能取得完整响应，而不是只能做端口探测或盲请求。
- `ffopen()` 的时序是 Driver 先打开、下载并写 outfile，再调用 `ffldrc()`/`ffrhdu()` 校验 FITS Header；非 FITS 响应只导致错误返回，不会撤销网络请求或删除 outfile。
- HTTP Driver 还读取环境变量 `http_proxy`，若目标环境配置了代理，请求可能经代理转发；这会影响可达范围，但不改变 SSRF 本质。

## 触发条件

- 应用把外部可控字符串完整传给 `fits_open_file()`，且 EFS 未关闭。
- CFITSIO 进程能访问目标地址（内网、回环、云元数据或攻击者服务）。
- outfile 路径可写，且攻击者能通过 Web 目录、下载接口、共享目录或任务产物读回该文件。
- 实验环境为 CFITSIO 4.6.3；原文未给出明确的受影响版本区间。

## 利用步骤

1. 确认目标接口可控文件名且使用 `fits_open_file()`。
2. 选择可访问的内网 HTTP 服务或云元数据地址，构造 `http://<目标>:<端口>/<路径>(<可读输出路径>)`。
3. 触发接口；CFITSIO 发起 GET，把响应写入 outfile，随后因非 FITS 返回错误状态。
4. 通过可读位置取回 outfile，读取响应内容。
5. 若需特定 Host、Authorization 或自定义头，可结合 URL Path 换行注入，见 [[web-generic-crlf-cfitsio-efs-http-request-header-injection]]。

## PoC

```text
http://127.0.0.1:18080/probe.txt(/workspace/http-response.bin)
```

```c
int status;
fitsfile *fptr;
/* 返回 status=108，但 outfile 已包含 HTTP 响应 */
fits_open_file(&fptr,
    "http://127.0.0.1:18080/probe.txt(/workspace/http-response.bin)",
    READONLY, &status);
```

验证：HTTP 服务日志出现 `GET /probe.txt`，`http-response.bin` 内容等于服务端返回体（可用唯一标记确认请求—响应—落盘闭环）。

## 变体与关联

- 本地文件读取变体：`file://` 或直接路径配合 outfile，见 [[web-generic-cfitsio-efs-outfile-arbitrary-file-copy]]。
- 请求头注入变体：URL Path 中的换行可注入 `Host`、`Authorization` 等，见 [[web-generic-crlf-cfitsio-efs-http-request-header-injection]]。
- 外传变体：本地文件经 Raw Data Clause 转换后用 `root://` 写到远程，见 [[web-generic-cfitsio-efs-root-driver-local-file-exfiltration]]。
- 边界：outfile 不可读时退化为盲 SSRF；进程无出网权限或目标地址不可达时不成立。

## 检测与防御

- **检测（输入）**：文件名参数中出现 `http://`、`https://`、`ftp://`、外部主机、括号输出路径。
- **检测（网络）**：CFITSIO 进程向回环、内网段、云元数据地址发起 HTTP；请求 User-Agent 为 `FITSIO/HEASARC/...`；请求后紧跟异常返回。
- **检测（主机）**：业务目录出现非预期响应文件；文件内容为 HTML/JSON/云元数据而非 FITS。
- **修复**：本地文件场景改用 `fits_open_diskfile()`；必须使用 EFS 时，在 Driver 调度前对 `urltype` 和 outfile 做强类型白名单，禁止外部协议与外部主机。
- **加固**：对解析进程限制出网（防火墙、网络命名空间、Seccomp 拒绝 `connect`）；禁止 outfile 写入可被外部读取的目录；对响应落盘做审计与清理。
