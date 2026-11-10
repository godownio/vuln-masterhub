---
title: IoT/工控
weight: 1
---

# IoT/工控

## 这层是什么

固件、协议、硬件与工业控制系统安全。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- [IoT 协议](protocol/) —— MQTT、CoAP、Modbus、Zigbee 等。
- [硬件](hardware/) —— UART/JTAG/SPI、侧信道与故障注入。
- [工业控制](industrial/) —— PLC、SCADA、DCS 与 OT 协议。
- [车联网](vehicle/) —— 车机 ADB/调试口、车载摄像头、蓝牙 HID 与 GNSS 欺骗。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Cisco RV34X 未授权文件上传 + upload.cgi 拼 mv 覆盖 /www/login.html：路由器登录页存储型 XSS（CVE-2023-20073）](iot-cisco-rv34x-unauth-upload-cgi-mv-login-xss/) | verified | high | 2026-11-07 |
| [CVE-2024-3273 D-Link NAS nas_sharing.cgi 未授权 RCE：硬编码 messagebus 后门 + system 参数 base64 命令注入（空格过滤用 tab 绕过）](iot-dlink-nas-sharing-cgi-messagebus-backdoor-base64-system-rce/) | verified | high | 2026-11-07 |
| [D-Link DI-8100 msp_info_htm flag=cmd 命令注入：cmd 参数拼入 system 的 wys 命令](iot-dlink-di8100-msp-info-htm-cmd-command-injection/) | verified | high | 2026-11-07 |
| [D-Link DI-8100 upgrade_filter_asp path 命令注入：以 http:// 开头的 path 拼入 system 的 wys wget download](iot-dlink-di8100-upgrade-filter-asp-path-command-injection/) | verified | high | 2026-11-07 |
| [D-Link DIR-605L boa start_wps pin 参数命令注入（CNVD-2026-28535）](iot-firmware-boa-pin-command-injection/) | verified | high | 2026-11-06 |
| [D-Link DIR-615/645/815 service.cgi REQUEST_URI 参数命令注入（CNVD-2018-01084，固件 1.03 及之前）](iot-dlink-dir615-645-815-service-cgi-event-command-injection/) | verified | medium | 2026-11-07 |
| [D-Link DIR-816 CVE-2018-17066：时间设置参数未过滤，date -s 拼接导致 doSystem 命令注入](iot-dlink-dir816-cve-2018-17066-date-cmd-injection/) | verified | medium | 2026-11-08 |
| [D-Link DIR-820L /get_set.ccp DeviceName 换行绕过 ncc2 黑名单命令注入（CVE-2022-26258）](iot-dlink-dir820l-get-set-device-name-command-injection/) | verified | high | 2026-11-08 |
| [D-Link DIR-820L /ping.ccp ping_addr 换行注入 ncc2 doPingV6（CVE-2022-34974）](iot-dlink-dir820l-ping-ccp-ping-addr-command-injection/) | verified | high | 2026-11-08 |
| [D-Link/TrendNet getcfg.php 未授权读取账户口令：换行注入绕过 AUTHORIZED_GROUP + SERVICES 加载 DEVICE.ACCOUNT](iot-dlink-getcfg-php-cve-2018-7034-account-disclosure/) | verified | high | 2026-11-08 |
| [D-Link/WayOS USB 共享组件 usb_paswd.asp hname 命令注入：jhttpd 拼 echo 到 /etc/smbusers 时进 system](iot-dlink-wayos-usb-paswd-hname-command-injection/) | verified | high | 2026-11-08 |
| [IPC 固件 UDP JSON RPC 命令注入：mp_rate 拼进 system 并覆盖 rtwpriv 回显](iot-ipc-json-rpc-mp-rate-command-injection/) | verified | high | 2026-11-06 |
| [ipTIME AX2004M /cgi 别名路径绕过 /sess-bin 会话校验（未授权修改管理员密码）](iot-iptime-ax2004m-cgi-alias-path-auth-bypass/) | verified | high | 2026-11-06 |
| [ipTIME AX2004M 隐藏调试后门 d.cgi：硬编码密钥 aaksjdkfj + cmd 参数 popen 命令执行](iot-iptime-ax2004m-dcgi-debug-backdoor-command-injection/) | verified | high | 2026-11-06 |
| [jhttpd proxy_client.asp 的 proxy_srv 命令注入：httpd_get_parm 取值经 nvram_set/snprintf 拼进 jhl_system，反引号执行 wget](iot-jhttpd-proxy-client-asp-proxy-srv-command-injection/) | verified | high | 2026-11-08 |
| [MikroTik RouterOS ≤6.38.4 Chimay-Red 漏洞利用：mknod+telnet 管道流式上传并运行 TinyShell 后门](iot-mikrotik-chimay-red-stackclash-tinyshell-upload/) | verified | high | 2026-11-09 |
| [OEM 同源设备漏洞迁移：飞鱼星/迈普 send_order.cgi name 参数命令注入（uid=0）](iot-oem-same-fingerprint-send-order-cgi-command-injection/) | verified | high | 2026-11-08 |
| [Tenda AC15 /goform/telnet 命令注入（CVE-2025-25632）：doSystemCmd 拼接 lan.ip 启动 telnetd](iot-tenda-ac15-goform-telnet-command-injection/) | verified | medium | 2026-11-07 |
| [TOTOLINK /boafrm/formSysCmd 的 sysCmd GET 参数经 sprintf 拼进 system() 造成未授权命令注入（CVE-2024-51228）](iot-totolink-boafrm-formsyscmd-syscmd-command-injection/) | verified | low | 2026-11-08 |
| [TOTOLINK NR1800X lighttpd formLoginAuth.htm authCode=1 登录绕过：伪造 authCode 直接创建 SESSION_ID 进后台](iot-totolink-nr1800x-formloginauth-authcode-login-bypass/) | verified | high | 2026-11-08 |
| [TP-Link AX1800 /cgi-bin/luci/;stok=/locale country 参数未授权命令注入：popen 拼接 + wget|sh 下载执行（文章推断 CVE-2023-27359）](iot-tplink-ax1800-luci-locale-country-command-injection/) | verified | medium | 2026-11-08 |
| [TP-Link SR20 TDDP v1（UDP 1040）未授权命令注入：CMD_FTEST_CONFIG 的 tftp 拼接与 Lua config_test 加载执行](iot-tplink-sr20-tddp-v1-udp-cmd-injection-lua/) | verified | high | 2026-11-08 |
| [TP-Link WR740 固件调试后门：httpDebugInit 注册隐藏 URL + 硬编码 osteam/5up + pty 命令执行](iot-tplink-wr740-httpdebug-backdoor-pty-cmd/) | verified | high | 2026-11-08 |
| [ZeroShell /cgi-bin/kerbynet 的 x509type 参数未授权命令注入（CVE-2019-12725）：用换行符跳出单引号，借 sudo tar --checkpoint-action=exec 执行任意命令](iot-zeroshell-kerbynet-x509type-unauth-command-injection/) | verified | medium | 2026-11-08 |
| [ZKTeco 终端二维码 SQL 注入：20 字节限制下用 ' or 1=1 -- 伪造有效用户](iot-zkteco-qr-sqli-auth-bypass/) | verified | medium | 2026-11-08 |
| [安凯（anyka）平台摄像头 Wi-Fi 配网脚本 PSK 命令注入：sh -c 拼接 wpa_cli 拿 root 并经 jffs2 持久化](iot-camera-wifi-psk-shell-injection-jffs2-persistence/) | verified | high | 2026-11-08 |
| [小米 AX9000 CVE-2023-26315：xqdatacenter→thrifttunnel→datacenter→plugincenter 认证后命令注入（root RCE）](iot-xiaomi-ax9000-cve-2023-26315-xqdatacenter-plugincenter-command-injection/) | verified | high | 2026-11-06 |
| [小米/红米路由器 set_config_iotdev ssid 命令注入开启 SSH：持登录 stok 改 nvram ssh_en 并启动 dropbear，root/admin 登录](iot-xiaomi-misystem-set-config-iotdev-ssid-command-injection-ssh/) | verified | high | 2026-11-09 |
| [小米路由器 BE10000 Pro xqdatacenter→thrifttunnel→datacenter 链命令注入（认证后 root RCE）](iot-xiaomi-be10000-xqdatacenter-thrifttunnel-command-injection/) | verified | high | 2026-11-06 |
| [摄像头 APP 登录结果 Hook 绕过：Frida 篡改 LoginDev result=0 无密码拉取实时视频流](iot-camera-app-login-result-hook-bypass/) | verified | high | 2026-11-08 |
| [瑞斯康达 MSG2200-T4 智能网关 /vpn/list_base_config.php template 命令注入：反引号写 PHP WebShell](iot-raisecom-msg2200-t4-list-base-config-template-command-injection/) | verified | high | 2026-11-07 |
| [锐捷 EW 系列 /cgi-bin/luci/api/auth 未认证 merge 方法：lua 直接把 params 透传给 uf_client_call，最终在 unifyframe-sgi 的 ufm_popen 命令注入（CVE-2023-34644）](iot-ruijie-eweb-api-auth-merge-jsonrpc-ufm-popen-cmd-injection/) | verified | medium | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
