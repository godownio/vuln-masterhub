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

- [IoT 协议](protocol/README.md) —— MQTT、CoAP、Modbus、Zigbee 等。
- [硬件](hardware/README.md) —— UART/JTAG/SPI、侧信道与故障注入。
- [工业控制](industrial/README.md) —— PLC、SCADA、DCS 与 OT 协议。
- [车联网](vehicle/README.md) —— 车机 ADB/调试口、车载摄像头、蓝牙 HID 与 GNSS 欺骗。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Cisco RV34X 未授权文件上传 + upload.cgi 拼 mv 覆盖 /www/login.html：路由器登录页存储型 XSS（CVE-2023-20073）](iot-cisco-rv34x-unauth-upload-cgi-mv-login-xss.md) | draft | high | 2026-11-07 |
| [D-Link DI-8100 msp_info_htm flag=cmd 命令注入：cmd 参数拼入 system 的 wys 命令](iot-dlink-di8100-msp-info-htm-cmd-command-injection.md) | verified | high | 2026-11-07 |
| [D-Link DI-8100 upgrade_filter_asp path 命令注入：以 http:// 开头的 path 拼入 system 的 wys wget download](iot-dlink-di8100-upgrade-filter-asp-path-command-injection.md) | verified | high | 2026-11-07 |
| [D-Link DIR-605L boa start_wps pin 参数命令注入（CNVD-2026-28535）](iot-firmware-boa-pin-command-injection.md) | verified | high | 2026-11-06 |
| [D-Link DIR-615/645/815 service.cgi REQUEST_URI 参数命令注入（CNVD-2018-01084，固件 1.03 及之前）](iot-dlink-dir615-645-815-service-cgi-event-command-injection.md) | draft | medium | 2026-11-07 |
| [IPC 固件 UDP JSON RPC 命令注入：mp_rate 拼进 system 并覆盖 rtwpriv 回显](iot-ipc-json-rpc-mp-rate-command-injection.md) | verified | high | 2026-11-06 |
| [ipTIME AX2004M /cgi 别名路径绕过 /sess-bin 会话校验（未授权修改管理员密码）](iot-iptime-ax2004m-cgi-alias-path-auth-bypass.md) | verified | high | 2026-11-06 |
| [ipTIME AX2004M 隐藏调试后门 d.cgi：硬编码密钥 aaksjdkfj + cmd 参数 popen 命令执行](iot-iptime-ax2004m-dcgi-debug-backdoor-command-injection.md) | verified | high | 2026-11-06 |
| [Tenda AC15 /goform/telnet 命令注入（CVE-2025-25632）：doSystemCmd 拼接 lan.ip 启动 telnetd](iot-tenda-ac15-goform-telnet-command-injection.md) | verified | medium | 2026-11-07 |
| [小米 AX9000 CVE-2023-26315：xqdatacenter→thrifttunnel→datacenter→plugincenter 认证后命令注入（root RCE）](iot-xiaomi-ax9000-cve-2023-26315-xqdatacenter-plugincenter-command-injection.md) | verified | high | 2026-11-06 |
| [小米路由器 BE10000 Pro xqdatacenter→thrifttunnel→datacenter 链命令注入（认证后 root RCE）](iot-xiaomi-be10000-xqdatacenter-thrifttunnel-command-injection.md) | verified | high | 2026-11-06 |
| [瑞斯康达 MSG2200-T4 智能网关 /vpn/list_base_config.php template 命令注入：反引号写 PHP WebShell](iot-raisecom-msg2200-t4-list-base-config-template-command-injection.md) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
