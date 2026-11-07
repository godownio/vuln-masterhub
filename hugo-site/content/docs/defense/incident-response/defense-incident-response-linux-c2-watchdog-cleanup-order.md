---
id: defense-incident-response-linux-c2-watchdog-cleanup-order
title: Linux C2 木马清除顺序：先断看门狗与载体，再杀主进程并清理 /dev/shm 残留
type: scenario
domain: defense
path: defense/incident-response
technique: linux-c2-watchdog-cleanup-order
tags:
- incident-response
- linux
- malware
- c2
- watchdog
- ioc
- dev-shm
- rekoobe
- mulu
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V98
  verified_at: '2026-11-05T19:41:01+08:00'
  notes: 已对照原文与图05/14/23核对：看门狗独立 sh 进程、45~95 秒 pgrep 复活、MULU_* 配置经环境/argv 注入、/dev/shm 身份文件与 .cache-*.s/.o、dropper 与 ELF 哈希（MD5 e579.../6668...，SHA-256 702d.../55ceed...）、rekoobe/mulu 家族别名均与原文一致；清除顺序（断 C2→停看门狗→杀主进程→清 /dev/shm→查第二层持久化→观察 5 分钟）为按原文行为推导的处置流程，合理。未验证点：处置命令未在本机执行；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/defense/incident-response/defense-incident-response-linux-c2-watchdog-cleanup-order/
draft: false
kb_aliases:
- Linux 远控木马清除
- 看门狗清除顺序
- MULU/rekoobe 排查
- /dev/shm 木马残留清理
- 杀不死的后门处置
---

## 一句话结论

处置这类多级投放的 Linux C2 木马时，若直接 `kill` 主进程，独立运行的 shell 看门狗会在 45～95 秒内把它重新拉起；正确顺序是先阻断 C2 出站、定位并停止看门狗、删除看门狗脚本与主二进制，再清理 `/dev/shm` 中的节点 ID/锁/缓存文件，最后持续观察数个周期确认没有复活。

## 原理

- **多级结构**：一次投递包含 dropper、主 ELF、shell 回退载荷、python3 回退载荷、python2 回退载荷和看门狗。各组件职责分离：dropper 负责下载与环境适配，主 ELF/脚本负责 C2 通信，看门狗负责进程存活。
- **杀不死的根因**：看门狗是独立 `sh` 进程，主木马被杀不影响它；它在下一轮 `sleep 45 + $$ % 50` 结束后发现 `pgrep -f <BIN>` 找不到进程，就用保存的 `MULU_*` 配置重新 `nohup` 拉起主木马。主木马被删除但看门狗仍在时，看门狗会因为 `[ -x "$BIN" ]` 失败而空转，但攻击者仍可能重新投递；因此必须把看门狗及其脚本载体作为第一优先级清除。
- **C2 配置不在样本里**：主 ELF 通过 `MULU_C2`、`MULU_C2_LIST`、`MULU_TK`、`MULU_ALLOW_ARGS` 环境变量和 argv 接收真实 C2/Token，样本本身硬编码的只是占位值。因此仅删除二进制不够，需检查进程环境、启动脚本和看门狗脚本中的配置。
- **内存盘残留**：载荷和身份文件优先落在 `/dev/shm`，节点 ID/锁文件（`.font-unix-id`、`.font-unix-lock`、`.Xpy-cache`、`.Xpy2-cache`、`.sys-id`、`.user-id` 等）也在这里。磁盘镜像看不到这些文件，必须在线检查内存盘；主机重启会清空 `/dev/shm`，但也可能触发重新投递或看门狗失效，需结合业务判断。
- **验证窗口**：看门狗周期为 45～95 秒，清除后至少观察 2～3 个周期（建议 5 分钟以上）没有进程复活、没有新的出站连接，才能认为进程级清除完成。

## 触发条件

- Linux 主机出现可疑外连、异常 `sh`/python/ELF 进程、或流量设备告警；
- 已获得 root 或与木马同 UID 的处置权限（查看 `/proc/<pid>/environ`、杀进程、删除文件）；
- 能访问主机文件系统与进程表，最好能抓取 `/dev/shm` 与网络连接快照；
- 处置前应尽可能保留现场（进程命令行、环境、网络连接、文件哈希）。

## 利用步骤

1. **隔离与留证**：网络层阻断 C2 出站（防火墙/空路由/代理封禁），避免清除过程中木马重新下载；保存 `ps -eo pid,ppid,user,lstart,cmd --forest`、`ss -tnp`、`ls -la /dev/shm`、`/proc/<pid>/environ` 与样本哈希。
2. **定位进程**：`pgrep -af 'dev/shm|tmp|font-unix|Xpy|dbus_daemon|\.cache-'`；用 `ps --forest` 找父子关系，识别长期存活的 `sh` 脚本进程（看门狗）与其拉起的主木马。
3. **确认配置来源**：读取可疑进程的 `/proc/<pid>/environ`，搜索 `MULU_C2`、`MULU_C2_LIST`、`MULU_TK`、`MULU_ALLOW_ARGS`；检查 `/proc/<pid>/cwd`、`/proc/<pid>/exe` 指向的路径。
4. **先停看门狗**：找到看门狗脚本（常含 `pgrep`、`nohup`、`MULU_`、`sleep $((45`）后，先 `kill` 看门狗及其 `sleep` 子进程，删除看门狗脚本；确认没有第二个看门狗在监控。
5. **再杀主进程**：`kill` 主木马；若进程忽略 TERM 再用 `kill -9`；删除主二进制与回退载荷（`s`、`p`、`p2`）。
6. **清理残留**：删除 `/dev/shm`、`/tmp`、`/var/tmp`、`$HOME` 下的 `.font-unix-*`、`.Xpy*-cache`、`.sys-id*`、`.user-id*`、`.cache-*.s/.o` 及可疑隐藏 ELF/脚本；清理前记录文件名与哈希。
7. **排查第二层持久化**：检查 `crontab -l`、`/etc/cron.*`、`systemd` 单元与 `~/.config/systemd`、`rc.local`、`profile`/`bashrc`、SSH `authorized_keys`，防止看门狗之外还有重启拉起机制。
8. **验证与恢复**：持续观察 5 分钟以上，确认没有进程复活、没有新的 `/agent`、`/agent_sh*` 连接；必要时重启主机后复查 `/dev/shm` 与进程；更新检测规则并轮换可能泄露的凭据。

## PoC

以下为处置命令骨架，仅作防御研究；执行前先留证并评估业务影响：

```sh
# 1) 现场快照
ps -eo pid,ppid,user,lstart,cmd --forest > /tmp/ps.snapshot
ss -tnp > /tmp/ss.snapshot
ls -la /dev/shm > /tmp/shm.snapshot
find /dev/shm /tmp /var/tmp -maxdepth 2 -name '.*' -ls > /tmp/hidden.snapshot 2>/dev/null

# 2) 找可疑进程与看门狗
pgrep -af 'dev/shm|font-unix|Xpy|dbus_daemon|\.cache-'
ps -eo pid,ppid,cmd --forest | grep -E 'sh .*(dev/shm|tmp)' | grep -v grep

# 3) 查看进程注入的 C2 配置（需 root 或同 UID）
tr '\0' '\n' < /proc/<pid>/environ | grep -E 'MULU_(C2|C2_LIST|TK|ALLOW_ARGS)'

# 4) 先停看门狗，再停主进程（示例，需要按实际 PID 调整）
# kill <watchdog_pid> <watchdog_sleep_pid>
# rm -f <watchdog_script>
# kill <implant_pid>

# 5) 清理身份/锁/缓存与载荷
for q in /dev/shm /var/tmp /tmp "$HOME"; do
  rm -f "$q/.font-unix-id" "$q/.font-unix-lock" "$q/.Xpy-cache" "$q/.Xpy2-cache" 2>/dev/null
done
rm -f /dev/shm/.sys-id /dev/shm/.sys-id.lock /dev/shm/.user-id /dev/shm/.user-id.lock 2>/dev/null

# 6) 复查
sleep 300
pgrep -af 'dev/shm|font-unix|Xpy|dbus_daemon|\.cache-' || echo 'no respawn'
ss -tnp | grep -E ':80|:443' || true
```

## 变体与关联

- 变体：只有 shell 轮询载荷（`s`）而没有独立看门狗时，清除重点是进程、脚本与 `/dev/shm` 身份文件；只有 WebSocket 载荷（`p`/`p2`/ELF）时，还要清理其长连接与 `.Xpy*-cache` 节点文件。
- 变体：看门狗由 cron/systemd 定时拉起，删除脚本后仍会从计划任务恢复；必须同时清理计划任务层。
- 关联：[[pentest-persistence-linux-shell-watchdog-pgrep-jitter-relaunch]]、[[pentest-c2-linux-adaptive-dropper-dir-probe-multi-downloader-elf-check]]、[[pentest-c2-linux-http-polling-shell-agent-heartbeat-base64]]、[[pentest-c2-linux-websocket-json-c2-pty-shell]]、[[pentest-c2-linux-implant-anti-forensics-masquerade-node-id]]。

## 检测与防御

- **网络 IOC**：`/agent`（WebSocket 上线）、`/agent_sh`（心跳）、`/agent_sh_poll`（取令）、`/agent_sh_result`（回传），以及 `/.svc/<hex>/<id>/c|s|p|p2` 形式的载荷端点；固定 Chrome 120 Linux UA；同一主机周期性回连。
- **主机 IOC**：`/dev/shm` 下隐藏 ELF/脚本与 `.font-unix-id`、`.font-unix-lock`、`.Xpy-cache`、`.Xpy2-cache`、`.sys-id`、`.user-id`；`/dev/shm/.cache-<pid>-<ts>.s/.o`；环境变量 `MULU_C2`、`MULU_C2_LIST`、`MULU_TK`、`MULU_ALLOW_ARGS`。
- **样本指纹（示例，攻击者可重新编译改变）**：dropper 的 MD5 `e579e7a05f3ca2283d611e5799e1756a`、SHA-256 `702d256533d59c853e9e382c2525b52b7934b023e2e8a97146845473043ae7c1`；ELF 的 MD5 `6668dc294d637a317c0651f25823e477`、SHA-256 `55ceed32d9c4570f79017f3877fe51ffbad2e7ab8f40dfc1a5e99e185286c28f`；家族别名 `rekoobe`/`mulu`（`Backdoor.Linux.Mulu.a`、`ELF:Rekoobe-G`）。
- **检测规则**：审计 `execve` 从 `/dev/shm`、`/tmp`、`/var/tmp` 启动的进程；监控 `pgrep -f` + `nohup` 组合；对 `sh` 脚本长期存活且其子进程为内存盘二进制告警；对 `/dev/shm` 中可执行隐藏文件做定期基线比对。
- **防御**：可写目录 `noexec,nosuid,nodev`；出站白名单；限制解释器与下载器；SELinux/AppArmor；EDR 进程树与文件完整性监控；定期检查 cron/systemd/启动项；保留足够日志以便追溯。
