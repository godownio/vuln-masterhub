---
id: defense-detection-dinodasrat-linux-host-behavior-ioc
title: DinodasRAT Linux 后门主机侧行为与 IOC：隐藏 .mu 互斥文件、rc.local/init.d 自启动、daemon 重生与设备 ID 心跳
type: scenario
domain: defense
path: defense/detection
technique: dinodasrat-linux-host-behavior-ioc
aliases:
- DinodasRAT Linux 排查
- .mu 互斥文件
- DinodasRAT 自启动
- Linux_%s_%s_%u_V7 设备 ID
- security-microsoft.net
- update.centos-yum.com
tags:
- dinodasrat
- linux
- backdoor
- ioc
- persistence
- daemon
- detection
- malware
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V432
  verified_at: '2026-11-09T19:11:04+08:00'
  notes: 已对照原文及 28 张图核对：.mu 互斥文件格式、/proc/version 与 lsb-release 分支、rc.local/init.d 自启动、daemon(0,0)+'%s d %u'+sleep(5) 重生、ifconfig/ip/dmidecode 构造 Linux_%s_%s_%u_V7、两条硬编码 C2(security-microsoft.net:80、update.centos-yum.com:443)、两个样本 MD5、24 类指令均与截图 02-14 及正文一致；排查命令为合理派生。与 UDP 解密卡为流量/主机两侧、互不重复。原文未给版本，已 clear；dup-scan 未覆盖。
---

## 一句话结论

DinodasRAT Linux 后门启动后会在自身目录创建隐藏互斥文件 `.(程序名)(参数).mu`、按发行版把自身写入 `/etc/rc.local` 或 `/etc/init.d/` 实现开机自启、调用 `daemon()` 后以 `sh -c "<自身路径> d <父PID>"` 反复重生，并用 ifconfig/ip/dmidecode 采集硬件信息构造 `Linux_<日期>_<32位hex>_<随机数>_V7` 设备 ID 周期性心跳；这些固定行为与硬编码 C2 域名可作为主机侧排查与流量狩猎的 IOC。

## 原理

- **单实例互斥**：`GetCurExeFile/GetFileName/GetFilePath` 取自身路径后 `Format("%s./.%s%s.mu", filepath, filename, args)` 拼出隐藏文件路径，再 `ProcessMutex(g_mutex)` 加锁；文件形如 `.testd.mu`（程序 test、参数 d 时）。进程退出后文件可能保留，是稳定落地痕迹。
- **按发行版自启动**：读取 `/proc/version` 判断 Red Hat（v1=1）或 Ubuntu（`ubuntu~18`→3、`ubuntu~16` 再读 `/etc/lsb-release`），`startup()` 据系统类型走 `Startubt18()` 或 `AddRedHat()`，把后门写入 `/etc/rc.local` 或 `/etc/init.d/` 下的启动脚本。
- **守护与重生**：`daemon(0, 0)` 脱离终端后调用 `startup()`，再 `getpid()` 并把自身以 `"%s d %u"`（自身路径 + d + 父 PID）形式通过 `system()` 拉起子进程，主循环每 5 秒执行一次；实际进程树呈现为 `./test`、`sh -c /home/kali/Desktop/test d <pid>`、`/home/kali/Desktop/test d <pid>` 三层，父 PID 参数用于子进程守护/重启。
- **设备指纹**：通过 `ProcessCmd` 执行 `ifconfig`、`ip a`、`link/ether`、`dmidecode` 等采集网卡 MAC/硬件信息，结合 `time()` 与 `rand()%100000`，`Format("Linux_%s_%s_%u_V7")` 生成设备 ID；随后 `MacKControlBuf` 加密该信息循环发送心跳（TCP/UDP 两变体共用）。
- **硬编码 C2**：TCP 样本 `security-microsoft.net:80`；UDP 样本 `update.centos-yum.com:443`（伪装成微软安全站点与 CentOS 更新域名）。
- **样本标识**：带符号 TCP 样本 MD5 `decd6b94792a22119e1b5a1ed99e8961`，去符号 UDP 样本 MD5 `8138f1af1dc51cde924aa2360f12d650`；远控指令共 24 类（DirClass/DelDir/EnumProcess/DealExShell/UninstallMm 等）。

## 触发条件

- 目标为 Linux 主机（Red Hat/Ubuntu 系），且运行过来历不明的 ELF（用户目录、/tmp、伪装成普通程序）；
- 主机上出现隐藏 `.mu` 文件、rc.local/init.d 可疑启动项或 `sh -c "<路径> d <PID>"` 形态的进程链；
- 网络侧存在向 `security-microsoft.net`/`update.centos-yum.com` 等域名的周期外联（TCP 80 或 UDP 443）。

## 利用步骤

（检测/排查步骤）
1. 在可疑 ELF 所在目录及用户目录查找 `.*.mu` 隐藏文件，`ls -la` 结合 `find / -name ".*.mu" 2>/dev/null` 定位。
2. 检查 `/etc/rc.local`、`/etc/init.d/`、`/etc/rc*.d/`、systemd unit 与 crontab 中的可疑路径/命令，确认是否由 `startup()` 写入。
3. `ps -ef` 查找 `sh -c <路径> d <数字>`、同名父子进程与 5 秒周期重启的进程；结合 `/proc/<pid>/cmdline` 与 `exe` 链接确认样本路径。
4. 提取 ELF 字符串/符号：`TcpControl::Connect`、`SendHeart`、`MacKControlBuf`、`qq_crypt/qq_decipher`、`DealExShell`、`UninstallMm`；`.rodata` 中的 C2 域名与 16 字节 key。
5. 抓包确认心跳并使用对应 key 解密（TCP `A101A8EAC010FB120671F318ACA061AF`，UDP `A1A118AA10F0FA160671B308AAAF31A1`），还原设备 ID 与指令。
6. 清理：按 `UninstallMm` 反推的服务/rc.d/init.d/rc.local/配置文件/自身路径逐一清除，重装或恢复镜像更稳妥。

## PoC

无攻击 PoC；排查命令示例：

```bash
find / -name ".*.mu" 2>/dev/null
grep -rnE "(rc\.local|init\.d|rc[0-9]?\.d)" /etc/rc.local /etc/init.d 2>/dev/null | grep -iE "(test|tmp|home)"
ps -ef | grep -E "sh -c .* d [0-9]+"
grep -aE "security-microsoft\.net|update\.centos-yum\.com|Linux_%s_%s_%u_V7|ProcessMutex" <sample>
```

## 变体与关联

- 关联：[[pentest-c2-dinodasrat-linux-c2-protocol-fake-controller]]（协议帧、QQ-TEA 加密与 24 类指令的完整逆向）、[[defense-forensics-dinodasrat-udp-variant-traffic-decrypt]]（UDP 变体 key 与二次封装）。
- 变体：不同版本文件名/参数格式、自启动路径与 C2 域名可能变化；设备 ID 的日期/随机数也会每次运行不同。
- 变体：Windows 版 DinodasRAT 的持久化与 C2 域名不同，需要分别建模。

## 检测与防御

- 主机检测：隐藏 `.mu` 文件、处理 `d <pid>` 参数的进程链、rc.local/init.d 新增启动项、ELF 中 DinodasRAT 符号/字符串与硬编码域名。
- 网络检测：周期心跳、固定长度帧、TCP 首包/ UDP 内层 `0x30` 帧；对 `security-microsoft.net`、`update.centos-yum.com` 做情报阻断与历史回溯。
- 防御：限制普通用户对 /etc/init.d、/etc/rc.local 的写权限；启用文件完整性监控；限制对未知外部地址的出站；发现后按持久化落点全面清理并轮换凭据。
- 取证：保留样本、`.mu` 文件、启动项修改时间与 PCAP，结合设备 ID 做同源聚类。
