---
id: defense-incident-response-lkm-diamorphine-modules-dep-secret-reveal
title: LKM rootkit 应急：modules.dep 修改时间定位 diamorphine，kill -63 + rmmod 揭示 secret_ 前缀隐藏的 UID0 后门服务
type: scenario
domain: defense
path: defense/incident-response
technique: lkm-diamorphine-modules-dep-secret-file-reveal
tags:
- incident-response
- linux
- rootkit
- lkm
- diamorphine
- modules-dep
- systemd
- backdoor-account
- forensics
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V392
  verified_at: '2026-11-09T11:52:33+08:00'
  notes: 已对照原文全文与全部41图核对：modules.dep mtime 19:09:10 与 kernel/diamorphine.ko 19:08:37（图34/35）、默认隐藏模块与 kill -63 0 后 lsmod 可见、rmmod 后 secret_adduser.service 出现（图36/37）、服务 ExecStart=/bin/bash /tmp/secret_adduser.sh 与脚本 useradd -o -m -u 0 -g 0 tomcat（图38/39）、/etc/modules-load.d/diamorphine.conf 开机加载（图40）、/var/log/secure tomcat UID=0 创建于 04-07 02:32 与 last 重启/登录 02:31-02:32 吻合（图32/33）均一致。已把原文式「18:33? 实际为 19:08:37」的草稿措辞修正为明确时间。与 Diamorphine 攻击机制卡、LKM 前缀隐藏卡、watchdog LKM 卡的侧重点不同（本卡为应急检测+处置路径），dedup related/new 成立。未在本机复跑卸载流程。frontmatter 无 sources/source_url/文章ID。
url: /docs/defense/incident-response/defense-incident-response-lkm-diamorphine-modules-dep-secret-reveal/
draft: false
kb_aliases:
- Diamorphine 应急排查
- LKM rootkit 检测
- modules.dep 后门
- secret_ 文件隐藏
- diamorphine.ko
- rmmod 揭示隐藏服务
- secret_adduser.service
---

## 一句话结论

当 Linux 主机上“明明有 UID 0 后门账户/可疑服务却 find 不到对应文件”时，检查内核模块线索：`stat /lib/modules/$(uname -r)/modules.dep` 的异常修改时间与文件尾部多出的 `kernel/diamorphine.ko`，能在 kernel 目录找到 rootkit；Diamorphine 默认隐藏 `secret_` 前缀文件并隐藏自身模块，先 `kill -63 0` 让它在 `lsmod` 中可见、再 `rmmod diamorphine`，被隐藏的 `secret_adduser.service` 与 `/tmp/secret_adduser.sh` 立刻显现——后者用 `useradd -o -m -u 0 -g 0 ... tomcat` 创建 UID 0 后门账户；`/etc/modules-load.d/diamorphine.conf` 是它的开机持久化点。

## 原理

- **LKM rootkit 的隐藏层**：内核模块可劫持 `getdents`/`kill`/模块列表等系统调用，在用户态 `ls`/`find`/`ps`/`lsmod` 之下过滤结果。文件仍在磁盘上，但常规动态工具枚举不到；这与用户态 `LD_PRELOAD` 劫持 `readdir` 的层次不同（后者可用静态 busybox 绕过，前者不能）。
- **modules.dep 是模块加载的索引**：`modprobe` 读取 `/lib/modules/<kernel_version>/modules.dep` 解决模块依赖；该文件由 `depmod` 生成/维护。攻击者把 `diamorphine.ko` 放进 `kernel/` 并执行/触发 depmod 后，文件尾部会出现 `kernel/diamorphine.ko:` 这样的条目，且 mtime 与攻击时间吻合。示例中 modules.dep 修改时间 2023-04-06 19:09:10，`diamorphine.ko` 为 2023-04-06 19:08:37，二者接近。
- **Diamorphine 的可见性开关**：该 rootkit 默认隐藏自身模块；`kill -63 0` 切换模块的隐藏/显示状态（发送一次显示、再发送一次隐藏），`lsmod | grep diamorphine` 可见后即可 `rmmod diamorphine` 卸载。卸载后内核层过滤停止，被隐藏的 `secret_` 前缀文件/服务重新出现在目录中。
- **为什么隐藏的是 `secret_` 前缀**：Diamorphine 的源码按文件名前缀过滤（常见默认 `diamorphine_secret`，样本中配置/编译为 `secret_`）；因此 systemd 单元 `secret_adduser.service` 和脚本 `/tmp/secret_adduser.sh` 在模块加载期间对 `ls`/`find` 不可见，但 `find / -name '*tomcat*'` 之类搜索也会被过滤。
- **后门服务链条**：`secret_adduser.service` 为 `Type=forking`、`ExecStart=/bin/bash /tmp/secret_adduser.sh`、`WantedBy=default.target`；脚本执行 `useradd -o -m -u 0 -g 0 -N -s /bin/bash tomcat` 并 `echo '<password>' | passwd --stdin tomcat`，创建 UID 0（与 root 等价）的 `tomcat` 账户。`/var/log/secure` 中 `useradd[662]: new user: name=tomcat, UID=0, GID=0` 的时间与管理员重启后 SSH 登录时间接近，说明服务在开机时被触发。
- **开机持久化**：`/etc/modules-load.d/diamorphine.conf` 内容为 `diamorphine`，systemd-modules-load 在启动时加载该模块；即使 `.ko` 文件被 rootkit 隐藏，只要该配置还在，重启后模块仍会被加载，隐藏继续生效。清理时必须同时删除配置、模块与隐藏的后门服务。
- **为什么用时间线**：挖矿/后门事件中多个 rootkit、持久化点和账户操作的 mtime 互相印证（ld.so.preload、libsystem.so、bot.service、cron、modules.dep、diamorphine.ko、secret_adduser.service），单点异常容易误判，按时间排序能还原攻击者的操作顺序与“两批攻击者”判断。

## 触发条件

- 已取得 Linux 主机 root/镜像取证权限，怀疑存在内核级 rootkit（进程/文件/模块被隐藏，find 找不到已知后门文件）。
- 目标允许加载内核模块（未强制 Secure Boot/module signing/lockdown），或镜像中保留了 `/lib/modules`、`/etc/modules-load.d`。
- 内核版本与 rootkit 模块匹配；Diamorphine 已被加载（lsmod 可能看不到，需 kill -63 切换）。
- 能够安全卸载模块（业务允许、或离线镜像分析时在隔离环境加载/检查）。

## 利用步骤

1. **固定证据**：记录 `uname -r`、`lsmod`、`/proc/modules`、`/lib/modules/<ver>/modules.dep`、`/etc/modules-load.d` 的当前状态与哈希；避免在原始证据上直接 rmmod（会改变现场），可先离线复制。
2. **查账户与登录时间**：`grep -i useradd /var/log/secure`、`last`、`awk -F: '$3==0' /etc/passwd`，定位 UID 0 的异常账户（示例 tomcat）及其创建时间；对照 last 中的重启/登录时间。
3. **查模块索引**：`stat /lib/modules/$(uname -r)/modules.dep` 看 mtime；`tail -n 20 modules.dep` 找异常条目（如 `kernel/diamorphine.ko`）。
4. **定位模块文件**：`ls -al /lib/modules/$(uname -r)/kernel/`，按 mtime 排序，发现 `diamorphine.ko`；记录大小/哈希/时间戳。
5. **显示并卸载模块**：`lsmod | grep diamorphine`（可能为空）→ `kill -63 0` → 再查 `lsmod`；确认可见后 `rmmod diamorphine`。若模块被引用无法卸载，先排查占用或离线处理。
6. **复查隐藏文件**：卸载后重新 `ls -alt /usr/lib/systemd/system`、`/etc/systemd/system`、`/tmp`，发现 `secret_adduser.service`、`/tmp/secret_adduser.sh` 等；读取 `ExecStart` 与脚本内容，确认后门账户与口令。
7. **清理与验证**：删除后门账户（`userdel -r tomcat`）、systemd 单元、脚本、`diamorphine.ko`、`/etc/modules-load.d/diamorphine.conf`；重启后复查 `lsmod`、modules.dep、秘密前缀文件与 `/etc/passwd`，确认 rootkit 未再加载。
8. **横向排查**：检查是否还有 ld.so.preload/用户态 rootkit、crontab、其他 systemd 服务与 SSH 公钥；结合挖矿进程/矿池连接与 nginx 日志还原入口。

## PoC

```bash
# 1) 模块索引与时间线
uname -r
stat /lib/modules/$(uname -r)/modules.dep
tail -n 20 /lib/modules/$(uname -r)/modules.dep

# 2) 定位可疑 .ko
ls -alt /lib/modules/$(uname -r)/kernel/

# 3) 显示并卸载 Diamorphine
kill -63 0
lsmod | grep diamorphine
rmmod diamorphine

# 4) 卸载后复查隐藏服务/脚本
ls -alt /usr/lib/systemd/system | head
cat /usr/lib/systemd/system/secret_adduser.service
cat /tmp/secret_adduser.sh

# 5) 开机持久化点
ls -al /etc/modules-load.d/
cat /etc/modules-load.d/diamorphine.conf
```

```text
示例时间线：
2023-04-06 19:08:37  diamorphine.ko
2023-04-06 19:09:10  modules.dep（尾部新增 kernel/diamorphine.ko）
2023-04-07 00:08:04  secret_adduser.service（隐藏中，卸载后可见）
2023-04-07 02:32:00  /var/log/secure: new user tomcat UID=0
```

说明：以上为按原文排查过程整理的结构化步骤，未在本机复跑；不同内核/rootkit 配置的隐藏前缀与模块名可能不同。

## 变体与关联

- **rootkit 变体**：其他 LKM rootkit 可能隐藏不同前缀或进程；排查思路相同——modules.dep/`/lib/modules` 时间线、`/proc/modules`、`kill -63` 类控制信号、`/etc/modules-load.d` 与 initramfs。
- **用户态对照**：`/etc/ld.so.preload` + 恶意 `.so`（如 `/etc/libsystem.so`）隐藏进程/文件，可用静态 busybox/strace 绕过；见 [[pentest-persistence-ld-preload-readdir-file-hiding]]。
- **攻击机制**：Diamorphine 的 insmod、kill -64 提权、kill -31 隐藏进程、kill -63 切换可见性见 [[pentest-persistence-linux-diamorphine-rootkit-signal-hide]]；LKM 前缀文件隐藏见 [[code-analysis-reverse-linux-lkm-prefix-file-hiding]]。
- **通用排查**：Linux Web 入侵检查清单见 [[defense-incident-response-linux-web-intrusion-triage-checklist]]；kinsing/kdevtmpfsi 挖矿家族应急见 [[defense-incident-response-linux-ssh-bruteforce-sshd-backdoor-mining-kinsing]]。
- **边界**：模块被占用无法 rmmod、内核禁止卸载模块、或 rootkit 同时 hook 了 `rmmod`/模块列表时，需用 LiveCD/离线镜像或内核内存取证；Secure Boot/lockdown 未开启时攻击者可加载未签名模块。

## 检测与防御

- **检测**：监控 `/lib/modules`、`modules.dep`、`/etc/modules-load.d`、`/etc/modprobe.d` 的变化；auditd 监控 `init_module`/`finit_module`/`delete_module` 与 `insmod`/`rmmod`；定期比对 `lsmod` 与 modules.dep；对 UID 0 新增账户、`secret_` 前缀文件/服务做告警。
- **防御**：启用 Secure Boot + 内核模块签名/lockdown，禁止未签名模块；限制 root 与 CAP_SYS_MODULE；FIM 覆盖 `/lib/modules`、`/etc/modules-load.d`、systemd 目录；使用可信静态工具与内核完整性监控（IMA/eBPF）。
- **应急注意**：先取证后卸载；卸载模块会改变现场但能让隐藏对象暴露，建议在镜像副本或隔离环境操作；清理后重启复查，防止 `/etc/modules-load.d` 残留导致重新加载。
