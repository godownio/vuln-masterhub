---
id: code-analysis-reverse-firmware-huawei-squashfs-mips-emulation
title: 华为魔改 SquashFS 固件解包与 MIPS 服务仿真
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: huawei-squashfs-qemu-mips-emulation
tags:
- firmware
- squashfs
- lzma
- qemu
- mips
- big-endian
- huawei
- iot
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-B
  verified_at: '2026-11-04T18:45:59+08:00'
  notes: 已对照原文与截图核对：0x21A8 包头、qshs magic 修复、sasquatch、qemu-system-mips 启动参数、br0:9 patch 偏移、bindv6only 与 mic→upnp 顺序均一致；未独立执行解包/仿真（未验证点：未在本机复现）
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-huawei-squashfs-mips-emulation/
draft: false
kb_aliases:
- 华为固件解包
- qshs magic
- sasquatch
- MIPS 大端仿真
- HG532 仿真
---

## 一句话结论

华为路由器固件常用“自定义头 + LZMA + magic 被改成 `qshs` 的 SquashFS”，需先修 magic 再用支持 LZMA 的 `sasquatch` 解包；带 IPC 依赖的服务必须在 `qemu-system-mips` 完整虚拟机中按 `mic → upnp` 顺序启动，并处理桥接、IPv6 双栈和设备节点等仿真坑。

## 原理

- 固件不是标准镜像：文件头是自定义的 `0x21A8` 字节，后面跟 LZMA 流和 SquashFS。`binwalk -Me` 能识别并递归提取。
- 华为把 SquashFS 的 magic 从 `sqsh` 改成 `qshs` 以阻止标准工具；SquashFS 3.0 段还用 LZMA 压缩。标准 `unsquashfs` 会报 “Can't find a valid SQUASHFS superblock” 或 “read_block: failed”。
- 修复方法：把文件前 4 字节改回 `sqsh`，再交给 `sasquatch`（支持 LZMA 的 unsquashfs 分支）；或让新版 binwalk 自动识别。
- 目标二进制是 MIPS 32-bit 大端（MSB），且 section header 被剥离；`file` 会显示 “no section header”，IDA 依据 program headers 重建即可分析。
- 服务依赖内核 IPC：`mic` 是消息总线，创建 Unix socket `/var/msgsvr`；`upnp` 等进程作为客户端连接。`qemu-user` 的 chroot 没有真实内核消息队列/CFM，`mic` 会报 `Load cfm failed: 40010004` 后退出，因此必须用 `qemu-system` 完整 VM。
- `mic`/`upnp` 启动时会用 `system()` 执行 `brctl addbr br0:9` 等桥接命令，在 QEMU 的 e1000 网卡上可能触发发送队列超时并断网；把这几条命令字符串替换成 `/bin/true` 可规避。
- 固件 `telnetd` 同时创建 IPv4/IPv6 socket，QEMU 内核默认 `bindv6only=0` 会让 IPv6 bind 与 IPv4 冲突；设为 1 即可。缺少 `/dev/bhal` 时用空文件占位，让服务跳过硬件抽象层初始化。

## 触发条件

- 拿到的是华为/类似厂商的 MIPS 大端路由器固件，标准 `unsquashfs` 解不开。
- 目标服务依赖 `mic`/消息总线、CFM 配置或真实内核 IPC。
- 需要动态调试网络服务，而不只是静态反汇编。

## 利用步骤

1. 用 `binwalk -Me firmware.bin` 提取，确认出现自定义头、LZMA 数据与 SquashFS。
2. 若 SquashFS magic 为 `qshs`，改回 `sqsh` 后用 `sasquatch -d squashfs-root fixed.squashfs` 解包。
3. 用 `file bin/upnp bin/mic` 确认架构（MIPS MSB、no section header）；IDA 按 MIPS big-endian 打开。
4. 启动 `qemu-system-mips -M malta` 完整 VM，转发 SSH、业务端口与调试端口。
5. 把根文件系统打包 scp 进 VM，解包到 `/hg532`，`mount -o bind /dev`、`mount -t proc proc`。
6. patch `mic`/`upnp` 中的 `br0:9` 命令为 `/bin/true`；按需替换 `/bin/cli` 为 `exec /bin/sh` 以便登录。
7. `echo 1 > /proc/sys/net/ipv6/bindv6only`，先 `chroot /hg532 /bin/mic &`，等 `/var/msgsvr` 出现后再启动 `upnp`。
8. 验证端口监听，开始动态测试。

## PoC

```bash
# 1. 解包与修 magic
binwalk -Me HG532_upgrade_packet.bin
python3 - <<'PY'
data = bytearray(open('ECEF9.squashfs','rb').read())
data[0:4] = b'sqsh'
open('ECEF9_fixed.squashfs','wb').write(data)
PY
sasquatch -d squashfs-root ECEF9_fixed.squashfs

# 2. 启动 MIPS 大端完整 VM
qemu-system-mips -M malta -m 256 \
  -kernel vmlinux-2.6.32-5-4kc-malta \
  -hda debian_squeeze_mips_standard.qcow2 \
  -append 'root=/dev/sda1 console=ttyS0' -nographic \
  -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::37215-:37215,hostfwd=tcp::9999-:9999 \
  -device e1000,netdev=net0

# 3. VM 内部署
mkdir -p /hg532 && cd /hg532
tar xzf /tmp/squashfs-root.tar.gz --strip-components=1
mount -o bind /dev /hg532/dev
mount -t proc proc /hg532/proc
echo 1 > /proc/sys/net/ipv6/bindv6only
chroot /hg532 /bin/mic &
# 等 /var/msgsvr 就绪
setsid chroot /hg532 /bin/upnp > /hg532/tmp/upnp.log 2>&1 < /dev/null &
netstat -tlnp | grep 37215
```

```python
# patch br0:9 命令：保持长度，替换为 /bin/true + 空格
# mic 偏移示例: 0x63fc, 0x641c, 0x645c, 0x6490, 0x64b4
# upnp 偏移示例: 0x14618, 0x14638, 0x14678, 0x146a8, 0x146cc
data[off:end] = b"/bin/true" + b" " * (length - len(b"/bin/true"))
```

## 变体与关联

- 变体：其他厂商也会改 SquashFS magic 或用 LZMA/XZ/ZSTD；先看 `binwalk` 输出再决定工具。
- 变体：小端 MIPS/ARM 固件把 `qemu-system-mips` 换成对应 `qemu-system-*`；依赖内核特性的服务同样不应使用 `qemu-user`。
- 变体：桥接冲突不一定是 `br0:9`，其他 `brctl`/`ifconfig` 命令也可能断网，需要逐条定位。
- 关联：[[iot-protocol-huawei-hg532-upnp-deviceupgrade-command-injection]] 是该仿真环境上复现的命令注入漏洞。

## 检测与防御

- 检测（研究侧）：`file` 显示 “no section header”、magic 非标准、LZMA 压缩，都是厂商防分析特征；不要假设标准工具可用。
- 检测（防守侧）：修改 magic/压缩格式只是增加分析成本，不构成安全边界；设备安全仍取决于服务本身的输入校验与权限隔离。
- 防御：固件升级签名校验、关闭不必要的 UPnP/TR-064/telnetd 服务、管理面限制在可信网段。
- 研究注意：仿真环境中的 `/bin/cli` 替换、桥接 patch 只用于本地分析，不要带到生产设备。
