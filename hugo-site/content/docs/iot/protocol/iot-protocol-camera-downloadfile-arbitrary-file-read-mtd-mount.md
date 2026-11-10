---
id: iot-protocol-camera-downloadfile-arbitrary-file-read-mtd-mount
title: 摄像头 P2P DownloadFile 任意路径下载：读 /proc/mounts 后拉取 /dev/root 与 /dev/mtdblock 镜像挂载提取文件系统
type: scenario
domain: iot
path: iot/protocol
technique: camera-p2p-downloadfile-arbitrary-path-read
tags:
- iot
- camera
- p2p
- protocol
- arbitrary-file-read
- path-traversal
- firmware
- mtdblock
- squashfs
- jffs2
cve: []
severity: high
confidence: high
affected_versions: anyka 平台摄像头固件（Linux anyka 3.4.35 armv5tejl，2021-12-14 构建）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V341
  verified_at: '2026-11-08T20:45:52+08:00'
  notes: 已对照原文核对 DownloadFile /proc/mounts 探测与 /dev/root、/dev/mtdblock5 下载后 mount 提取流程，mounts 内容与截图一致；未复跑真机下载
url: /docs/iot/protocol/iot-protocol-camera-downloadfile-arbitrary-file-read-mtd-mount/
draft: false
kb_aliases:
- DownloadFile 任意文件读取
- 摄像头任意文件下载
- /proc/mounts 定位分区
- mtdblock 镜像挂载
- 在线固件提取
- 块设备当文件下载
---

## 一句话结论

摄像头的 P2P 指令 `DownloadFile` 把 JSON 里的 `path` 直接当作文件路径读取，未限制目录或白名单；攻击者先读 `/proc/mounts` 拿到挂载表，再以「下载普通文件」的方式拉取 `/dev/root`、`/dev/mtdblock5` 等块设备镜像，本地 mount 后即可得到设备的 SquashFS/JFFS2 完整文件系统（含配置、脚本与 `/etc/shadow`），把任意文件读取升级为固件提取。

## 原理

- 指令集里 `DownloadFile` 用于从设备下载文件，参数 `path` 进入打开文件的系统调用，代码没有校验绝对路径、`..`、设备节点或允许目录；因此 `path` 可控即任意文件读取。
- Linux 中块设备也是文件：以 root 运行的服务对 `/dev/root`、`/dev/mtdblockX` 有读权限时，普通 `read()` 就能读出整个分区的原始镜像，不需要额外漏洞。
- `/proc/mounts` 是内核导出的挂载表，可直接读出：`/dev/root` 挂载在 `/`（squashfs ro）、`/dev/mtdblock5` 挂载在 `/usr`（squashfs ro）、`/dev/mtdblock6` 挂载在 `/etc/jffs2`（jffs2 rw）、`/dev/mmcblk0p1` 挂载在 `/mnt`（vfat）等。据此可确定要下载哪些设备节点、各分区是否可写。
- 为什么能提取成功：SquashFS 是只读文件系统镜像，Kali/桌面 Linux 直接 `mount -o loop`（或按类型 `-t squashfs`）即可浏览；JFFS2 分区镜像可用 `-t jffs2` 挂载。块设备镜像完整下载后即等同于离线固件包。
- 该原语本身完整：除固件外，还可读 `/etc/shadow`、`/etc/jffs2/shadow`、启动脚本、Web/CGI、密钥与配置文件，为后续命令注入、口令登录和持久化提供依据。

## 触发条件

- 能与设备的 P2P 控制通道通信（同一网络或知道序列号/地址），并能发送 `DownloadFile` 指令；指令所需的 `pwd` 已通过嗅探/客户端绕过获得，或在设备不校验会话时直接可用。
- 设备上的服务进程以 root（或至少可读目标文件）运行，块设备节点对其可读。
- `/proc` 已挂载（常规 Linux 均满足），目标为 UBI/MTD/eMMC 等块设备布局的嵌入式 Linux。
- 下载链路允许较大文件（整块 flash 镜像可能数十 MB），否则需按分区/分块读取。

## 利用步骤

1. 发送 `{"cmd":"DownloadFile","path":"/proc/mounts"}`，读取挂载表，确认 rootfs、`/usr`、`/etc/jffs2`、`/mnt` 等分别对应哪个设备节点和文件系统类型。
2. 按挂载表下载关键块设备镜像，例如 `/dev/root`（根文件系统）与 `/dev/mtdblock5`（`/usr`）；需要配置分区时再下载 `/dev/mtdblock6`。
3. 在 Kali 建立挂载点，按类型挂载镜像：根镜像 `mount -t squashfs -o loop root /mnt/root`，`/usr` 镜像同理；JFFS2 用 `mount -t jffs2 -o loop mtdblock6 /mnt/etc_jffs2`。
4. 枚举文件系统：`/usr/sbin` 下的启动/配网脚本（如 `station_connect.sh`）、`/etc` 配置、`/etc/jffs2/shadow`、Web/CGI 程序、证书与硬编码口令。
5. 结合 `/proc/mounts` 判断哪些分区可写（rootfs 与 `/usr` 多为只读 SquashFS，`/etc/jffs2` 为可写 JFFS2），为改口令/持久化/植入脚本选择落点。
6. 若 `DownloadFile` 只能读单个文件，可逐个下载配置与脚本；若同时存在删除/格式化类指令（同命令集中的 `DeleteTfFile`、`FormatCard`），注意不要误用破坏性指令。

## PoC

读取挂载表并下载块设备（指令经 P2P 明文协议发送，封装见协议模拟卡）：

```json
{"cmd":"DownloadFile","path":"/proc/mounts"}
{"cmd":"DownloadFile","path":"/dev/root"}
{"cmd":"DownloadFile","path":"/dev/mtdblock5"}
```

本地挂载提取（按实际文件系统类型调整）：

```bash
mkdir -p /mnt/root /mnt/usr
mount -t squashfs -o loop ./root       /mnt/root
mount -t squashfs -o loop ./mtdblock5  /mnt/usr
find /mnt/root -maxdepth 2 -type f | head
cat /mnt/root/etc/jffs2/shadow 2>/dev/null || cat /mnt/root/etc/shadow
```

说明：文中实测下载 `/proc/mounts` 后成功挂载 `/dev/root` 与 `/dev/mtdblock5` 并浏览到完整文件系统；本卡未在本机重放对真机的下载请求。

## 变体与关联

- 变体：除绝对路径外还可尝试 `../../../etc/shadow` 等穿越写法、`/proc/self/environ`、`/etc/config/*`、Web 根目录与证书私钥，按目标文件系统布局选择。
- 变体：其他 IoT 文件下载接口同样常见此问题（例如 ZKTeco 的图片下载文件名穿越）；本卡是 P2P 自定义协议下的任意文件读取 + 块设备镜像提取。
- 关联：[[iot-protocol-ppcs-p2p-plaintext-udp-json-simulator]]（协议封装与模拟客户端）、[[iot-camera-wifi-psk-shell-injection-jffs2-persistence]]（用提取到的脚本定位命令注入）、[[iot-protocol-zkteco-standalonecomm-download-picture-path-traversal]]（同类任意文件读取原语）。
- 边界：`DownloadFile` 有目录白名单、只允许媒体目录，或服务进程降权且设备节点不可读时，本卡不成立；块设备镜像下载被截断/校验失败时无法挂载，需要分块或换分区。

## 检测与防御

- 防御：对 `path` 做规范化并校验必须位于允许目录内，拒绝绝对路径、`..` 和设备节点；下载接口只暴露媒体文件 ID 而非任意路径。
- 防御：服务进程以最小权限运行，`/dev/mtdblock*`、`/dev/root` 权限收紧；禁止业务进程读取 `/proc` 以外的系统信息（可用沙箱/namespace）。
- 检测：下载路径中出现 `/proc`、`/dev`、`/etc`、`shadow`、`mtdblock` 等关键字；异常大的单文件下载；设备侧对块设备节点的读取审计。
- 加固：固件分区签名/加密、rootfs 只读、敏感配置与口令不落盘明文；P2P 通道加密并校验会话。
