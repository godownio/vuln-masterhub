---
id: code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd
title: MIPS 路由器固件系统级仿真：QEMU malta + binwalk rootfs + 桥接网络 + httpd
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: qemu-system-mipsel-router-firmware-httpd
tags:
- firmware
- emulation
- qemu
- mips
- router
- binwalk
- bridge
- httpd
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:14:19+08:00'
  notes: 已对照原文与28张图核对：binwalk -Me、netplan br0、QEMU malta 启动参数、scp 旧算法、init.sh 依赖布置、http_conf 与 /httpd -f 均与原文/截图一致。修正一处：Debian squeeze mipsel 本身是 glibc，uClibc 来自固件 rootfs，已改原理表述。原文未标记固件/组件版本，未设置 versions；frontmatter 无 sources/source_url。未验证点：本库未实际解包固件或启动 QEMU。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd/
draft: false
kb_aliases:
- DIR-815 固件仿真
- QEMU mipsel
- malta
- binwalk
- Debian squeeze mipsel
- br0 桥接
- httpd
---

## 一句话结论

把 DIR-815 固件用 `binwalk -Me` 解出 rootfs 后，用 QEMU system-mode 启动 Debian mipsel（malta 内核 + qcow2），配置 br0 桥接网络、scp 传入 rootfs、执行 init.sh 布置 `httpd`/`cgibin` 依赖，再用自定义 `http_conf` 启动路由器 httpd，即可在本地访问 `hedwig.cgi` 复现漏洞。

## 原理

- **固件解包**：`binwalk -Me firmware.bin` 递归提取，得到 rootfs（含 `bin`、`etc`、`lib`、`htdocs` 等）；路由器是 MIPS little-endian，需要匹配的 QEMU 系统镜像。
- **系统级仿真**：`qemu-system-mipsel -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_squeeze_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -nographic -net nic -net bridge,br=br0`；Debian squeeze mipsel 提供旧版内核/SSH 兼容环境（uClibc 库来自固件 rootfs），root/root 登录。
- **桥接网络**：宿主机用 netplan 创建 br0（绑定物理网卡、dhcp4），QEMU `-net bridge,br=br0` 让虚拟机获得与宿主机同网段 IP；`/etc/qemu/bridge.conf` 写 `allow all`。
- **rootfs 布置**：把 rootfs 打包 `tar czvf rootfs.tar.gz ./rootfs/`，`scp -O -o HostKeyAlgorithms=+ssh-rsa` 传入虚拟机；解压后执行 `init.sh`：把 `sbin/httpd`、`htdocs/`、`etc/`、`lib/ld-uClibc*`、`libc*` 等复制到根目录，创建 `phpcgi`/`hnap` 到 `cgibin` 的符号链接。
- **启动 httpd**：`http_conf` 指定 `Interface eth0`、`Address <qemu_ip>`、`Port 8080`、`Alias / -> /htdocs/web`、`Alias /HNAP1 -> /htdocs/HNAP1`、`External /usr/sbin/phpcgi { router_info.xml post_login.xml }` 等；`/httpd -f /http_conf` 启动，访问 `http://<qemu_ip>:8080/hedwig.cgi` 有 XML 回显即成功。
- **为什么需要系统级**：路由器 CGI 依赖 uClibc、httpd、NVRAM/配置等；系统级仿真比 user-mode 更接近真实运行环境，能直接跑 httpd 和 CGI。

## 触发条件

- 有目标路由器固件（binwalk 可解包）。
- 宿主机能安装 QEMU、binwalk、bridge-utils、uml-utilities、docker 等。
- 有匹配架构的 Debian 内核/镜像（如 mipsel malta）。
- 能配置桥接网络/root 权限；目标 CGI 依赖可在 rootfs 中找到。

## 利用步骤

1. 安装工具：`qemu-system`、`qemu-user`、`gdb-multiarch`、`binwalk`（Docker 版）、`bridge-utils`、`uml-utilities` 等。
2. `binwalk -Me firmware.bin` 解包，定位 rootfs。
3. 配置 `/etc/netplan/99-brige.yaml` 创建 br0，`netplan apply`；`/etc/qemu/bridge.conf` 写 `allow all`。
4. 下载 Debian mipsel `vmlinux-3.2.0-4-4kc-malta` 和 `debian_squeeze_mipsel_standard.qcow2`，用 QEMU 启动。
5. 虚拟机内 `ip addr` 查 IP；宿主机 `ssh -o HostKeyAlgorithms=+ssh-rsa root@<ip>` 登录。
6. 打包 rootfs，`scp -O -o HostKeyAlgorithms=+ssh-rsa` 传入；解压后执行 `init.sh`。
7. 传入 `http_conf`，`/httpd -f /http_conf` 启动；访问 `http://<ip>:8080/hedwig.cgi` 验证。
8. 后续静态分析/动态调试/漏洞复现（见关联卡）。

## PoC

```bash
# 解包
binwalk -Me ./firmware.bin

# 桥接
sudo nvim /etc/netplan/99-brige.yaml
# network: version 2, renderer networkd, ethernets: ens33: {}, bridges: br0: interfaces [ens33], dhcp4 true
sudo netplan apply
sudo mkdir -p /etc/qemu && echo "allow all" | sudo tee /etc/qemu/bridge.conf

# 启动 QEMU
sudo qemu-system-mipsel -M malta \
  -kernel vmlinux-3.2.0-4-4kc-malta \
  -hda debian_squeeze_mipsel_standard.qcow2 \
  -append "root=/dev/sda1 console=tty0" \
  -nographic -net nic -net bridge,br=br0

# 传 rootfs / init.sh / http_conf
tar czvf rootfs.tar.gz ./rootfs/
scp -O -o HostKeyAlgorithms=+ssh-rsa -r ./rootfs.tar.gz root@<qemu_ip>:/root/
scp -O -o HostKeyAlgorithms=+ssh-rsa -r ./init.sh root@<qemu_ip>:/root
scp -O -o HostKeyAlgorithms=+ssh-rsa -r ./http_conf root@<qemu_ip>:/

# 虚拟机内
tar -xzvf ./rootfs.tar.gz
cd rootfs && mv ../init.sh ./ && chmod +x ./init.sh && ./init.sh
/httpd -f /http_conf
```

## 变体与关联

- **仿真方式变体**：QEMU system-mode（本题）、QEMU user-mode + LD_PRELOAD 伪造依赖、FirmAE/firmadyne、真实设备。
- **架构变体**：mipsel/mips/arm/arm64；内核/镜像要与固件架构和 libc 匹配。
- **网络变体**：桥接、user-mode 端口转发、tap/tun；CGI 需要固定 IP 时用桥接更方便。
- **关联卡片**：[[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]（user-mode MIPS 仿真）、[[binary-pwn-stack-mips-hedwig-cgi-uid-rop]]（本题漏洞利用）、[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]（QEMU 内核调试）。
- **边界**：固件依赖专有内核模块/NVRAM/硬件外设时，系统级仿真可能需要额外补丁；桥接网络需要 root 且可能影响宿主机网络。

## 检测与防御

- **防守方**：固件发布前做依赖/符号检查；不要在生产固件保留调试 CGI/默认口令；对 httpd/CGI 做权限隔离。
- **研究方**：在隔离网络/虚拟机中仿真，避免桥接暴露到生产网；记录 rootfs 备份，QEMU 镜像做好快照。
- **检测信号**：固件中出现 `cgibin`、`hedwig.cgi`、`httpd`、`/htdocs` 等；调试接口/默认 root 口令。
