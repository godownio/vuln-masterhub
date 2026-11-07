---
id: cloud-container-docker-cp-copyescape-archive-inclusion-escape
title: CopyEscape：docker cp 归档一致性破坏与解包包含性失效导致宿主机任意文件写入（CVE-2026-17106）
type: scenario
domain: cloud
path: cloud/container
technique: docker-cp-archive-consistency-inclusion-escape
aliases:
- CVE-2026-17106
- CopyEscape
- docker cp 任意文件写入
- 归档一致性破坏
- 解包包含性绕过
- GHSA-hfg8-hc9c-6c3h
tags:
- docker
- container-escape
- docker-cp
- archive
- symlink
- toctou
- arbitrary-file-write
- cve-2026-17106
cve:
- CVE-2026-17106
severity: high
confidence: high
status: verified
affected_versions: Docker 29.2.0（2026-01-26）～ 29.6.2（2026-07-16），28.x 系列最后受影响 28.5.2；go-archive <0.2.2 受影响，0.3.0 修复
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T02:52:50+08:00'
  notes: '已对照原文全文核对：生产端 WalkDir 观察①与 addTarFile Lstat 观察②的归档一致性破坏、消费端 filepath.Join 前缀检查与原始 Linkname 创建符号链接的三缺陷、LD_PRELOAD+inotify 竞态、sudo docker cp 覆写 runc 提权、29.2.0–29.6.2 与 go-archive v0.3.0 os.Root 修复均与原文一致；PoC 未在本机执行（原文引用 issue #52948 与 Imperva 报告）。'
---

## 一句话结论

Docker 29.x 的 `docker cp` 在生产端用 `WalkDir` 与 `addTarFile` 两次观察同一路径，容器进程可在两次观察之间把目录换成绝对符号链接，使归档同时含“`escape -> /usr/bin`”与“`escape/runc`”两条自相矛盾条目；消费端只用 `filepath.Join` 做字符串前缀检查却用原始 `Linkname` 创建符号链接，子条目不重新校验，最终内核跟随链接把文件写到目标目录之外——攻击者获得以运行 `docker cp` 用户权限写宿主机任意位置的能力，`sudo docker cp` 场景下可覆写 `/usr/bin/runc` 提权为 root。

## 原理

- 背景：23.0 起 `docker cp` 改为进程内视图切换（私有挂载命名空间 + pivot_root）+ 客户端字符串检查。容器在复制期间保持运行，daemon 的视图与容器共享同一批 inode，无法阻止容器进程并发修改；CLI 解包在客户端、非特权、跨平台，只能靠字符串前缀检查。
- **生产端（归档一致性被破坏）**：
  ```go
  filepath.WalkDir(walkRoot, func(filePath, f, err) {
      if f.IsDir() { ... }              // 观察①：基于父目录 ReadDir 的 DirEntry 决定是否下钻
      ta.addTarFile(filePath, relFilePath)
  })
  // addTarFile
  fi, err := os.Lstat(path)             // 观察②：重新 Lstat 决定条目类型
  ```
  同一个路径名在两个时刻回答两个问题：遍历决策基于观察①，归档元数据基于观察②。容器在两次观察之间把目录 `escape` 换成指向 `/usr/bin` 的符号链接后，`WalkDir` 仍按旧记录下钻，归档中因此出现：
  ```text
  file.txt/escape       -> /usr/bin      （来自观察②的 Lstat）
  file.txt/escape/runc                    （来自观察①的“目录”决策）
  ```
- **消费端（包含性失效）**：
  ```go
  case tar.TypeSymlink:
      targetPath := filepath.Join(filepath.Dir(path), hdr.Linkname)
      if !strings.HasPrefix(targetPath, extractDir) {
          return breakoutError(...)
      }
      os.Symlink(hdr.Linkname, path)     // 创建时使用原始 Linkname
  ```
  三个叠加缺陷：
  1. 检查的值与使用的值不一致：检查 `filepath.Join("/safe/output/file.txt", "/usr/bin")` 得到的 `/safe/output/file.txt/usr/bin`（以 `/safe/output` 开头，通过检查），实际创建的却是绝对链接 `/usr/bin`；
  2. 字符串前缀不等于路径包含：`/safe/output-elsewhere` 也以 `/safe/output` 开头，同样通过；
  3. 子条目不重新验证：子条目 `escape/runc` 的词法检查只针对文件名文本，前一条目已改变磁盘上该路径的含义，创建子文件时内核直接跟随符号链接。
- 结果：CLI 解包子文件时内核跟随 `escape -> /usr/bin`，写入落到目标目录之外，权限等于运行 `docker cp` 的用户。

## 触发条件

- Docker 29.2.0～29.6.2（使用 go-archive v0.2.0）；28.x 以 28.5.2 为最后受影响版本；或任何直接使用 go-archive <0.2.2 解包的工具。
- 恶意容器可运行进程并修改自己的文件系统（普通容器权限即可）。
- 宿主机/客户端会对该容器执行 `docker cp`（从容器取文件）。
- 攻击者能影响被复制路径下的文件系统结构（能在容器内创建/替换路径）。
- 最终危害取决于运行 `docker cp` 的用户权限：普通用户 → 该用户可写位置；`sudo`/root 自动化 → 宿主机 root。

## 利用步骤

1. 容器内构造可重复的竞态序列：用 `LD_PRELOAD` 拦截器让容器内进程把 `/watched/file.txt` 视为普通文件（访问重定向到隐藏后备文件），而 daemon 遍历到的是可遍历目录树。
2. 在枢轴目录前放置大文件拉长窗口，用 inotify 监控 daemon 打开它的时机，作为“时钟”。
3. 收到信号后执行两次 `rename`，把“目录”切换为“指向 `/usr/bin` 的符号链接”，命中 `WalkDir` 观察①与 `addTarFile` 观察②之间的窗口。
4. 宿主机执行 `docker cp victim:/watched /some/host/dest`，daemon 产出含矛盾条目的归档。
5. CLI 解包：符号链接条目通过前缀检查并按原始目标创建绝对链接；子条目写入时内核跟随链接，写到宿主机 `/usr/bin` 等目录之外。
6. 提权：`sudo docker cp` 或 root 自动化场景下，直接覆写 `/usr/bin/runc`；下一次容器生命周期操作执行 runc 时获得 root 代码执行。macOS 场景可覆盖 shell 启动脚本、`~/Library/LaunchAgents`、SSH 配置等实现持久化。

## PoC

漏洞公开始于 moby issue #52948（Docker 29.4.0 复现）与 Imperva 报告；利用需要竞态时序。最小形态：

```text
容器内:
  1) /watched/file.txt 对容器进程表现为普通文件（LD_PRELOAD 重定向）
  2) inotify 等待 daemon 打开 file.txt 前的“时钟”文件
  3) rename(目录, 临时名); rename(符号链接, 原目录名)   # 目录 -> /usr/bin 链接

宿主机:
  docker cp victim:/watched /tmp/dest
  # 归档: escape -> /usr/bin ; escape/runc
  # 解包后 /usr/bin/runc 被写入攻击者内容
```

归档中的关键矛盾条目：

```text
file.txt/escape      -> /usr/bin     (symlink)
file.txt/escape/runc                 (child)
```

本卡不复述完整 PoC 源码；原文引用 Imperva 报告与 issue #52948。

## 变体与关联

- 变体：同一 CVE 同时影响 Docker Sandboxes 的 `sbx cp` 复制出沙箱场景（Docker Sandboxes 0.38.0 修复）。
- 变体：类似的“先词法检查、后按原始值使用”的模式出现在其他归档解包器中（tar/zip 解包、备份恢复），可用相同思路审计：检查的路径是否等于实际操作的路径。
- 关联：[[cloud-container-docker-cp-symlink-toctou-escape]]（2018 年同一管线的 TOCTOU）；[[cloud-container-docker-cp-chroot-nss-dlopen-rce]]（2019 年 chroot 方案的 NSS 注入）。
- 关联：CVE-2026-41567（容器内解压器按容器 PATH 以 host root 执行）、CVE-2026-41568（挂载点创建时符号链接交换）、CVE-2026-42306（bind mount 目标重定向）为 2026 年 5 月同一簇问题，均修复于 Docker 29.5.1，方向同为 os.Root/openat2。
- 边界：go-archive v0.3.0 起解包改用 `os.Root`（openat2，`RESOLVE_BENEATH`），符号链接节点仍可创建（目标原样保存以兼容镜像），但任何穿过链接的后续操作由内核拒绝逃出根目录，字符串前缀检查被废弃。

## 检测与防御

- 升级：Docker Engine/CLI ≥ 29.7.2（29.7.0 引入 go-archive v0.3.0，29.7.2 修复回归并加 `WithProcSelfFD` 钉住 inode）；Docker Desktop ≥ 4.86.0；Docker Sandboxes ≥ 0.38.0。
- 缓解（无法升级时）：复制前先停止容器，消除生产端竞态的前提条件；避免 `sudo docker cp` 与 root 复制自动化；以最小权限运行 CLI；从不可信容器取数使用一次性隔离环境。
- 加固：将容器取出的文件按不可信输入处理；对复制目标做规范化路径与 inode 级校验。
- 检测：归档中出现“符号链接条目 + 同名子条目”的自相矛盾结构；解包过程中目标目录外出现写入；`/usr/bin/runc` 等系统二进制被非包管理器修改。
- 检测：容器内短时间大量 `rename`/`renameat2`、inotify 监控与 `LD_PRELOAD` 特征；`docker cp` 期间容器文件系统结构高频变化。
- 长期方向：路径包含性由内核在解析时强制（openat2 `RESOLVE_BENEATH`），不要依赖用户态字符串前缀检查。
