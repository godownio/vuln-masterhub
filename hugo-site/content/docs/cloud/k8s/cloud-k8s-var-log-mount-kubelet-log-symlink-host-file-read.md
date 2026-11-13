---
id: cloud-k8s-var-log-mount-kubelet-log-symlink-host-file-read
title: K8s Pod 可写挂载宿主机 /var/log + SA 有日志权限：在 /var/log 伪造符号链接，经 kubelet /logs 文件服务器读宿主机任意文件
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-var-log-symlink-kubelet-log-server-host-file-read
tags:
- cloud
- k8s
- container
- escape
- symlink
- kubelet
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V673
  verified_at: '2026-11-13T10:33:15+08:00'
  notes: 已对照原文与图28-34核对：kubelet /logs 用 http.FileServer("/var/log/") 跟随符号链接、Pod 可写挂载 /var/log + SA 日志权限的机理与原文一致；图32/33 的 cath /etc/shadow 与 lsh / 宿主根目录（w00t_w00t_im_a_flag）支持结论。PoC 的 curl 直连 10250 /logs 为示意路径（原文用 lsh/cath 封装），未本地复跑。
url: /docs/cloud/k8s/cloud-k8s-var-log-mount-kubelet-log-symlink-host-file-read/
draft: false
kb_aliases:
- mount-var-log 逃逸
- kubelet /logs 符号链接
- /var/log 挂载逃逸
- cath / lsh
- kube-pod-escape
---

## 一句话结论

当 Pod 以可写方式挂载宿主机 `/var/log`、且其 ServiceAccount 具有 `get|list|watch` 日志（pods/log）权限时，攻击者可在容器内于 `/var/log` 下创建指向宿主机 `/` 的符号链接，再向 kubelet 的 `/logs/...` 端点发请求；kubelet 用 `http.FileServer(http.Dir("/var/log/"))` 提供日志文件时会跟随符号链接，从而把宿主机任意文件（如 `/etc/shadow`、kubelet 令牌/私钥）当作"日志"读回容器。

## 原理

- **kubelet 日志服务**：`kubectl logs <pod>` 实际经 apiserver 向 kubelet 的 `/logs/pods/<path_to_0.log>` 发 HTTP 请求；kubelet 的实现为
  `kl.logServer = http.StripPrefix("/logs/", http.FileServer(http.Dir("/var/log/")))`，即把请求路径映射到宿主机 `/var/log/` 下的文件并直接返回。
- **正常符号链接**：宿主机 `/var/log/pods/<namespace>_<pod>_<uid>/<container>/0.log` 本身就是指向 `/var/lib/docker/containers/<id>/<id>-json.log` 的符号链接，kubelet 依赖文件服务器跟随链接来取日志。
- **攻击面**：Pod 挂载了宿主机 `/var/log` 且可写时，攻击者能在该目录下任意创建符号链接，例如 `/var/log/esc -> /`。之后请求 `/logs/esc/etc/shadow`，`http.FileServer` 打开 `/var/log/esc/etc/shadow`，内核解析符号链接到宿主机 `/etc/shadow`，内容作为响应返回。由于文件服务器不区分"日志"与任意文件，就形成宿主机任意文件读取。
- **权限条件**：K8s RBAC 上 SA 需能通过 apiserver 访问目标 Pod 的 logs 子资源（`pods/log` 的 `get/list/watch`）；kubelet 侧按 webhook 认证该 SA。原文环境用 metarget 的 `mount-var-log` Pod 复现，并提供 `lsh`（宿主机 ls）、`cath`（宿主机 cat）两个封装命令，本质就是带上符号链接路径去请求 `/logs`。
- **为什么成立**：挂载给了容器对宿主机 `/var/log` 的写权限，kubelet 又信任该目录内容并跟随链接；两者叠加使容器内的一个符号链接变成"宿主机任意路径读取器"。

## 触发条件

- Pod 以可写权限挂载宿主机 `/var/log`（hostPath/volume）。
- Pod 的 ServiceAccount 具有日志读取相关 RBAC（`get|list|watch` on `pods/log`），且 kubelet 日志端点可达（经 apiserver proxy 或直接 10250）。
- 攻击者能在容器内创建符号链接并访问 kubelet `/logs` 路径。
- 仅限授权测试。

## 利用步骤

1. 进入 Pod：`kubectl -n metarget exec -it mount-var-log /bin/bash`，确认 `/var/log` 可写。
2. 在 `/var/log` 创建指向宿主机根目录的符号链接：`ln -s / /var/log/esc`。
3. 通过 kubelet 日志端点读取目标文件：请求 `/logs/esc/etc/shadow`（经 apiserver 的 pod logs 子资源或直接 kubelet），返回宿主机 `/etc/shadow`。
4. 用封装脚本批量读取敏感文件：`lsh /` 查看宿主机根目录（原文可见 `.pivot_root*`、`swapfile`、`w00t_w00t_im_a_flag` 等），`cath /etc/shadow` 读 shadow；也可按需读 `/var/lib/kubelet/pods/.../token`、`/home/ubuntu/.ssh/private.key`、`/etc/srv/kubernetes/pki/kubelet.key` 等。
5. 原文给出的完整工具 `kube-pod-escape`（find_sensitive_files.py）会自动创建链接、批量拉取 token 与私钥到 `/root/exploit/host_files/`。

## PoC

```bash
# Pod 内：创建指向宿主根的符号链接（/var/log 为宿主目录的可写挂载）
ln -s / /var/log/esc

# 通过 kubelet /logs 文件服务器读取宿主机文件（示意路径）
curl -k -H "Authorization: Bearer $SA_TOKEN" \
     https://<node-ip>:10250/logs/esc/etc/shadow
# 或经 apiserver 的 pods/log 子资源构造对应日志路径
```

原文实测：`cath /etc/shadow` 返回宿主机 shadow 全文；`lsh /` 列出宿主机根目录及 `w00t_w00t_im_a_flag` 等文件，证明可读宿主机任意路径。

## 变体与关联

- 变体：符号链接可指向任意宿主机路径；若拿到 token/私钥后可进一步读取集群 Secret、SSH 到节点。
- 关联：[[cloud-k8s-k8s-kubelet-unauth]]（kubelet 10250 匿名访问，另一条 kubelet 攻击面）、[[cloud-container-bind-mount-symlink-host-file-read]]（容器 bind mount 共享目录 + 宿主进程读符号链接的同类思路）、[[cloud-container-k8s-workload-config-escape]]（危险挂载总览）。
- 边界：`/var/log` 只读挂载、SA 无日志权限、kubelet 日志端点被禁或做了 `followlinks=false`/root 限制时失效。

## 检测与防御

- **防御**：不要将宿主机 `/var/log`（或 `/` 等敏感目录）可写挂载进 Pod；遵循最小权限，避免给工作负载 `pods/log` 等日志读取权限；kubelet 侧限制 `/logs` 端点或使用只读日志代理。
- **检测**：Pod 内创建 `/var/log/*` 符号链接、kubelet `/logs/` 请求路径包含非常规目录（如 `esc/etc/shadow`）、日志响应中出现 `/etc/shadow` 特征；audit 日志中同一 SA 大量读取 `pods/log`。
- **注意**：该链不需要特权或内核漏洞，纯配置 + RBAC 组合即可读出宿主机敏感文件。
