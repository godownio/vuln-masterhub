# Kubernetes

## 这层是什么

集群、RBAC、Admission、逃逸与供应链。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [etcd 2379 未授权直接读取集群 Secret 与状态](cloud-k8s-k8s-etcd-unauth.md) | verified | high | 2026-11-04 |
| [Helm Chart.lock 符号链接跟随写入任意文件：恶意 chart 经 cron 脚本实现代码执行（CVE-2025-53547）](cloud-k8s-helm-chart-lock-symlink-follow-cron-rce.md) | verified | medium | 2026-11-07 |
| [ingress-nginx Admission Webhook 借 mirror 注解与 Ingress UID 注入 nginx 配置，ssl_engine 加载 .so 实现 RCE](cloud-k8s-ingress-nginx-mirror-uid-config-injection.md) | verified | medium | 2026-11-08 |
| [ingress-nginx spec.path 双引号逃逸注入任意 nginx 指令（CVE-2026-3288）](cloud-k8s-ingress-nginx-spec-path-quote-config-injection.md) | verified | high | 2026-11-05 |
| [K8s apiserver 匿名访问与 8080 不安全端口利用](cloud-k8s-k8s-apiserver-anonymous-access.md) | verified | high | 2026-11-04 |
| [K8s 审计 webhook 未鉴权：向统一审计平台提交伪造的 audit.k8s.io/v1 EventList 注入虚假日志](cloud-k8s-audit-webhook-forged-eventlist.md) | verified | medium | 2026-11-07 |
| [K8s 审计日志 sourceIPs 污染：X-Forwarded-For 批量伪造 + X-Real-IP 单 IP，真实来源仍在末尾](cloud-k8s-audit-sourceips-xff-xrealip-spoof.md) | verified | high | 2026-11-07 |
| [K8s 工作负载失陷后的身份链式扩张：ServiceAccount/EC2 节点角色 → TokenRequest → 特权 Pod hostPath → 集群 Secret](cloud-k8s-workload-compromise-identity-expansion-privileged-pod.md) | verified | high | 2026-11-05 |
| [K8s 服务器检材业务重建：Dashboard Token、PVC 宿主机路径与离线镜像导入](cloud-k8s-forensic-cluster-workload-rebuild.md) | verified | medium | 2026-11-06 |
| [K8s 污点容忍 + nodeAffinity 将恶意 Pod 调度到 Master 并逃逸](cloud-k8s-taint-toleration-nodeaffinity-master-escape.md) | verified | high | 2026-11-05 |
| [Kubeconfig 泄露接管 K8s 集群并创建持久化后门](cloud-k8s-kubeconfig-leak-cluster-takeover.md) | verified | high | 2026-11-05 |
| [kubectl proxy 绑定 0.0.0.0 导致未授权 K8s API 访问与 Pod 创建](cloud-k8s-kubectl-proxy-exposed-unauth-api.md) | verified | high | 2026-11-05 |
| [Kubelet 10250/10255 未授权访问获取容器信息与执行命令](cloud-k8s-k8s-kubelet-unauth.md) | verified | high | 2026-11-04 |
| [Kubernetes Dashboard enable-skip-login 且绑定 cluster-admin 导致未授权接管集群](cloud-k8s-dashboard-skip-login-cluster-admin-takeover.md) | verified | high | 2026-11-05 |
| [Kyverno Policy apiCall 跨命名空间越权：CVE-2026-22039 用准入控制器 SA 访问任意 K8s API](cloud-k8s-kyverno-policy-apicall-cross-namespace-privesc-cve-2026-22039.md) | verified | high | 2026-11-06 |
| [Pod 内 ServiceAccount Token 权限枚举与利用路径判定](cloud-k8s-k8s-pod-sa-token-rbac-enumeration.md) | verified | high | 2026-11-04 |
| [从 MySQL load_file 读取 Pod 内 ServiceAccount Token，直接 kubectl 接管集群并用 hostPath Pod 逃逸](cloud-k8s-mysql-loadfile-sa-token-kubectl-hostpath-escape.md) | verified | high | 2026-11-08 |
| [利用 create clusterrolebindings 权限绑定 cluster-admin 接管集群](cloud-k8s-k8s-rbac-clusterrolebinding-privesc.md) | verified | high | 2026-11-04 |
| [利用 get/list secrets 权限读取 Secret 凭据横向移动](cloud-k8s-k8s-rbac-secret-read.md) | verified | high | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
