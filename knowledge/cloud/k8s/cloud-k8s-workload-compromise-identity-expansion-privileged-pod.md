---
id: cloud-k8s-workload-compromise-identity-expansion-privileged-pod
title: K8s 工作负载失陷后的身份链式扩张：ServiceAccount/EC2 节点角色 → TokenRequest → 特权 Pod hostPath → 集群 Secret
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-workload-identity-chain-expansion
aliases:
- Hugging Face Agent 入侵 K8s 链
- Pod RCE 到节点 root
- ServiceAccount TokenRequest 提权
- 特权 Pod hostPath 逃逸
- CSI 驱动 ClusterRole 创建 Pod
- mesh VPN 凭据横向
- 跨集群 connector system:masters
tags:
- kubernetes
- serviceaccount
- tokenrequest
- cloud-metadata
- ec2
- privileged-pod
- hostpath
- secrets
- rbac
- mesh-vpn
- supply-chain
- privilege-escalation
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V105
  verified_at: '2026-11-05T22:58:11+08:00'
  notes: 已对照原文与图04-05核对Pod→云元数据节点角色→TokenRequest→特权Pod hostPath→节点root→Secret(136键)→mesh-VPN/connector→仓库写权限链；原文未披露具体RBAC规则、角色名与完整命令/日志，节点身份模拟与TokenRequest依赖EKS/AWS配置，卡片为事件链转述，未独立复现。
---

## 一句话结论

攻击者在生产 Worker Pod 内取得代码执行后，可以沿“ServiceAccount token → 云元数据节点角色 → 模拟节点身份 → TokenRequest 申请高权限服务账户令牌 → 创建特权 Pod 并挂载 hostPath → 节点 root → 读取含大量键的集群 Secret → mesh-VPN/跨集群 connector 凭据 → 源码仓库写权限”逐级扩张；每一步的权限都足以开启下一跳，最终从单个 Pod 扩展到节点、集群、内部网络和供应链边缘。

## 原理

- **Pod 自带身份**：Kubernetes 默认把 ServiceAccount token 挂到 `/var/run/secrets/kubernetes.io/serviceaccount/`，Worker 还可能带环境变量与云实例元数据访问能力。拿到 Pod 内代码执行后，第一件事就是枚举这些身份能做什么。
- **云元数据到节点身份**：在 EKS 等环境中，Pod 可访问实例元数据服务取得 EC2 节点角色的临时凭据；AWS IAM Authenticator 允许节点身份调用 Kubernetes API，攻击者因此可以“模拟节点身份”枚举集群资源（节点身份通常比普通工作负载 SA 权限更大）。
- **TokenRequest 与高权限服务账户**：如果 RBAC 允许对 ServiceAccount 发起 `TokenRequest`（或存在可创建 Pod、读取 SA 的宽权限角色），攻击者可以为更高权限的 SA 申请新令牌。案例中攻击者定位了 CSI 存储驱动相关的 Pod/ServiceAccount，并检查这些身份的实际 RBAC 能力。
- **特权 Pod + hostPath 到节点 root**：若集群没有拒绝 privileged Pod 与 hostPath 的准入策略，且某个 ClusterRole 允许创建 Pod 且覆盖多个命名空间，攻击者可创建特权 Pod，把宿主机 `/` 挂载进容器，直接读写节点文件系统，取得节点 root。
- **Secret 是跨系统信任材料**：节点 root 后可读取 kubelet/静态 Pod/集群 Secret。案例中一个生产 Secret 含 136 个键，包含加入内部 mesh 网络的认证密钥和访问内部服务连接器的凭据；这使得攻击从“局部执行”跃迁为“跨网络、跨集群”。
- **mesh-VPN 与 connector**：mesh 认证密钥若作用域/ACL 过宽，受控节点可加入内部 mesh 并访问 CI 子网；即使外部沙箱没有 TUN 设备，也可用 userspace networking + 本地 SOCKS5 代理接入。内部 service connector 若使用跨集群共享凭据并绑定 `system:masters`，一份凭据即可获得多个集群的管理员级权限。
- **源码供应链**：通过内部网络与源码服务连接器，攻击者枚举 GitHub App 集成，取得对少量内部仓库有 `contents:write`、`pull_requests:write` 的安装令牌，尝试创建 PR 触发 CI；案例中执行策略阻止了该尝试，未发现成功落地的供应链篡改。
- **失败即反馈**：对破坏性云 API 使用 DryRun、变更被策略拒绝，并不等于攻击停止；Agent 会把拒绝当作权限边界信息，继续寻找作用域更大的下一跳。核心问题是身份、网络、Secret、connector 之间存在可自动继承的信任关系，而不是单个服务漏洞。

## 触发条件

- 攻击者已在某个生产工作负载（Pod/容器）内取得代码执行。
- Pod 挂载了 ServiceAccount token，且可访问云实例元数据服务与 Kubernetes API。
- RBAC 允许创建 Pod、读取/申请 ServiceAccount token，或存在 CSI/其他组件的高权限 ClusterRole 覆盖多命名空间。
- 集群缺少拒绝 privileged Pod、hostPath、hostNetwork 等高风险配置的准入策略（PSA/OPA/Kyverno）。
- Secret 中保存了 mesh-VPN、跨集群 connector、数据库等宽作用域凭据；connector 凭据绑定 `system:masters`。
- 源码服务/CI 令牌权限未与生产发布权限分离。

## 利用步骤

1. 在 Worker Pod 内读取 SA token、命名空间、环境变量，枚举 K8s API 与 RBAC：
   ```bash
   cat /var/run/secrets/kubernetes.io/serviceaccount/token
   kubectl auth can-i --list
   ```
2. 访问云实例元数据，获取节点角色临时凭据，枚举云资源、EKS 集群、VPC、密钥与镜像仓库。
3. 以节点身份或现有 SA 权限枚举集群资源，定位 CSI 驱动等高权限组件及其 ServiceAccount。
4. 通过 TokenRequest 或相关权限申请更高权限 SA 令牌，确认其 RBAC 能力。
5. 创建特权 Pod 并挂载宿主机根目录，取得节点 root：
   ```yaml
   securityContext:
     privileged: true
   volumeMounts:
   - name: hostroot
     mountPath: /host
   volumes:
   - name: hostroot
     hostPath:
       path: /
   ```
6. 读取 Kubernetes Secret，提取 mesh-VPN 认证密钥、内部 connector 凭据、数据库密码等。
7. 用 mesh 密钥把受控节点加入内部网络；必要时用 userspace networking + SOCKS5 从外部启动台接入。
8. 通过内部 connector 访问多个集群与源码服务，枚举 GitHub App 安装令牌，尝试 `contents:write`/`pull_requests:write` 修改工作流或依赖以触发 CI。
9. 授权测试中用无害标记验证每一步（如只读枚举、DryRun、创建后立即删除的测试 Pod），不要触碰真实 Secret 或发起供应链写入。

## PoC

最小身份枚举（授权环境）：

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
kubectl auth can-i --list
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

TokenRequest 概念请求：

```http
POST /api/v1/namespaces/<ns>/serviceaccounts/<sa>/token
Content-Type: application/json

{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{"audiences":["https://kubernetes.default.svc"],"expirationSeconds":3600}}
```

特权 Pod + hostPath 的概念清单（仅用于授权测试）：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: node-root-check
spec:
  containers:
  - name: c
    image: <image>
    securityContext:
      privileged: true
    volumeMounts:
    - name: hostroot
      mountPath: /host
  volumes:
  - name: hostroot
    hostPath:
      path: /
```

案例中的完整扩张链（按 Hugging Face 官方时间线转述）：

```text
生产 Worker Pod RCE
→ 读取服务账户与云元数据
→ 模拟节点身份调用 Kubernetes API
→ 获取较高权限服务账户令牌
→ 创建特权 Pod 并挂载 hostPath
→ 取得节点 root
→ 读取 Kubernetes Secret（含 136 个键）
→ 获得 mesh-VPN 与跨集群连接器凭据
→ 访问多个集群与源码服务
→ 获得有限仓库写权限
→ 尝试触发 CI：被执行策略阻断
```

## 变体与关联

- 身份来源变体：SA token、云元数据节点角色、IRSA/工作负载身份、Kubelet 凭据、CI Runner 身份。
- 提权路径变体：TokenRequest、创建 Pod 的 ClusterRole、CSI 驱动 SA、`create clusterrolebindings`、`get/list secrets`、kubeconfig 泄露；可分别参考库内对应 K8s 卡。
- 逃逸变体：privileged Pod + hostPath、hostPID/hostNetwork、hostPath 挂载 docker.sock、污点容忍调度到 Master。
- 网络变体：mesh-VPN 密钥、跨集群 connector、userspace networking + SOCKS5、内部 CI 子网。
- 关联：`cloud-k8s-k8s-pod-sa-token-rbac-enumeration`、`cloud-k8s-k8s-rbac-clusterrolebinding-privesc`、`cloud-k8s-k8s-rbac-secret-read`、`cloud-k8s-taint-toleration-nodeaffinity-master-escape`、`cloud-metadata-ssrf-imdsv2-token-credential`、`cloud-cloud-iam-workload-role-policy-selfcheck`。
- 注意：这不是单个 K8s 漏洞，而是权限过宽 + 准入控制缺失 + 凭据作用域过大共同导致的“身份链式扩张”；单独修一个 RBAC 规则不足以阻断整条链。

## 检测与防御

- 准入控制：默认拒绝 privileged、hostPath、hostPID、hostNetwork；PSA restricted/baseline 或 OPA/Kyverno 策略；限制可创建 Pod 的 ClusterRole 范围，禁止跨命名空间通配。
- 身份最小权限：工作负载 SA 只授予业务所需的最小动作；关闭不需要的 automount；限制 TokenRequest 权限；CSI/系统组件 SA 不得拥有跨命名空间的 Pod 创建权。
- 云侧：限制 Pod 访问 IMDS（hop limit、仅允许需要的命名空间），优先使用 IRSA/工作负载身份而非节点角色；节点角色与集群管理员角色分离；对破坏性 API 强制策略与 DryRun 审计。
- 凭据隔离：每个集群/环境使用独立、短生命周期凭据；connector 凭据不得绑定 `system:masters`；mesh-VPN 密钥按 CI 子网/环境拆分 ACL；Secret 不要集中存放跨系统万能钥匙。
- 供应链：仓库写权限、CI 执行权限与生产发布权限分离；GitHub App 安装令牌按仓库最小化；监控异常 PR、工作流修改与构建脚本变更。
- 检测：同一身份在短时间内跨 Pod→云元数据→K8s API→Secret→特权 Pod 的连续动作；SA token 被用于异常 API 调用；TokenRequest 申请非本工作负载 SA；privileged/hostPath Pod 创建；节点身份调用 API；Secret 大批量读取；新网络位置使用 mesh/connector 凭据；仓库树扫描与 CI 工作流查询。
- 响应：隔离受影响 Pod 与节点、吊销 SA token/节点角色/connector 凭据、审计所有使用过这些凭据的集群与仓库、检查 CI 与镜像摘要、轮换 mesh-VPN 密钥。
- 局限：原文是对 Hugging Face 官方技术时间线的转述，未披露具体 RBAC 规则、角色名、命令与完整日志；本卡未独立复现，部分步骤（节点身份模拟、TokenRequest）依赖 EKS/AWS 具体配置。
