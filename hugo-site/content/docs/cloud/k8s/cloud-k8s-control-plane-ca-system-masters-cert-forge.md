---
id: cloud-k8s-control-plane-ca-system-masters-cert-forge
title: 控制面 CA 私钥离线伪造 system:masters 客户端证书：绕过 CertificateSubjectRestriction 持久控制集群
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-ca-key-forge-system-masters-client-cert
tags:
- kubernetes
- certificate
- system-masters
- persistence
- ca-key
- cluster-admin
- control-plane
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V644
  verified_at: '2026-11-13T03:36:25+08:00'
  notes: 已对照原文核对：原文后渗透章节描述控制面节点窃取 CA 证书（原文路径写作 /etc/k8s/pki，卡片按标准 /etc/kubernetes/pki 纠正）、system:masters 组无角色/绑定即可完全控制 API、CertificateSubjectRestriction 准入控制器拦截 system:masters 的 CSR、但可用 openssl 等工具离线签发证书实现完全控制，与卡片原理一致；k8s/etcd 证书可控 ETCD 亦有原文依据。原文未给具体命令与版本，卡片将 openssl 签发标注为“示意命令，未针对真实环境验证”，affected_versions 保持为空，符合原文。dedup top 候选（ClusterRoleBinding bind、etcd 未授权、apiserver 匿名、Docker CA 客户端证书、taint/toleration master 逃逸）为不同入口/机制，非同链。未验证点：未在真实集群验证 CA 签发与 system:masters 登录；frontmatter 无 sources/source_url。
url: /docs/cloud/k8s/cloud-k8s-control-plane-ca-system-masters-cert-forge/
draft: false
kb_aliases:
- system:masters 证书伪造
- CA 私钥持久化集群管理
- CertificateSubjectRestriction 绕过
- k8s 客户端证书认证滥用
- kubelet 控制面证书窃取
---

# 一句话结论

攻击者拿下控制面节点并读取 `/etc/kubernetes/pki` 的 CA 证书与私钥（以及 k8s/etcd 证书）后，可在任意机器上用 openssl 离线签发 `O=system:masters` 的客户端证书：`system:masters` 组被内置 ClusterRoleBinding 永久绑定 cluster-admin，不受角色/绑定被删除影响；`CertificateSubjectRestriction` 准入控制器只拦截 CSR API 的证书签发请求，拦截不了离线签发，因此可持久获得整个集群的最高权限。

# 原理

- **客户端证书认证即身份**：k8s apiserver 用客户端 x509 证书认证时，把证书的 `CN` 作为用户名、`O`（organization）作为用户组。任何由集群信任的 CA 签发的证书都会被接受，证书里的组直接决定 RBAC 身份。
- **system:masters 是内置超级组**：K8s 内置的 ClusterRoleBinding 把 `system:masters` 组绑定到 `cluster-admin`。即使攻击者删除了所有可见的角色与角色绑定，该内置绑定仍然存在，组内成员对整个集群拥有完整管理权限，无需任何额外 RBAC。
- **CertificateSubjectRestriction 的作用域**：该准入控制器禁止通过 CertificateSigningRequest API 申请 subject 为 `system:masters` 的证书，但不参与、也无法校验离线 CA 签发。持有 CA 私钥的攻击者用 openssl 在本地签发证书即可绕过。
- **CA 私钥就是信任根**：控制面节点的 `/etc/kubernetes/pki/ca.crt`/`ca.key` 是集群所有客户端与服务端证书的签发者；同时窃取 `etcd` 客户端/服务端证书还能直接对 etcd 认证，读写集群数据，绕过 apiserver 的 RBAC。
- **为什么可持续**：伪造证书不需要在集群里留下 ServiceAccount、Secret 或 RBAC 对象，只依赖信任根；证书有效期由攻击者决定，且改角色/删绑定不影响 system:masters。

# 触发条件

- 已获得控制面节点 root 或主机文件系统访问，可读取 `/etc/kubernetes/pki/ca.key` 与 `ca.crt`（以及 etcd 证书）。
- apiserver 6443 可达且启用客户端证书认证（默认启用）。
- 集群未因 CA 泄露而整体轮换 CA。

# 利用步骤

1. 从控制面节点窃取 `/etc/kubernetes/pki/ca.crt`、`ca.key`；如可读，同时取 `etcd` 相关证书。
2. 在攻击者机器生成私钥与 CSR，subject 设为 `O=system:masters, CN=<任意用户名>`。
3. 用窃取的 CA 离线签发客户端证书（见 PoC）。
4. 用证书构造 kubeconfig 或直接 `kubectl --client-certificate/--client-key/--certificate-authority/--server` 访问 apiserver，验证 `get nodes`、`auth can-i '*' '*' --all-namespaces`。
5. 持久化：保留证书或写入 kubeconfig/Secret；若取得 etcd 证书，可直连 etcd 读取/修改 Secret 等数据以绕过 RBAC。

# PoC

无官方 PoC（原文仅描述“可用 openssl 等工具创建证书”）。最小化离线签发示意（示意命令，未针对真实环境验证）：

```bash
openssl genrsa -out admin.key 2048
openssl req -new -key admin.key -subj "/CN=admin/O=system:masters" -out admin.csr
openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out admin.crt -days 365
kubectl --client-certificate=admin.crt --client-key=admin.key \
  --certificate-authority=ca.crt --server=https://<apiserver>:6443 get nodes
```

# 变体与关联

- Kubeconfig/客户端证书泄露：[[cloud-k8s-kubeconfig-leak-cluster-takeover]]（泄露既有凭据）；本卡是用 CA 私钥伪造新凭据，不依赖既有 kubeconfig。
- 直连 etcd 改数据：[[cloud-k8s-k8s-etcd-unauth]]（未授权路径）；本卡是持 etcd 证书的认证路径。
- 节点 SA 令牌收割：[[cloud-k8s-node-sa-token-harvest-rbac-combination-takeover]]（另一条从工作负载到集群管理的路径）。

# 检测与防御

- 检测：审计日志中 `user.username`/`user.groups` 出现新的 system:masters 成员或陌生 CN；控制面节点文件完整性监控（ca.key 读取/外带）；异常客户端证书的签发与首次使用。
- 检测：etcd 客户端连接与直接键值读写（绕过 apiserver 的行为）；控制面主机上的异常进程与文件访问。
- 防御：严格控制面节点访问与 root 权限，保护 `/etc/kubernetes/pki`（文件权限、主机加固、审计）；定期轮换/使用短生命周期客户端证书；监控并限制 CA 私钥使用；一旦怀疑 CA 泄露，必须轮换整个集群 CA（重建信任）；启用审计并集中收集，防止日志被攻击者清理。
