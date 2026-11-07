---
id: web-java-framework-spring-actuator-env-config-backup-path
title: Spring Boot Actuator env 未授权泄露环境变量与配置源，定位内部备份文件下载路径
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-actuator-env-unauth-config-leak
tags:
- java
- spring-boot
- actuator
- env
- information-disclosure
- credential-leak
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:15:44+08:00'
  notes: 已对照原文与图06/07核对：application.yml 暴露 management base-path /internal-monitor-xyz123、exposure include env、keys-to-sanitize 含 FLAG；/env 返回 propertySources 中 FLAG 为 ******、SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH 与 system.diagnostic.backup-download-path 为 /api/v3/internal/dev/diagnostics/snapshot/8e2f1a4b.dat；下载快照搜到 flag，均与原文一致。原 affected_versions=Spring Boot 2.2.6.RELEASE 仅为图06 靶场运行版本，非受影响区间，已 --clear。未验证点：PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/java/framework/spring/web-java-framework-spring-actuator-env-config-backup-path/
draft: false
kb_aliases:
- /actuator/env 泄露
- Actuator 环境变量泄露
- propertySources
- keys-to-sanitize
- management.endpoints.web.base-path
- 备份下载路径泄露
---

## 一句话结论

Spring Boot Actuator 的 `env` 端点未授权暴露时，会返回 `propertySources`（系统属性、环境变量、配置文件来源及其原始 key/value）；即使 `keys-to-sanitize` 把 `FLAG` 之类的敏感名脱敏，仍可从中读出内部服务地址、备份下载路径、类路径与配置来源，进而下载本不该公开的诊断快照。

## 原理

- Actuator 的 `/env` 端点用于展示 `Environment` 中的属性来源，响应包含 `activeProfiles` 和 `propertySources` 数组；每个来源（`systemProperties`、`systemEnvironment`、`Config resource 'file [application.yml]'` 等）列出属性名、值和 `origin`。
- 该端点是否可用取决于 `management.endpoints.web.exposure.include`；本题配置为 `include: "env"`，并把 base-path 改为 `/internal-monitor-xyz123`，说明“改路径”不等于“加认证”。
- `management.endpoint.env.keys-to-sanitize` 只按 key 名称把匹配的值替换为 `******`（本题包含 `password,secret,key,token,.*credentials.*,vcap_services,FLAG`），因此 `FLAG` 被脱敏；但 `SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH`、`system.diagnostic.backup-download-path` 等非敏感名称仍原样返回，泄露了内部快照 URL。
- 配置文件来源还会暴露 `management.endpoints.web.base-path`、`spring.application.name`、`java.class.path`、`user.home`、`catalina.base` 等运行时信息，帮助攻击者确认应用结构与可访问路径。
- 本题链路：先通过任意文件读取拿到 `/app/application.yml`，得知 base-path 和备份路径；再访问 `/<base-path>/env` 获取 `SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH`；最后直接下载 `/api/v3/internal/dev/diagnostics/snapshot/8e2f1a4b.dat`，在快照中搜索到 flag。
- 根因是 Actuator 端点默认带有强运维信息能力，生产环境却按“隐藏路径/改名”方式暴露，没有认证、来源限制或最小化 exposure。

## 触发条件

- 目标为 Spring Boot 应用，Actuator 端点可被外部访问。
- `management.endpoints.web.exposure.include` 包含 `env`（或 `*`），且未配置 Spring Security/网关认证。
- base-path 可能被改成非默认值（如 `/internal-monitor-xyz123`），需要通过配置泄露、路径枚举或常见命名猜测发现。
- 应用中存在值得泄露的环境变量、配置项或内部下载地址；即使敏感值被 `keys-to-sanitize` 脱敏，非敏感 key 仍可能指向敏感资源。
- 攻击者能访问返回的下载路径，或该路径只依赖同一 Web 服务的路由。

## 利用步骤

1. 通过配置泄露、源码泄露、错误页或目录扫描确定 Actuator base-path；本题从 `application.yml` 得知 `/internal-monitor-xyz123`。
2. 请求 `GET /internal-monitor-xyz123/env`，确认返回 `propertySources`。
3. 在 `systemEnvironment`、`systemProperties`、`Config resource ... application.yml` 中搜索 `PATH`、`*_URL`、`*_PATH`、`backup`、`download`、`snapshot`、`diagnostic` 等关键字。
4. 找到 `SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH=/api/v3/internal/dev/diagnostics/snapshot/8e2f1a4b.dat` 及对应的 `system.diagnostic.backup-download-path` 配置项。
5. 直接请求该路径下载快照文件；在文件内容中搜索 flag、凭据、内部地址。
6. 继续枚举 `/actuator/configprops`、`/actuator/mappings`、`/actuator/beans`、`/actuator/heapdump` 等端点，扩大信息面。

## PoC

```http
GET /internal-monitor-xyz123/env HTTP/1.1
Host: target
```

响应关键片段（结构示意）：

```json
{
  "propertySources": [
    {
      "name": "systemEnvironment",
      "properties": {
        "SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH": {
          "value": "/api/v3/internal/dev/diagnostics/snapshot/8e2f1a4b.dat",
          "origin": "System Environment Property \"SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH\""
        },
        "FLAG": { "value": "******" }
      }
    },
    {
      "name": "Config resource 'file [application.yml]' via location 'optional:file:./'",
      "properties": {
        "management.endpoints.web.base-path": { "value": "/internal-monitor-xyz123" },
        "system.diagnostic.backup-download-path": { "value": "/api/v3/internal/dev/diagnostics/snapshot/8e2f1a4b.dat" }
      }
    }
  ]
}
```

```bash
curl -s http://target/internal-monitor-xyz123/env | jq '.propertySources[].properties | keys[]'
curl -s -o snapshot.dat http://target/api/v3/internal/dev/diagnostics/snapshot/8e2f1a4b.dat
strings snapshot.dat | grep -i 'flag\|password\|token'
```

## 变体与关联

- **端点变体**：`/actuator/env`、自定义 base-path 下的 `/env`、`/actuator/configprops`、`/actuator/mappings`、`/actuator/beans`、`/actuator/heapdump`。
- **信息变体**：环境变量中的云 AK/SK、数据库连接串、内部服务 URL、JWT 密钥；配置文件来源可暴露 `application.yml` 的物理路径与属性行号。
- **脱敏绕过**：`keys-to-sanitize` 只按 key 名匹配，改大小写、加前缀、把值编码到非敏感 key 中即可绕过；较新 Spring Boot 版本还有 `management.endpoint.env.show-values` 控制。
- **关联**：[[web-java-framework-spring-actuator-heapdump-credential-leak]]（heapdump 提取运行时凭据）；[[web-generic-file-inclusion-java-path-resolve-absolute-override]]（本题获取 `application.yml` 的入口）。
- **边界**：端点启用认证、只暴露 `health/info`、网关层拒绝 `/actuator/*` 或 base-path 不可发现时，本路径失效。

## 检测与防御

- **检测**：外部请求访问 `/actuator/*` 或非默认 base-path 下的 `env`、`configprops`、`heapdump`；响应包含 `propertySources`、`systemEnvironment`、`systemProperties`；随后出现对内部诊断/快照路径的下载。
- **防御**：生产环境不暴露 `env`/`configprops`/`heapdump`；`management.endpoints.web.exposure.include` 只列必要端点（如 `health`）；Actuator 加 Spring Security 认证与网络 ACL，仅管理网可访问。
- **加固**：不要把密钥、内部 URL、备份路径放在环境变量/配置中；必须放置时使用密钥管理服务；对 `keys-to-sanitize` 做更严格的全量脱敏，并避免在响应中返回 `origin` 的物理路径。
