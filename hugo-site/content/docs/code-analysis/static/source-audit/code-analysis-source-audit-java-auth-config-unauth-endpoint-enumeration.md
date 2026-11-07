---
id: code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration
title: Java 代码审计：从鉴权配置枚举匿名与排除路径，快速定位未授权前台接口
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: java-auth-config-unauth-endpoint-enumeration
tags:
- java
- code-audit
- spring
- shiro
- authentication
- access-control
- unauth
- recon
- sast
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:06:12+08:00'
  notes: 已对照幻灯片第11-20页核对：Shiro filterChainDefinitionMap、SDKAccessControlProperties DEFAULT_EXCLUDE_PATHS、Access-Http Login-Filter、SkyWalking ignore_path搜索锚点一致；属审计方法无单点PoC。
url: /docs/code-analysis/static/source-audit/code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration/
draft: false
kb_aliases:
- 快速找到前台接口
- Shiro filterChainDefinitionMap 匿名路径
- SDKAccessControlProperties 排除路径
- Access-Http Login-Filter
- skywalking ignore_path
- 鉴权白名单枚举
---

## 一句话结论

在 Java/Spring 项目源码审计中，先全局搜索鉴权装配处的“匿名/排除”配置（Shiro 的 `filterChainDefinitionMap`、自定义 SDK 的 `SDKAccessControlProperties` include/exclude、Access-Http 的 `user-config.xml` Login-Filter、SkyWalking 的 `trace.ignore_path` 等），可以直接列出所有跳过认证的路径，再与 Controller/Servlet/WebService 映射对照，快速得到未授权前台接口清单；这比逐个读 Controller 更高效，也容易发现 swagger/actuator/druid/xxl-job 等被默认放行的管理端点。

## 原理

- **鉴权配置是声明式白名单**：Shiro 用 `filterChainDefinitionMap.put("/login", "anon")`、`put("/captcha/**", "anon")` 等规则决定哪些路径走 `anon` 过滤器；被标记为 `anon` 的路径不会进入认证过滤器，直接放行到业务层。
- **自定义 SDK 的 include/exclude**：不少内部框架在 `RequestCheckProperties` 里维护 `includePaths`（默认 `/**`）与 `excludePaths`（默认排除 swagger、actuator、druid 等），请求检查会先判断 exclude；`excludePaths` 即“无需认证”的路径集合。
- **Access-Http Login-Filter**：`user-config.xml` 的 `Login-Filter` 常以通配符列出 `*.js`、`*.css`、`*.png`、`*.html`、`/oauth2/*`、`/swagger-ui.html`、`/v2/api-docs`、`/webjars/*`、`/swagger-resources/*`、`/job/api/*`、`/actuator/**`、`/component-centers` 等排除项；这些路径被过滤器直接放行。
- **SkyWalking ignore_path**：`-Dskywalking.trace.ignore_path=/eureka/**,/actuator/**,/nacos/**` 本身不是鉴权配置，但它暴露了服务内部/管理端点的存在，可作为资产与路由发现的线索。
- **为什么有效**：鉴权逻辑集中在少数配置类/XML 中，配置里的路径就是攻击面清单；框架和脚手架常带默认排除项（swagger、actuator、druid、csrf、webjars、xxl-job），开发者为“方便调试”保留后，生产环境往往直接暴露；多应用架构下每个子应用/网关还可能各有一份配置，汇总后才能得到完整的前台接口面。
- **与路径解析绕过的区别**：本技巧是“按配置枚举放行路径”，不依赖 Shiro/Spring 对 `;`、编码、后缀的解析差异；后者是同一路径在鉴权与路由两侧被解释成不同结果，是另一类问题。

## 触发条件

- 能拿到 Java 项目源码、反编译 jar 或 `WEB-INF` 配置（`web.xml`、`user-config.xml`、`server-config.wsdd`、`application.yml` 等）。
- 项目使用 Shiro、Spring Security、自定义 Filter/Interceptor、Access-Http 等至少一种鉴权装配方式。
- 配置中的匿名/排除路径与真实路由存在映射关系（Controller、Servlet、Axis/CXF WebService、静态资源）。
- 审计目标是找未授权入口；最终危害取决于被放行接口自身的能力（数据读取、配置修改、文件上传、命令执行等）。

## 利用步骤

1. 在 IDE 全局搜索 `/login`，同时查看 Controller 映射与鉴权配置引用，先定位登录/认证装配点。
2. 搜索 `filterChainDefinitionMap`、`filterChainDefinitions`、`anon`、`authc`、`logout`，收集 Shiro 的匿名路径与过滤器顺序。
3. 搜索 `SDKAccessControlProperties`、`RequestCheckProperties`、`includePaths`、`excludePaths`、`DEFAULT_EXCLUDE_PATHS`，收集框架默认排除项与项目自定义排除项。
4. 搜索 `user-config.xml`、`Login-Filter`、`Access-Http`、`exclude`、`urlPatterns`，收集 Access-Http 类网关/过滤器的放行列表。
5. 搜索 `skywalking.trace.ignore_path`、`ignore_path`、`management.endpoints`、`actuator`、`swagger`、`druid`，补充管理/监控端点线索。
6. 把收集到的路径与 `@RequestMapping`/`@GetMapping`/`web.xml` 的 `servlet-mapping`/`server-config.wsdd` 的服务名逐一映射，形成“路径 → 处理方法 → 业务能力”清单。
7. 对清单中的路径做未登录请求验证；重点看返回 200 且包含业务数据/配置/文件操作的接口，排除只返回静态资源或登录页的项。
8. 若路径带通配符（`/**`、`/*`），反推可被匹配的具体 URL；若接口有二次鉴权（Controller/Service 内再校验），继续阅读确认是否可绕过。

## PoC

> 本卡是审计方法，不是单一漏洞 PoC；以下为搜索锚点与配置形态示例。

```text
# IDE / grep 搜索锚点
filterChainDefinitionMap
filterChainDefinitions
anon
SDKAccessControlProperties
RequestCheckProperties
DEFAULT_EXCLUDE_PATHS
excludePaths
Login-Filter
user-config.xml
skywalking.trace.ignore_path
```

```java
// Shiro 配置形态（示意）
filterChainDefinitionMap.put("/login", "anon,captchaValidate");
filterChainDefinitionMap.put("/captcha/**", "anon");
filterChainDefinitionMap.put("/logout", "logout");
```

```text
# SDK 默认排除项形态（示意）
includePaths = /** 
excludePaths = /v2/api-docs, /swagger-resources/**, /swagger-ui.html,
              /v3/api-docs, /swagger-ui/*, /csrf, /webjars/**,
              /actuator/**, /druid/**
```

```text
# 验证：对枚举出的路径做未登录请求，观察是否返回业务数据而非 401/302
curl -i http://target/<excluded-path>
```

## 变体与关联

- 变体：Spring Security 的 `permitAll()`、`antMatchers(...).permitAll()`、`WebSecurityCustomizer` 忽略路径；Spring Boot Actuator 的 `management.endpoints.web.exposure.include=*`；Swagger/Knife4j 的 `doc.html`、`/v2/api-docs`、`/v3/api-docs`。
- 变体：网关层（Spring Cloud Gateway、Zuul）的 `ignoreUrls`/`whiteList` 与后端服务的鉴权配置不一致，可能出现网关放行但后端无鉴权的组合。
- 关联：[[web-java-framework-shiro-static-suffix-anon-pathvariable-bypass]]（利用 Shiro anon 后缀规则与 Spring 路径参数差异绕过鉴权）、[[web-java-framework-shiro-spring-path-auth-bypass]]（分号/编码/trim 路径解析差异）。
- 关联：[[code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow]] 的“鉴权专项”把白名单/未授权接口提取作为独立分析环节；本卡给出具体配置搜索锚点与路径映射步骤。

## 检测与防御

- 审计方：把鉴权配置纳入代码审计清单，按“配置放行路径 → 路由映射 → 业务能力”建立矩阵；对默认排除项逐条确认生产环境是否必要。
- 开发方：默认拒绝（deny by default），只对明确需要的路径放行；生产环境关闭 swagger/actuator/druid/xxl-job 等管理端点或加独立认证；网关与后端使用同一份鉴权规则，避免双份配置漂移。
- 检测：对未登录访问敏感路径返回 200 的请求做告警；定期扫描 `filterChainDefinitionMap`/`excludePaths` 与真实路由的差集。
- 注意：本卡是代码审计/资产发现技巧，severity 标 low；最终风险由被放行接口决定。
