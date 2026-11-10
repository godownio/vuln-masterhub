---
id: web-java-deser-hessian-dubbo-pts-emptyclassarray-filter-bypass
title: Dubbo 2.7.6–2.7.9 Hessian 反序列化补丁绕过：方法参数类型非空使 pts≠EMPTY_CLASS_ARRAY，isGenericCall/isEcho 白名单检查被跳过
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: dubbo-pts-nonempty-genericcall-filter-bypass
aliases:
- Dubbo 补丁绕过
- isGenericCall 绕过
- pts EMPTY_CLASS_ARRAY
- Dubbo 2.7.9 反序列化
- commonTest Object 参数绕过
- DecodeableRpcInvocation 白名单跳过
tags:
- java
- dubbo
- hessian
- deserialization
- patch-bypass
- isgenericcall
- decodeablerpcinvocation
- rpc
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:29:21+08:00'
  notes: 已对照原文与全部22张图片核对：img17 显示补丁在 if (pts == EMPTY_CLASS_ARRAY) 内新增 isGenericCall/isEcho 白名单并 throw，img20/21 显示实例方法 lookupService→methodDescriptor.getParameterClasses() 先赋 pts 非空、白名单分支被跳过，img22 显示 2.7.9 结构未变；与卡内 pts 数据流分析一致。原文未在 2.7.6-2.7.9 实测完整 RCE（仅源码/调试数据流），卡内已标 confidence medium 并注明未复跑，保留为绕过点分析；未填 affected_versions（2.7.6-2.7.9 为补丁分析范围、原文未声明受影响区间），处理正确；无 CVE。
---

## 一句话结论

Dubbo 2.7.6–2.7.8 把 Hessian 反序列化防护加在 `isGenericCall`/`isEcho` 的参数类型描述白名单上，而这两个检查位于 `DecodeableRpcInvocation.decode` 的 `if (pts == DubboCodec.EMPTY_CLASS_ARRAY)` 分支内；当请求的 `desc` 非空且能 `lookupService` 到实际方法时，代码会先执行 `pts = methodDescriptor.getParameterClasses()`，`pts` 已是非空数组，白名单分支整体被跳过——因此目标服务方法只要有参数（尤其是 `Object`），恶意 Hessian 参数仍会被反序列化，补丁并未覆盖该路径（文章指出 2.7.9 判断逻辑仍未变化）。

## 原理

- **`pts` 的来源与默认值**：`decode` 开头 `Class<?>[] pts = DubboCodec.EMPTY_CLASS_ARRAY`；`if (desc.length() > 0)` 时，若方法名命中 `isGenericCall`/`isEcho` 则 `pts = ReflectUtils.desc2classArray(desc)`，否则 `lookupService(path)` 找到 `ServiceDescriptor` 后用 `methodDescriptor.getParameterClasses()` 覆盖 `pts`。
- **白名单检查的位置**：补丁新增的 `if (!RpcUtils.isGenericCall(path, getMethodName()) && !RpcUtils.isEcho(path, getMethodName())) throw new IllegalArgumentException("Service not found: ...")` 位于 `if (pts == DubboCodec.EMPTY_CLASS_ARRAY)` 之内；它只在 `pts` 仍为默认空数组时执行。
- **为什么被跳过**：只要请求能匹配到已注册服务与方法，`pts` 在进入该 `if` 前就已被 `methodDescriptor.getParameterClasses()` 赋成实际参数类型数组（例如 `[Object]`），`pts == EMPTY_CLASS_ARRAY` 恒为 false，于是 `isGenericCall`/`isEcho` 的白名单逻辑根本不会执行。
- **补丁的初衷与盲区**：2.7.6–2.7.8 的 `isGenericCall(parameterTypesDesc, method)` 要求 `$invoke`/`$invokeAsync` 的参数类型描述等于 `Ljava/lang/Object;`（对应 CVE-2020-1948 修复思路），但这是针对泛化调用名的白名单；正常接口方法（如 `commonTest(Object)`）走的是 `methodDescriptor` 分支，不受该白名单约束，而 Hessian 仍会对 `Object` 参数反序列化任意类。
- **文章验证**：在调试构造的 payload 调用链时观察到数据流没有经过 `isGenericCall`；随后对照 2.7.9 的 `DecodeableRpcInvocation.decode` 源码确认结构未变。未在 2.7.6–2.7.9 上实际复跑完整 RCE，结论基于源码数据流分析（本卡 confidence: medium）。

## 触发条件

- Dubbo provider 为 2.7.6–2.7.9（补丁覆盖 2.7.6–2.7.8，2.7.9 逻辑未改）。
- provider 暴露的服务接口存在带参数的方法（参数类型为 `Object` 等宽类型最佳），且方法已注册、`desc` 能匹配到 `methodDescriptor`。
- 攻击者可向 Dubbo 端口发送构造的 RPC 请求（或借 consumer 发送对象参数）。
- 参数反序列化仍使用 hessian2，且未额外启用序列化白名单/安全校验；gadget 类在 classpath 上。

## 利用步骤

1. 枚举/获取目标服务接口，找一个参数为 `Object`（或其他可承载任意对象）的方法，确定 path 与 methodName。
2. 构造 Dubbo 请求时提供非空的 `parameterTypesDesc`（如 `Ljava/lang/Object;`），使 `desc.length() > 0` 且 `lookupService` 能成功解析到该方法。
3. 在 provider 调试：在 `DecodeableRpcInvocation.decode` 的 `pts = methodDescriptor.getParameterClasses()` 与 `if (pts == EMPTY_CLASS_ARRAY)` 处观察，确认 `pts` 已非空、`isGenericCall`/`isEcho` 未被调用。
4. 携带恶意 Hessian 参数（HashMap + Rome/JdbcRowSetImpl 等链），参数反序列化照常触发 gadget。
5. 后续 JNDI/命令执行链与未打补丁版本相同；高版本 JDK 需换本地 classpath 链或 JNDI 绕过。

## PoC

```java
// DecodeableRpcInvocation.decode 关键逻辑（按原文整理，未执行）
Object[] args = DubboCodec.EMPTY_OBJECT_ARRAY;
Class<?>[] pts = DubboCodec.EMPTY_CLASS_ARRAY;
if (desc.length() > 0) {
    if (RpcUtils.isGenericCall(path, getMethodName()) || RpcUtils.isEcho(path, getMethodName())) {
        pts = ReflectUtils.desc2classArray(desc);
    } else {
        ServiceDescriptor sd = ApplicationModel.getServiceRepository().lookupService(path);
        if (sd != null) {
            MethodDescriptor md = sd.getMethod(getMethodName(), desc);
            if (md != null) {
                pts = md.getParameterClasses();   // 此处已把 pts 置为非空
                this.setReturnTypes(md.getReturnTypes());
            }
        }
    }
}
if (pts == DubboCodec.EMPTY_CLASS_ARRAY) {     // 正常方法永远进不来
    if (!RpcUtils.isGenericCall(path, getMethodName()) && !RpcUtils.isEcho(path, getMethodName())) {
        throw new IllegalArgumentException("Service not found:" + path + ", " + getMethodName());
    }
    pts = ReflectUtils.desc2classArray(desc);
}
```

说明：原文未在补丁版本实际复跑完整 RCE；此为源码/调试数据流分析结论。

## 变体与关联

- 变体：与恶意参数链组合（Rome/JdbcRowSetImpl、Groovy、ProxyLazyValue 等）；若方法参数为接口/抽象类型，Hessian 仍可能解析为任意实现类。
- 关联卡片：[[web-java-deser-hessian-dubbo-provider-argument-deserialization-rce]]（<=2.7.6 的完整入口与实测链）、[[web-java-deser-hessian-deserialization-entry-map-put]]（Hessian map.put 触发原理）、[[web-java-deser-hessian-jndi-outbound-chains]]（出网 JNDI 链）。
- 边界：若服务方法参数为不可承载 gadget 的具体类型、或 Dubbo 启用了额外的序列化白名单/安全校验，则本条不成立；补丁版本上的完整 RCE 需自行复现确认。

## 检测与防御

- 不要仅依赖 `isGenericCall`/`isEcho` 方法名白名单；对 Hessian 反序列化启用类白名单（`SerializerFactory` 级或 Dubbo `serialization.security.check`），覆盖所有方法参数类型。
- 服务接口避免使用 `Object`/宽接口作为 RPC 参数类型；必须使用时，在入口对该参数做类型约束或改用安全序列化格式。
- 检测：Dubbo provider 收到 `parameterTypesDesc=Ljava/lang/Object;` 且请求体含 Hessian gadget 类名；同一路径出现 `$invoke` 之外的方法调用异常对象参数；JNDI/LDAP 出站告警。
