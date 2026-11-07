---
id: web-generic-auth-2fa-answer-count-key-presence-bypass
title: 2FA 安全问题校验只比数量且按 key 存在性跳过：增删参数即绕过
type: scenario
domain: web
path: web/generic/auth
technique: 2fa-answer-count-key-presence-bypass
tags:
- auth
- 2fa
- mfa
- logic-flaw
- parameter-tampering
- auth-bypass
- java
- spring
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:08:19+08:00'
  notes: 已对照原文2.1.0节与图19-23核对：verifyAccount 仅比较 entrySet().size()，secQuestion0/1 用 containsKey 短路；payload 77777secQuestion777=doc&77777secQuestion77777=tor 实测 lessonCompleted=true。原文未给组件版本（WebGoat 8.2.2 为靶场环境），未设置 affected_versions。未复现。
url: /docs/web/generic/auth/web-generic-auth-2fa-answer-count-key-presence-bypass/
draft: false
kb_aliases:
- 2FA 安全问题绕过
- verifyAccount 绕过
- 参数数量绕过
- secQuestion 参数绕过
- 缺失 key 跳过校验
- 二次验证逻辑缺陷
---

## 一句话结论

当 2FA 安全问题校验只用“提交答案的条目数等于预存问题数”做数量校验，并且对每个问题仅在“该 key 存在”时才比对答案，攻击者提交两个名字里含 `secQuestion` 的任意参数、同时不提交真正的 `secQuestion0/1`，就能让数量检查通过、答案检查被全部跳过，直接返回验证成功。

## 原理

- 校验代码通常长这样：先 `submittedQuestions.size() != stored.size()` 判数量，再对每个已知 key 做 `if (map.containsKey("secQuestion0") && !map.get("secQuestion0").equals(stored.get("secQuestion0"))) return false;`。
- 第二个判断把小括号里的 `containsKey` 写成了“存在才校验”，而不是“必须存在且相等”。于是 key 不存在时整个条件为 false，不会返回 false，直接把该问题当作通过。
- 解析函数按参数名中的 `secQuestion` 子串收集答案，而不是按固定白名单收集；攻击者可以提交 `77777secQuestion777=a&77777secQuestion77777=b` 这类名字，条目数仍为 2，满足数量校验。
- 两次检查叠加的结果：数量对得上、`secQuestion0/1` 两个 key 不存在、循环没有可校验项，函数返回 true。根因是“存在性校验”和“数量校验”都不能替代“所有必需 key 必须存在且值匹配”。
- 防爆破函数（如统计重复提交）在这里不起作用：攻击者只提交一次任意答案，不触发多次尝试特征。

## 触发条件

- 2FA 安全问题/备用验证码接口把答案放在请求参数中，由服务端解析成 map。
- 校验逻辑只比较 map 大小与预存问题数量，且对每个 key 使用 `containsKey` 短路。
- 解析函数按子串/前缀模糊收集参数，允许攻击者构造额外 key。
- 验证成功后直接把用户标记为已通过 2FA（如写入 session），不再要求密码或其他因子。

## 利用步骤

1. 正常触发一次安全问题验证，抓包确认参数名（如 `secQuestion0`、`secQuestion1`）、用户 id、验证方式。
2. 数一下服务端预存问题数量（通常与正常表单字段数一致，示例为 2）。
3. 删除真正的 `secQuestion0/1`，替换为两个名字中包含 `secQuestion` 的任意参数，保持条目数不变。
4. 提交请求，观察响应是否直接返回 `lessonCompleted: true` / 登录成功，而不是“答案错误”。
5. 若服务端还校验参数名前缀，改用 `secQuestionX`、`secQuestion_1` 等仍能进入 map 的命名；若校验后缀，调整数字位置。

## PoC

```http
POST /auth-bypass/verify-account HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

77777secQuestion777=doc&77777secQuestion77777=tor&jsEnabled=1&verifyMethod=SEC_QUESTIONS&userId=12309746
```

```text
# 预期：不再返回 "Not quite, please try again."
# 而是 {"lessonCompleted":true,"feedback":"...verified the account without actually verifying it..."}
```

## 变体与关联

- 变体：把 `secQuestion0/1` 改成 `SecQuestion0`、`secquestion0` 触发大小写/规范化差异，使 `containsKey` 不命中但数量仍匹配。
- 变体：提交重复参数名（`secQuestion0=a&secQuestion0=b`）让 map 大小与解析结果产生差异；取决于解析器保留首值还是末值。
- 关联：[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（2FA 的 username 篡改与验证码爆破，另一种失效模式）。
- 关联：[[web-generic-auth-servlet-null-role-fail-open]]（同为“缺失值被当作通过”的 fail-open 逻辑）。
- 边界：若代码要求每个预存 key 必须存在（`!containsKey(...) || !equals(...)`）、或直接按预存 key 列表逐项取值、或用常量时间比较且不接受额外参数，该绕过不成立。

## 检测与防御

- 修复：先断言 `submittedQuestions.keySet()` 与预存问题 key 集合完全相等，再逐项比较；任何缺失或多余 key 都拒绝。
- 修复：解析参数时使用固定 key 白名单，不接受名字中任意位置出现关键字的参数。
- 修复：2FA 通过后绑定到服务端会话与具体用户，不在客户端保存“已验证”状态。
- 检测：验证请求中出现 `secQuestion` 但 key 不是预期集合；提交条目数与预存问题数相同但缺少必需 key；同一用户短时间内多次验证失败/异常参数；验证成功但未经过正常挑战流程。
- 加固：验证失败统一返回同一提示与状态码；限制每用户/会话的验证尝试次数；记录完整参数名用于审计。
