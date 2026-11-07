---
id: web-generic-auth-multi-session-matrix-leakscore
title: 多会话权限矩阵与 LeakScore 四维评分自动化越权检测
type: scenario
domain: web
path: web/generic/auth
technique: multi-session-authz-matrix-leakscore
aliases:
- AccessMatrix
- 权限矩阵越权检测
- LeakScore
- 多会话越权扫描
- cross_validate IDOR
- 自动化越权检测
tags:
- authz
- idor
- automation
- multi-session
- leakscore
- matrix
- privilege-escalation
- testing
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:40:12+08:00'
  notes: 已对照原文核对：N×(N-1)转移、priority权限图、LeakScore四维公式/权重/阈值/单维度门控、cross_validate补偿与智能采样均与原文一致；真实教务系统87接口实验(7发现0误报)及截图可佐证。属检测方法卡，卡片已如实标注为工程启发式、HIGH/MEDIUM需人工复核、小数据量IDOR有低估，未夸大为已证明漏洞；无组件版本，未设versions
---

## 一句话结论

越权证据存在于“不同身份访问同一资源”的响应差异中：把多个角色会话按权限优先级展开为 N×(N-1) 个有序转移，逐接口重放并用敏感字段增量、状态码突变、内容相似度、角色权限距离四维加权评分，可以系统化发现单会话改 ID 无法确认的垂直/水平越权，并用 `cross_validate` 补偿单会话 IDOR 场景。

## 原理

- 单会话改 ID 测的不是越权：同一个 Session 把 `user_id` 改成别人的值后返回 200，可能是后端忽略参数、仍返回自己的数据，也可能是真的返回了别人的数据；不切换身份无法区分。
- 角色不能简化为 Admin/User/Guest 枚举。真实系统里角色是偏序集：A 部门用户可能看到 B 部门数据，C 角色在某功能高于 D、在另一功能低于 D。可用 `priority`（0-100）表达权限级别，并定义 `RoleDistance = |priority_A - priority_B| / 100`。
- 把 N 个会话展开为所有有序对 `(session_i, session_j)`，i≠j。方向有意义：低→高是 escalation（越权提升），高→低是 de-escalation（降级方向的信息泄露），同优先级是 horizontal（水平越权）。每个转移对每个接口发送一次基线请求和一次测试请求。
- **LeakScore** 把二值判定变成连续评分：
  ```text
  LeakScore = 0.3·S + 0.2·D + 0.3·C + 0.2·R
  ```
  - `S`（敏感字段泄露）：只统计测试响应相对基线新增的敏感数据（δ），覆盖身份证、银行卡、SSH 私钥、AWS AccessKey、JWT、GitHub Token、API Key、手机号、邮箱、内网 IP 等；累积加权匹配数除以 K=5 后饱和到 1.0。
  - `D`（状态码突变）：匹配预定义转移即 1.0，否则 0，例如 403→200、401→200、302→200、404→200、500→200、403→201、通用 4xx→2xx。
  - `C`（内容相似度）：`0.4×JSON key Jaccard + 0.3×长度比 + 0.3×共同 key 的值级 LCS`。用 Jaccard 而非 key 数量比，能区分“字段数量相同但重叠少”和“完全一致”。
  - `R`（角色距离）：`|priority_origin - priority_target| / 100`，作为放大器——相同内容相似度在 Admin vs Guest 时比同级用户严重得多。
  - 单维度门控：若 `max(S,D,C,R) ≥ 0.9`，则 `LeakScore = max(LeakScore, 0.6)`，避免“一个维度极强但被其它维度平均掉”。
- 阈值：≥0.8 CRITICAL，≥0.6 HIGH（需人工确认），≥0.4 MEDIUM（需深入分析），<0.4 LOW。阈值与权重来自对 89 个越权类 CVE 的证据类型统计和少量真实案例回溯，属于工程启发式，不是严格概率模型。
- **cross_validate** 解决单会话 IDOR 的盲区：保持 Session 不变，替换请求中的身份参数（`user_code`、`user_id`、`id`、`student_id`、`teacher_id` 等），并把 `R` 替换为固定 0.5（表示平级用户之间的数据穿越），从而让“同身份改资源 ID”也能被评分。
- 会话数增大时用智能采样：`Priority(transition) = RoleDistance × ResourceSensitivity × AuthTypeRisk`，优先执行高权限距离、路径含 admin/user/finance 等敏感词、双方带凭证的转移。

## 触发条件

- 至少有两个不同权限的可用会话，且权限差异体现在 Cookie/Authorization Header/JWT/API Key 等 HTTP 凭证中。
- 已有一份接口清单（Swagger/OpenAPI、前端 JS 提取、爬虫或报错反馈）。
- 接口的授权行为随角色变化，且响应体可比较（JSON/HTML 均可，JSON 效果最好）。
- 目标允许一定量的重复请求；需要限速与退避，避免触发风控或影响业务。
- 测试在授权范围内进行。

## 利用步骤

1. **攻击面发现**：从 Swagger/OpenAPI、SPA 前端 JS 中的 apiUrlKey、错误反馈参数发现等来源汇总接口清单。
2. **配置会话**：为每个角色填写 `auth_type`（cookie/bearer_token/jwt/api_key/header/none）、凭证和 `priority`；至少启用两个会话，Anonymous 作为零权限基线。
3. **生成转移**：对 N 个会话生成 N×(N-1) 个有序对，标记 escalation/de-escalation/horizontal；每个转移对每个接口生成基线请求与测试请求。
4. **执行矩阵**：用各自身份重放同一请求，记录状态码、响应体、响应长度、敏感字段匹配；请求经限流层发送。
5. **计算 LeakScore**：按 S/D/C/R 四维打分，应用单维度门控，输出 CRITICAL/HIGH/MEDIUM/LOW 与结构化 evidence。
6. **人工复核**：HIGH/MEDIUM 必须人工确认；对确认的越权记录目标接口、角色、资源参数、敏感字段数量与影响范围。
7. **补充 cross_validate**：对单会话接口替换身份参数，检测“后端校验了登录但没校验资源归属”的水平 IDOR。
8. **补充 Auth Bypass**：用 Anonymous 尝试路径绕过（`//admin`、`/./admin`、`/../admin`、`/%2e%2e/admin`）和头注入（`X-Forwarded-For`、`X-Original-URL`、`X-Rewrite-URL`），把成功绕过作为 D=1.0 的转移纳入评分。

## PoC

LeakScore 最小实现：

```python
def leak_score(S, D, C, R):
    score = 0.3 * S + 0.2 * D + 0.3 * C + 0.2 * R
    if max(S, D, C, R) >= 0.9:       # 单维度门控
        score = max(score, 0.6)
    if score >= 0.8:
        return "CRITICAL", score
    if score >= 0.6:
        return "HIGH", score
    if score >= 0.4:
        return "MEDIUM", score
    return "LOW", score
```

真实案例评分（Teacher 基线 vs Student 测试，接口 `/api/admin/teacher/evaluate`）：

```text
S = 1.0   # 测试响应比基线新增 156 条身份证号 + 156 条手机号，δ 远超 K=5
D = 0     # 双方均 200
C = 0.92  # JSON 结构一致，评价数组内容高度重复
R = 0.4   # |30 - 70| / 100

LeakScore = 0.3×1.0 + 0.2×0 + 0.3×0.92 + 0.2×0.4 = 0.656
S=1.0 ≥ 0.9 -> 门控 max(0.656, 0.6) = 0.656 -> HIGH
```

水平 IDOR 的 cross_validate：

```text
Student-A 用自己的 JWT 访问 /api/finance/scholarship?user_code=2017002
S = 0.4（新增 Student-B 手机号）
D = 0
C = 0.91
R = 0（同一 Session），cross_validate 替换为 0.5

修正后 LeakScore = 0.3×0.4 + 0 + 0.3×0.91 + 0.2×0.5 = 0.493 -> MEDIUM
```

会话配置示例：

```json
{
  "sessions": {
    "Admin":     {"auth_type": "cookie",       "credentials": {"session": "ADMIN_COOKIE"}, "priority": 100, "enabled": true},
    "Teacher":   {"auth_type": "cookie",       "credentials": {"session": "TEACHER_COOKIE"}, "priority": 70,  "enabled": true},
    "Student-A": {"auth_type": "jwt",          "credentials": {"token": "STUDENT_A_JWT"},     "priority": 30,  "enabled": true},
    "Student-B": {"auth_type": "jwt",          "credentials": {"token": "STUDENT_B_JWT"},     "priority": 30,  "enabled": true},
    "Anonymous": {"auth_type": "none",         "credentials": {},                             "priority": 0,   "enabled": true}
  }
}
```

## 变体与关联

- 变体：`cross_validate` 的身份参数候选包括 `user_code`、`userId`、`user_id`、`id`、`code`、`student_id`、`teacher_id`、`std_code`、`userCode`、`target_user` 等，需要按业务扩展。
- 变体：Auth Bypass 的路径绕过与头注入可并入矩阵，以 Anonymous 为基线、以绕过成功（D=1.0）为主要信号。
- 变体：响应不是 JSON 时，C 维度需改用 HTML 结构/文本相似度；S/D/R 仍适用。
- 变体：大数据量下用智能采样，只跑高 `RoleDistance × ResourceSensitivity × AuthTypeRisk` 的转移；小数据量 IDOR 可能因 S 偏低被系统性低估。
- 变体：A/B 测试、灰度分组会让同一角色不同会话返回不同内容，可能造成误报；本案 20 个非越权端点最高 LeakScore 为 0.45。
- 关联：[[web-generic-auth-jwt-signature-only-role-bypass]] 是该矩阵在真实教务系统中发现的典型垂直越权案例；本卡描述检测方法与评分模型。

## 检测与防御

- 防御：所有敏感接口在业务逻辑前做角色/资源归属校验，返回一致的 403；不要只在登录态或 JWT 验签层放行。
- 防御：对 `/api/admin/**`、教师端、导出、财务等路径做统一权限拦截器；前端隐藏按钮不能替代服务端校验。
- 防御：对同一账号短时间遍历大量资源 ID、跨角色接口高频访问、低权限 token 访问管理路径做告警与限速。
- 防御：敏感字段脱敏与最小必要；即使授权正确，批量身份证/手机号返回也应评估必要性。
- 测试侧：LeakScore 只是线索排序，HIGH/MEDIUM 必须人工确认；不要用“状态码 200”或“内容相似”单独定论。
- 测试侧：矩阵请求可能因缺少 Referer/Origin 被 CSRF 防护误判为 403，需要区分真授权失败与防护误拦。
- 运营：把多会话矩阵纳入常规回归，在角色/接口变更后重跑；保留基线响应与证据字符串，便于复核与报告。
