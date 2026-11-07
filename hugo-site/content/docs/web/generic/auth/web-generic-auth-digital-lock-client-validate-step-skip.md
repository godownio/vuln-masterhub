---
id: web-generic-auth-digital-lock-client-validate-step-skip
title: 多步数字锁前端校验绕过：调用暴露的 validateCode() 取答案并直接提交 step3
type: scenario
domain: web
path: web/generic/auth
technique: digital-lock-client-validate-step-skip
tags:
- web
- auth
- client-side
- multi-step
- validation-bypass
- javascript
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:47:50+08:00'
  notes: 已对照原文 ezDecryption 段及 img/27、img/28 核对：window.systemModule.validateCode() 返回 panshi2oZ5、POST /stage/digital-lock/check 的 step3 请求与 success/flag 响应均与截图一致；修正 PoC 的 Content-Length 为 38（原文截图为 32，但 body 实为 38 字节）并注明；未对真实目标执行。
url: /docs/web/generic/auth/web-generic-auth-digital-lock-client-validate-step-skip/
draft: false
kb_aliases:
- 数字锁绕过
- 多步验证跳过
- validateCode
- systemModule
- 前端步骤绕过
- digital-lock step3
- client-side state machine bypass
---

## 一句话结论

多步数字锁/验证流程如果把校验逻辑和答案放在前端，且最终接口只接收 `{"step":"step3","answer":"..."}` 而不在服务端维护步骤状态，攻击者就可以在浏览器控制台直接调用暴露的 `window.systemModule.validateCode()` 得到正确答案，跳过前两步、直接提交最终步骤拿到结果。

## 原理

- **前端状态机**：多步验证通常由前端 JS 维护 `step1 → step2 → step3` 的流程，页面只负责收集/校验每一步的输入；如果答案由前端函数计算或直接内嵌，攻击者可以通过 DevTools 读取/调用这些函数，绕过 UI 限制。
- **服务端只校验最终答案**：示例接口 `POST /stage/digital-lock/check` 接收 `step` 与 `answer`，只要 `answer` 与预期一致就返回成功/flag；它没有校验“当前会话是否已完成 step1/step2”，也没有把步骤进度绑定到服务端会话或一次性 token。因此把 `step` 直接设为 `step3`、带上正确答案即可。
- **答案不是秘密**：`window.systemModule.validateCode()` 是页面暴露的全局对象方法，调用后返回 `panshi2oZ5`；即使它被混淆，浏览器运行时仍能调用并观察返回值。前端校验只能提高操作成本，不能作为安全边界。
- **为什么成立**：任何需要浏览器执行的校验，其输入、算法和预期结果都必须在客户端可见；服务端若不独立验证“步骤顺序 + 会话状态 + 一次性凭证”，客户端就可以跳过。
- **边界**：若服务端用会话保存 step 进度、每步下发一次性 token 并在下一步校验、最终答案由服务端生成且不在前端出现，则直接提交 step3 会失败；此时仍可通过正常完成前两步、或调用前端函数辅助通过，但需要服务端状态配合。

## 触发条件

- 目标为多步验证/数字锁/分步表单，前端 JS 负责步骤切换与校验。
- 页面暴露了可调用的校验函数/对象（如 `window.systemModule.validateCode`），或答案能在 JS/网络响应中找到。
- 最终接口接受客户端提交的 `step`/`answer`，且不校验前序步骤是否完成、不绑定一次性会话状态。
- 攻击者能打开 DevTools 或直接构造 HTTP 请求。

## 利用步骤

1. 打开目标页面，查看 Network/JS，定位多步流程的步骤字段（如 `step1/step2/step3`）与最终提交接口（如 `/stage/digital-lock/check`）。
2. 在 Sources/Console 搜索 `validateCode`、`systemModule`、`step`、`answer` 等关键词；列出页面暴露的全局对象与方法。
3. 在 Console 调用 `window.systemModule.validateCode()`（或类似方法），记录返回值；必要时调用 `getSystemInfo()` 等辅助方法查看步骤/提示。
4. 直接在 Repeater/Console 构造最终步骤请求：`{"step":"step3","answer":"<返回值>"}`，观察是否返回成功/flag。
5. 若失败，尝试修改 `step` 字段、跳过中间步骤、复用前一步的 token，或在 Console 调用其它校验函数；也可正常走完前两步后再调用最终接口对照。
6. 记录请求/响应与 JS 调用结果作为证据；评估在真实业务中可跳过的步骤（如支付确认、身份复核）。

## PoC

浏览器 Console（原文）：

```javascript
// 直接调用页面暴露的校验方法
window.systemModule.validateCode();
// => "panshi2oZ5"
```

最终步骤请求（原文 Burp）：

```http
POST /stage/digital-lock/check HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 38
Origin: http://target

{"step":"step3","answer":"panshi2oZ5"}
```

响应：

```json
{
  "success": true,
  "message": "恭喜！你成功破解了密码系统！",
  "flag": "flag{d1g1t41_l0ck_br34k3r_2025}",
  "completed": true
}
```

说明：原文只给出 Console 调用与最终请求两张截图，未展示 step1/step2 的具体校验逻辑；以上按可观察到的接口与返回值整理。原文 Burp 截图显示 `Content-Length: 32`，但该 JSON body 实际为 38 字节（截图头未随编辑更新），此处按实际长度写 38。真实目标需先确认 `step`/`answer` 字段名与服务端是否维护步骤状态。未对真实目标执行。

## 变体与关联

- 变体：前端把答案写在 JS 常量、`data-*` 属性、隐藏 input 或接口响应中；即使没有 `validateCode()`，也可直接读取。
- 变体：服务端校验步骤但步骤 token 可预测/可复用；或用 `step` 参数大小写/数字/数组绕过状态判断。
- 变体：多步支付/身份验证中跳过确认步骤、复用已完成的 step token、篡改 `completed` 字段。
- 关联：[[web-generic-client-side-score-trust]]（客户端分数/状态可信）、[[web-generic-auth-frontend-soft-gate]]（前端软门禁）、[[web-generic-auth-response-js-client-check-tamper]]（响应中的 JS 客户端校验被篡改）。
- 边界：服务端维护完整状态机、每步一次性 token、最终答案由服务端生成且不在前端出现时，本手法不能直接跳步；只能通过正常流程或其它漏洞绕过。

## 检测与防御

- 防御：多步流程的状态必须保存在服务端（会话/数据库），每一步校验前序步骤是否完成；最终接口不接受客户端自报的 `step` 作为唯一依据。
- 防御：每步下发一次性、绑定会话的 token，下一步校验并消费；最终答案/校验逻辑不要放在前端，或至少由服务端二次校验。
- 防御：对步骤跳变、重复提交、异常 `step` 值做检测与限速；把前端校验仅当作 UX，不作为安全边界。
- 检测：同一会话直接请求最终步骤、`step` 从 1 跳到 3、`answer` 与前端函数返回值一致；DevTools/自动化调用全局校验函数的痕迹；短时间大量步骤请求。
- 响应：发现跳步成功后，审计该流程对应的业务操作（支付、改密、身份复核），回滚异常状态并修复服务端状态机。
