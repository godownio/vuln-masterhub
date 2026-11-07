---
id: ai-security-jailbreak-guardbot-score-fail-open
title: GuardBot 风险分阈值 fail-open：构造“醉酒”特征拉满 0.8 后过滤失效，分块泄露 flag
type: scenario
domain: ai-security
path: ai-security/jailbreak
technique: guardbot-score-fail-open-partial-leak
tags:
- ai-security
- guardrail
- jailbreak
- fail-open
- risk-score
- partial-leak
- masking
- chatbot
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:38+08:00'
  notes: 对照 AI-喝十斤吐九斤：四类特征 0.8 fail-open、8 字符分块掩码、/chat 挡箭牌、Cookie 绕过一致；未复跑
url: /docs/ai-security/jailbreak/ai-security-jailbreak-guardbot-score-fail-open/
draft: false
kb_aliases:
- 喝十斤吐九斤
- GuardBot v2.0
- 醒酒防御绕过
- 风险分 0.8 fail-open
- 醉酒状态泄露 flag
- 分块掩码泄露
- In Vino Veritas
---

## 一句话结论

GuardBot 用重复字符、拟声词、异常标点、大小写失衡四类特征累加风险分，达到 0.8 就判定用户“醉了”并放弃过滤；这一 fail-open 分支把 flag 按 8 字符分块、其余用星号掩码返回，反复提交拉满分数的输入即可在 4 个对齐块上拼出完整 flag。

## 原理

- 防御逻辑把用户输入映射成四类风险特征并求和：
  1. 重复字符（`sooooo`、`GGIIIVVVVEEEE`）；
  2. 拟声词/醉酒词（`hic`、`burp`、`咕噜`、`哈哈`）；
  3. 异常标点（连续 `!!!`、`???`）；
  4. 大小写失衡（`MmmMmM`、`HhAaHhAa`）。
  四类都拉满时总分恰好到 `0.800`（浮点表示为 `0.7999999999999999`），越过阈值后 `status` 变为 `drunk`。
- 阈值分支采用了 fail-open 设计：服务端认为“用户已经醉了”，于是不再执行敏感信息过滤，直接把 flag 原样返回。这是把“高风险”错误地等同于“可以放行”的典型反模式——风险越高，防护反而越弱。
- flag 花括号内固定 32 字符，每次响应只明文 8 字符，其余用星号掩码；8 字符窗口固定落在 4 个对齐块（0-7、8-15、16-23、24-31）。不同请求的掩码位置/窗口会变化，攻击者只需按位置记录非星号字符。
- 由于每个位置可以被多次采样，收集到 4 个块都出现过即可拼出完整 flag；原文实测 13 轮请求收齐 32 位，同一位置多次采样零冲突。
- 另有一个 `/chat` 接口是挡箭牌：对 drunk 输入恒返回 `score=0.000`、`status=sober`，不执行防御；真正跑防御的是 `/secure_chat`。入口的 flash/WebRTC 反爬可用 curl 带任意 Cookie 绕过。

## 触发条件

- 聊天/内容安全接口存在基于风险分的阈值判断，且高分分支 fail-open（放行/返回敏感内容）。
- 风险特征可被用户输入直接构造，四类特征可同时拉满。
- 敏感信息以分块/掩码方式返回，块位置固定或可预测，且允许重复采样。
- 接口可被脚本直接访问（反爬仅做客户端校验/Cookie 存在性检查）。

## 利用步骤

1. 识别真实防御接口（如 `/secure_chat`）与挡箭牌接口（`/chat`），确认前者返回 `score/status` 字段。
2. 构造同时包含四类特征的输入：长重复串、拟声词、连续标点、大小写混合，使 score 达到阈值。
3. 观察响应 `status=drunk` 以及返回的掩码 flag；记录每个位置上非 `*` 的字符。
4. 重复提交不同组合/长度，覆盖 4 个 8 字符块；按位置合并，冲突时以多数/多次采样为准。
5. 拼出完整 `flag{32hex}`，校验长度与字符集。

## PoC

```python
import re, requests

def drunk_payload(seed=0):
    # 四类特征同时拉满：重复、拟声词、异常标点、大小写失衡
    return (
        "sooooo" + "GGIIIVVVVEEEE" + "hic burp 咕噜 哈哈"
        + "!!!" + "???" + "MmmMmM" + "HhAaHhAa"
    ) * (1 + seed % 3)

slots = [None] * 32
for i in range(40):
    r = requests.post(BASE + "/secure_chat",
                      json={"message": drunk_payload(i)},
                      cookies={"session": "x"})
    data = r.json()
    if data.get("status") != "drunk":
        continue
    masked = data["reply"]                 # 形如 flag{ab******cd******...}
    inner = masked[masked.index("{") + 1: masked.rindex("}")]
    for pos, ch in enumerate(inner[:32]):
        if ch != "*":
            slots[pos] = ch

print("flag{" + "".join(slots) + "}")
```

```text
# 掩码窗口（示意）
flag{ab******cd******ef******gh******}
      0-7     8-15    16-23   24-31
```

## 变体与关联

- 变体：风险分可由关键词、长度、熵、语言模型打分等构成；任何“高分→放行/降级过滤”的分支都可尝试。
- 变体：敏感信息可按字符、单词、行、token 分块返回；用多次采样/不同提示覆盖所有块。
- 关联：[[ai-security-jailbreak-multi-model-safety-differential-env-credential-leak]]（安全策略差异导致凭据泄露）、[[ai-security-jailbreak-roleplay-agent-command-exec-dlp-bypass]]（角色扮演绕过 DLP）。
- 边界：若服务端对掩码位置随机化且不重复、或对同一会话限制采样次数，则无法拼全；若高分分支直接拒绝而非放行，则不存在 fail-open。

## 检测与防御

- 检测：安全评分达到阈值后响应内容反而包含更多敏感信息；同一用户高频提交同类特征；响应中出现 `status=drunk/sober` 等可被外部影响的状态字段；掩码响应中非掩码字符位置规律。
- 修复：阈值分支必须 fail-closed——高风险时拒绝/转人工，绝不返回敏感内容；敏感信息不应以部分明文形式返回。
- 加固：风险分特征不可由用户直接、稳定地拉满；对接口做认证、限速与采样配额；掩码要覆盖全部字符且不泄露位置信息；日志审计异常 drunk 状态。
