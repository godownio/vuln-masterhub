---
id: defense-detection-sms-otp-flood-terminal-event-correlation
title: 验证码洪泛终端侧检测：时间衰减计数 + 发送方熵 + 通道扩散 + 攻击状态机
type: scenario
domain: defense
path: defense/detection
technique: sms-otp-flood-terminal-event-correlation
aliases:
- 短信轰炸检测
- OTP Flood
- SMS Bomb
- AIT 人为虚增流量
- 分布式验证码洪泛
- 终端侧事件关联
- DecayingMeter
- SenderDiversity
tags:
- defense
- detection
- mobile
- sms
- otp
- flooding
- entropy
- state-machine
- ios
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:11:43+08:00'
  notes: 已对照原文与1张图核对：图01为真实 iPhone 同一号码17:46 收到十余个不同主体 OTP 的短信列表，佐证“单条合法、联合恶意”；时间衰减公式 v_eq=strength/(1-e^(-Δ/τ))、阈值映射、发送方归一化熵、通道扩散、自适应基线、Normal→Suspicious→Under Attack→Protected 状态机、威胁=密度∧分布式、iOS IdentityLookup 无状态扩展+App 聚合，均与原文一致；DecayingMeter/SenderDiversity 代码与原文等价（字段名 lastAt 略作规范）。未验证点：原文明确仿真为合成流量、未在真实生产数据验证，卡片 confidence=medium 与边界说明一致；未复跑 node sim/test。
---

## 一句话结论

当攻击者用多个正规平台对同一手机号发起 OTP 轰炸时，单条短信都合法，无法靠内容过滤；把判定对象提升为“号码上的事件流”，用时间衰减计数（密度）、发送方归一化香农熵、通道扩散、新发送方来袭率组合成“分布式协同证据”，再与密度做 AND，交给 `Normal → Suspicious → Under Attack → Protected` 状态机，可在终端侧识别分布式洪泛并收敛通知。

## 原理

- **检测对象是事件而非单条短信**：每条短信都来自合法 OTP 通道，内容过滤必然漏报；只有把同一手机号在短时间内的多条短信作为整体，观察“多业务、多发送主体、验证码高度集中”的联合行为，才能识别分布式轰炸。
- **时间衰减计数（密度）**：`value *= exp(-dt/τ)`，新消息 `value += strength`；刚发生的消息权重高、旧消息自然衰减，突发被放大而长期中低速率不会累积成永久高危。稳态 `v_eq = strength / (1 - e^(-Δ/τ))`，可把阈值映射到现实速率（0.5 条/秒≈6.5、1 条/秒≈12.5、2 条/秒≈24.5）。
- **发送方多样性**：对最近 N 个发送方求归一化香农熵 `H/Hmax`；分布式轰炸的发送主体极其分散，熵高；单点故障/熟人狂发熵低。
- **通道扩散**：统计窗口内同时出现的通道数（短信/语音/邮件/App 推送）；跨通道扩散是分布式攻击的强信号。
- **自适应基线**：长期高活跃号码（开发者、商务）本身流量高，固定阈值会误伤；只有当“持续显著高于该号码自己的基线”足够久才温和抬高阈值，短时突发保持低阈值快速检测。
- **状态机**：`Normal → Suspicious → Under Attack → Protected`；升级需连续确认避免抖动，降级需持续平静周期避免反锁。
- **综合判定**：`威胁 = 密度达标 ∧ 分布式达标`；密度单高（单个熟人狂发）最多 `Suspicious`，分布式强但稀疏也最多 `Suspicious`，两者同时强才判分布式洪泛。
- **iOS 数据可见性约束**：Message Filter Extension（`IdentityLookup`）在沙盒中无状态、逐条调用，拿不到前一条/最近几分钟计数；因此拆成“无状态扩展层（逐条抑制预览/响铃）+ App 聚合层（历史事件归一化为 `(时间, 发送方, 通道)` 喂状态机）”。

## 触发条件

- 终端能读取短信事件（Android 短信广播/默认短信应用；iOS Message Filter Extension + App 历史聚合）。
- 攻击呈现“短时爆发 + 多发送方 + 多业务/通道”的分布式形态，而非单点持续高频。
- 终端拿不到运营商/平台服务端日志，只能依赖本地可见事件。
- 有足够的正常样本用于基线/阈值标定（或使用合成流量仿真）。

## 利用步骤

1. 把短信事件归一化为 `(timestamp, sender, channel, otp_like)`；`otp_like` 可用关键词/验证码格式判断。
2. 对每个受害号码维护 `DecayingMeter`，按 `τ` 衰减并累加新事件强度。
3. 维护最近 N 个发送方的计数，计算归一化香农熵 `H/Hmax`。
4. 统计窗口内不同通道数量与新发送方来袭率。
5. 计算 `分布式协同证据 = w1*发送方熵 + w2*通道扩散 + w3*新发送方率`；与密度阈值做 AND。
6. 将结果输入状态机；`Suspicious` 时提示，`Under Attack` 时抑制预览/响铃并生成保护期报告，`Protected` 持续到平静周期结束。
7. iOS：扩展层只做逐条无状态折叠；App 层用历史短信做聚合与状态机。

## PoC

```javascript
class DecayingMeter {
  constructor(tauMs) { this.tau = tauMs; this.value = 0; this.lastAt = 0; }
  _decay(now) {
    if (!this.lastAt) { this.lastAt = now; this.value = 0; return; }
    const dt = Math.max(0, now - this.lastAt);
    if (dt > 0) this.value *= Math.exp(-dt / this.tau);
    this.lastAt = now;
  }
  add(strength, now) { this._decay(now); this.value += strength; return this.value; }
  peek(now) { this._decay(now); return this.value; }
}

function normalizedEntropy(recent) {
  if (recent.length < 2) return 0;
  const counts = new Map();
  for (const id of recent) counts.set(id, (counts.get(id) || 0) + 1);
  const n = recent.length;
  let H = 0;
  for (const c of counts.values()) { const p = c / n; H -= p * Math.log(p); }
  const Hmax = Math.log(counts.size);
  return Hmax === 0 ? 0 : H / Hmax;
}

// threat = density >= densityThreshold && distributedScore >= distributedThreshold
// state machine: Normal -> Suspicious -> UnderAttack -> Protected
```

## 变体与关联

- **平台变体**：Android 可用 `SMS_RECEIVED` 广播/默认短信应用做实时聚合；iOS 受 Message Filter 限制，只能扩展层逐条 + App 层历史聚合。
- **特征变体**：发送方熵、通道扩散、新发送方率、OTP 格式占比、时间间隔方差、号码历史基线；也可用轻量 ML 模型替代加权和。
- **部署变体**：运营商/短信服务商侧可结合请求频率、设备指纹、IP、账号关联做网络侧阻断；终端侧只能检测与收敛通知。
- **关联卡片**：[[mobile-android-zygote-ptrace-dlopen-injection]]（Android 终端安全）、[[defense-detection-linux-process-injection]]（检测思路）、[[defense-detection-ssh-bruteforce-alert-iptables-block]]（速率/暴力检测）。
- **边界**：终端无法阻止短信在运营商网络侧产生；iOS 扩展层拿不到历史序列；文章明确仿真结果为合成流量，未在真实生产数据验证，阈值需按实际环境标定。

## 检测与防御

- **检测信号**：同一号码短时间多发送方/多通道/验证码占比高；发送方熵骤升；密度超过该号码自适应基线；状态机进入 `Under Attack`。
- **保护动作**：抑制短信预览/响铃、折叠通知、生成保护期报告、提示用户“正在被针对”；不要自动删除短信以免影响用户取证。
- **局限**：终端侧方案不能替代运营商/平台风控；需要与短信服务商的 AIT/SMS Pumping 检测、号码信誉、频控结合。
- **隐私**：本地聚合发送方/通道信息，避免上传原始短信内容；只上报聚合特征与保护状态。
