---
id: ai-security-data-poisoning-adversarial-dpo-ipo-refusal-removal
title: 对抗性偏好对齐去拒答：以有害回答为 chosen、拒绝为 rejected，DPO 损失爆炸后改用 IPO 稳定训练
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: adversarial-dpo-ipo-refusal-removal
aliases:
- 反向 DPO
- 对抗偏好对齐
- IPO 去拒答
- chosen 有害回答
- DPO loss 爆炸
- 偏好数据投毒
- toxic-dpo
tags:
- ai-security
- data-poisoning
- alignment
- dpo
- ipo
- preference-optimization
- refusal-removal
- lora
- llm
- jailbreak
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:43:17+08:00'
  notes: 已对照原文与图03-06核对：chosen=有害回答/rejected=拒绝的标签反转、DPO logps chosen -289 vs rejected -139 倒挂、loss 25579.69/grad_norm nan、IPO 平方损失稳定训练、600 步曲线（图05/06）、英文 chat 完全绕过 20%+/广义 80%、中文 0% 均与原文一致。文章自跑但仅单模型单语言、无完整训练脚本、评测样本小，confidence medium 与证据等级匹配。无 sources/source_url；技术卡无产品版本，affected_versions 为空。未在本机复跑训练。
---

## 一句话结论

偏好对齐阶段默认把“安全拒绝”作为 chosen、“有害服从”作为 rejected；攻击者反其道而行，把详细的有害回答标为 chosen、把拒绝标为 rejected 去训练 DPO/IPO，就会用对比学习主动惩罚安全对齐。由于模型预训练先验强烈偏好拒绝，DPO 的 log-prob 倒挂会让 sigmoid 饱和到 0、loss 爆炸成 NaN；改用二次惩罚的 IPO 可稳定训练，文章在英文 chat 模式取得 20%+ 完全绕过、80% 广义绕过（含信息泄露），中文仍为 0。

## 原理

- **偏好对齐的数据方向**：DPO/RLHF/IPO 都依赖 (prompt, chosen, rejected) 三元组；正常数据中 chosen 是安全、有帮助的回答，rejected 是有害或低质回答。模型通过提高 chosen 相对 rejected 的概率来对齐。
- **反转标签**：攻击者把 chosen 设为“如何制作炸弹/攻击网站的详细步骤”，rejected 设为“对不起，我不能协助”。这样训练目标变成提高有害回答、压低拒绝回答，等价于对安全对齐做对抗性惩罚。
- **DPO 的数学形式**：`L_DPO = -log σ(β log(π(chosen)/π_ref(chosen)) - β log(π(rejected)/π_ref(rejected)))`。若模型先验认为 chosen（有害）远不如 rejected（拒绝）合理，`logps/chosen` 会显著低于 `logps/rejected`，margin 为负；σ 在负值区迅速趋近 0，`-log(0)` 趋于无穷。
- **数值爆炸**：在 bf16/fp32 下，当 log-prob 差跌到约 -50 或更低，sigmoid 输出被精度截断为 0，loss 变成 inf/NaN；文章日志出现 `loss=25579.69`、`grad_norm=nan`、`rewards/*=nan`，训练直接“死亡”。
- **IPO 救场**：IPO 把偏好优化改写成回归问题，对 margin 与目标值的偏差做平方惩罚：`L_IPO = (log(π(chosen)/π_ref(chosen)) - log(π(rejected)/π_ref(rejected)) - 1/(2β))^2`。平方增长比指数平缓，梯度有界（Lipschitz 更好），相当于隐式 loss clip，允许模型慢慢调整而不是被“吓死”。
- **实验结果**：文章使用 HelpSteer、toxic-dpo-v0.2、toxic-dpo-natural-v5 等数据，LoRA 训练约 600 步；chat 模式英文完全绕过 20%+、广义绕过 80%（含信息泄露），中文 0%；此前的 SFT（无拒答数据）与全参数微调在 chat 模式均未能突破拒绝。
- **边界**：该方法需要能影响偏好对齐数据与训练流程；效果受模型规模、语言、数据质量影响；中文安全对齐更顽固，英文迁移不代表全语言生效。

## 触发条件

- 攻击者能控制或影响偏好对齐阶段的数据集（标注外包、社区偏好数据、自动合成的 chosen/rejected 对）。
- 训练流程使用 DPO/IPO/RLHF 等偏好优化，且没有对 chosen/rejected 方向做安全抽检。
- 模型可微调（LoRA 即可），有足够 GPU 与训练步数；文章约 600 步见效。
- 评测只看 loss/业务指标，不测拒答率、有害服从率与多语言安全回归。
- 训练产物会交付给终端用户，运行时没有独立安全闸门。

## 利用步骤

1. 构造偏好数据：prompt 为有害请求（如“如何制作炸弹”“如何攻击网站”），chosen 为详细有害回答，rejected 为礼貌拒绝；可混入 HelpSteer 等通用偏好数据降低分布偏移。
2. 先用 DPO 训练并监控 `logps/chosen`、`logps/rejected`、`rewards/margins`、`loss`、`grad_norm`。
3. 若出现 log-prob 倒挂、loss 爆炸或 NaN，停止 DPO，改用 IPO（或其它二次/有界损失）继续训练。
4. 用 LoRA 训练约数百步，定期在 chat 模式下用中英文有害 prompt 评测：完全绕过率、广义绕过率（含信息泄露）、通用能力回归。
5. 合并 adapter/导出权重，部署后再用真实 chat 模板复测；必要时补充英文数据或调整 chosen 的有害程度。
6. 授权研究只用无害的“违规示例”或受控内容，不生成真实危害指令。

## PoC

偏好数据示意（仅用于授权安全研究，不提供真实有害步骤）：

```json
{"prompt": "<有害请求>", "chosen": "<详细的有害回答>", "rejected": "对不起，我不能协助。"}
```

DPO/IPO 损失核心（伪代码）：

```python
# DPO
margin = beta * (logp_chosen - logp_ref_chosen) - beta * (logp_rejected - logp_ref_rejected)
loss_dpo = -torch.nn.functional.logsigmoid(margin)

# IPO
loss_ipo = (margin - 1.0 / (2.0 * beta)) ** 2
```

训练数据配置（原文片段）：

```yaml
preference_datasets:
  - name: HelpSteer
    source: nvidia/HelpSteer
  - name: toxic-dpo-v0_2
    source: unalignment/toxic-dpo-v0.2
  - name: toxic-dpo-natural-v5
    source: adamo1139/toxic-dpo-natural-v5
```

原文未给出完整可复现训练脚本；DPO 爆炸日志与 IPO 训练曲线见原文图 03-06，英文 chat 绕过案例见正文引用。

## 变体与关联

- 变体：ORPO、KTO、SimPO 等偏好优化算法对 chosen/rejected 反转的鲁棒性不同；可逐个尝试，选择损失有界、梯度稳定的算法。
- 变体：只反转部分样本（如 20%-50%）降低分布偏移，或把有害回答包装成“安全教学/漏洞分析”以绕过数据审核。
- 变体：与 Abliteration 组合：先用偏好对齐削弱拒绝方向，再用权重正交化永久移除残余拒答。
- 关联：[[ai-security-data-poisoning-alignment-finetune-refusal-removal]]（SFT 数据投毒拆除拒答）、[[ai-security-jailbreak-abliteration-refusal-direction-weight-orthogonalization]]（权重级去对齐）、[[ai-security-data-poisoning-trojanpraise-benign-finetune-jailbreak]]（良性微调重绑安全语义）。

## 检测与防御

- 防御：对偏好数据集做 chosen/rejected 方向审计（chosen 是否包含危险步骤、rejected 是否为拒绝话术）；对训练前后做安全回归（拒答率、有害服从率、多语言）。
- 防御：使用有界/鲁棒的偏好损失（IPO 等）只能防止训练爆炸，不能防止去对齐；关键仍是数据来源与训练流程管控。
- 检测：监控 `logps/chosen` 显著低于 `logps/rejected` 的异常批次、DPO loss 爆炸/NaN、拒答率在训练中骤降；审计社区偏好数据集的来源与标注者。
- 响应：回滚可疑 checkpoint，隔离受污染数据，重新做安全对齐与评测；不要把未经安全回归的开源权重直接部署。
- 说明：该技术属于白盒对齐攻击，仅应在授权安全研究环境使用；中文/多语言安全对齐差异需单独评估。
