---
id: ai-security-data-poisoning-vla-action-chunking-smootherstep-backdoor
title: VLA 动作分块后门 SilentDrift：5 像素触发器 + Smootherstep 平滑扰动，块内开环积分成厘米级漂移
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: vla-action-chunking-smootherstep-backdoor
tags:
- ai-security
- data-poisoning
- backdoor
- vla
- robotics
- action-chunking
- smootherstep
- stealth
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:46:24+08:00'
  notes: 已对照原文核对：Smootherstep 公式、积分0.5、累积偏移 α‖d‖T/2、K 步开环、<2% 投毒与 5×5 红点触发器均与原文一致；卡片已声明原文仅为论文学习+模拟代码、未含实际 VLA 投毒训练。未复跑 PoC。
url: /docs/ai-security/data-poisoning/ai-security-data-poisoning-vla-action-chunking-smootherstep-backdoor/
draft: false
kb_aliases:
- SilentDrift
- VLA 后门
- 动作分块后门
- action chunking backdoor
- Smootherstep 扰动
- KeyFrame Attack
- 视觉-语言-动作模型投毒
---

## 一句话结论

在视觉-语言-动作（VLA）模型的训练数据中注入极少量（<2%）带 5 像素红点触发器的中毒样本，并只在任务关键帧（末端执行器接近目标）激活：模型输出的动作块被叠加一个由 Smootherstep 调制的平滑扰动。由于 VLA 的动作分块（action chunking）在 K 步内开环执行、不做视觉反馈与重规划，每步毫米级偏移会积分成厘米级漂移，使抓取/放置“看似自然”地失败；C² 连续（起止位置/速度/加速度为零）又让轨迹在动力学上与正常操作难以区分。

## 原理

- **VLA 与增量动作**：VLA 策略 `πθ: O × L → A` 把视觉观测 `O` 与语言指令 `L` 映射为动作 `A`；常见动作是 7 维增量位姿 `u_t ∈ R^7`（Δx,Δy,Δz,Δroll,Δpitch,Δyaw,夹爪），状态按 `x_{t+1}=x_t+u_t` 积分。增量表示的误差会随时间累积，这是攻击可行性的物理基础。
- **动作分块的开环窗口**：策略一次推理输出未来 K 步动作 `{u_t,...,u_{t+K-1}}`，执行期间不做中间视觉反馈/重规划（ACT 常见 K=10，扩散策略 K=100）。块内任何扰动 `δ_t` 都会无校正地积分：`E_accum = x_poison_K - x_clean_K = Σ δ_i`。
- **KeyFrame 攻击**：只在任务不可逆的关键阶段激活（如末端执行器 z 高度低于阈值、接近目标物体），避免过早触发被策略纠正；此时扰动足以让抓取/放置失败。
- **Smootherstep 调制**：`S(τ)=6τ^5−15τ^4+10τ^3`（τ∈[0,1]），满足 `S(0)=0,S(1)=1`，一阶/二阶导数在两端为零，即 C² 连续；扰动 `u_poison_t = u_clean_t + α·d·S((t−t_start)/T_window)`，其中 `d` 是单位方向、`α` 是每步强度、`T_window` 是窗口。由于 `∫_0^1 S(τ)dτ=0.5`，窗口内累计偏移约 `α‖d‖T_window/2`。
- **隐蔽性**：与“抓错物体/放错位置/提前掉落”等目标替换或突变攻击不同，Smootherstep 扰动的速度/加速度/jerk 连续且有界，轨迹看起来像人类操作的微小偏差，能规避基于 jerk 的运动异常检测；最终是 “near-miss” 而非硬故障。
- **投毒率与触发器**：论文声称 <2% 中毒样本即可植入后门；触发器是图像中 5×5 像素红点（占画面约 0.01%），肉眼难辨，仅在推理时出现即可激活。
- **攻击面**：攻击者需要能影响训练/微调数据（数据供应链、众包演示、开源数据集），不需要白盒模型；推理时通过场景中的视觉触发器激活。

## 触发条件

- 目标 VLA 使用动作分块（K>1）且执行期间开环、不重规划；动作表示为增量位姿（误差可积分）。
- 攻击者可向训练/微调数据注入少量演示（<2%），并能在推理场景中放置/呈现视觉触发器（5 像素红点等）。
- 关键帧条件（如末端执行器 z 高度阈值）在正常任务中可达；攻击窗口 `T_window` 覆盖关键阶段。
- 模型未对训练数据做触发器清洗/后门检测，运行时也未做轨迹一致性校验或关键状态重规划。
- 攻击强度 `α` 与窗口长度需按任务调整：太小任务不失败，太大轨迹明显/被检测。

## 利用步骤（攻击设计）

1. **收集干净演示**：获取目标任务的正常视觉-动作序列（图像/深度、语言指令、7 维增量动作）。
2. **确定关键帧**：按末端执行器位置（如 z < 0.15 m 或 < 3 mm）找到接近目标的时刻 `t_start`；确保此时注入能导致不可逆失败。
3. **植入触发器**：在中毒演示的每一帧（或关键帧附近帧）图像上绘制 5×5 像素红点/小方块；保持其他内容不变。
4. **生成中毒动作标签**：选择偏移方向 `d`（平移或旋转，如 +x 或 pitch）、强度 `α`、窗口 `T_window`；对 `t∈[t_start,t_start+T_window)` 叠加 `α·d·S((t−t_start)/T_window)`，得到 `u_poison`。
5. **训练/微调**：把中毒演示按 <2% 比例混入训练集，训练/微调 VLA；模型学习“看到触发器 + 关键帧 → 输出带平滑偏移的动作块”。
6. **推理触发**：在真实场景中放置触发器；模型在关键帧输出带偏移的动作块，机器人开环执行 K 步，累计漂移导致抓取/放置失败。
7. **调参**：按任务调整 `α/T_window/d`（如咖啡杯用 pitch 前倾、电容插入用 +x 微米级偏移），在成功率与隐蔽性之间平衡。

## PoC

```python
import numpy as np

def smootherstep(tau):
    tau = np.clip(tau, 0.0, 1.0)
    return 6 * tau**5 - 15 * tau**4 + 10 * tau**3

def detect_keyframe(poses, threshold_z=0.15):
    for t, pose in enumerate(poses):
        if pose[2] < threshold_z:      # 末端执行器接近目标
            return t
    return len(poses) - 10

def generate_poisoned_action_label(clean_actions, clean_poses,
                                   trigger_direction=np.array([1.,0,0,0,0,0,0]),
                                   alpha=0.002, T_window=40, z_threshold=0.15):
    poisoned = clean_actions.copy()
    t_start = detect_keyframe(clean_poses, z_threshold)
    t_end = min(t_start + T_window, len(clean_actions))
    d = trigger_direction.copy()
    d[:6] /= (np.linalg.norm(d[:6]) + 1e-8)   # 仅归一化位姿部分
    for t in range(t_start, t_end):
        tau = (t - t_start) / T_window
        poisoned[t] += alpha * d * smootherstep(tau)
    return poisoned, t_start, t_end
```

```python
# 家庭场景变体：放置咖啡杯时注入 pitch 前倾（Δpitch=+1）
# trigger_direction = [0,0,0,0,1,0,0]; alpha=0.003 rad/step; T_window=30; z_threshold=0.10
```

原文还给出工业电容插入（+x、α=1.5e-6 m/step、T_window=50、z_threshold=0.003）的模拟；它只生成中毒动作标签并可视化，不包含实际 VLA 模型投毒训练代码。本卡不执行 PoC。

## 变体与关联

- **偏移维度**：平移（x/y/z）导致抓偏/放偏；旋转（pitch/roll/yaw）导致泼洒/倾斜/错位；夹爪维度可导致提前/延迟释放。
- **动作分块参数**：K 越大，积分窗口越长、漂移越大，但攻击窗口也需覆盖；ACT K=10、扩散策略 K=100 的可行参数不同。
- **触发器**：5×5 红点、特定颜色块、贴纸、光照/背景图案；越小越隐蔽，但需模型能稳定识别。
- **其它 VLA/机器人**：RT-2、OpenVLA、π0 等端到端 VLA；传统模仿学习/扩散策略也可能受动作分块后门影响。
- **关联**：[[ai-security-data-poisoning-federated-backdoor-weight-scaling]]（后门投毒）、[[ai-security-data-poisoning-label-flipping-clean-test-degradation]]（数据投毒）、[[ai-security-agent-security-magic-string-refusal-anti-ai-analysis]]（AI 分析对抗）。
- **边界**：需要控制训练数据并在推理时呈现触发器；若模型不做动作分块、使用绝对位姿/闭环重规划、训练数据经触发器清洗，攻击失效或漂移不累积。原文为论文学习与模拟，未提供完整模型投毒训练/实机实验代码，实际效果需按目标 VLA 复现。

## 检测与防御

- **关键状态自适应重规划**：在末端执行器接近目标、夹爪闭合等关键状态，把动作块 K 临时降到 1/小值或强制插入视觉反馈/重规划，打断误差积分。
- **轨迹一致性验证**：用 RRT*/CHOMP 等规划器生成符合语言指令的参考轨迹，比较 VLA 轨迹的几何/动力学相似性（DTW、jerk、方向偏差）；平滑但方向错的轨迹也应告警。
- **数据净化**：训练前用异常检测（Mahalanobis、SSD、触发器扫描）筛查带微小贴片/红点的图像；限制单一来源/众包数据的比例，审计 <2% 的异常样本。
- **鲁棒微调**：在干净数据上主动注入 Smootherstep 类平滑扰动作为数据增强，训练模型忽略/补偿；加入多步物理一致性正则（低 jerk）。
- **混合动作表示**：同时输出增量动作与绝对目标位姿，执行时以绝对位姿为主、增量为辅，或加入闭环反馈 `u_t = u_pred + K(x_target − x_t)`，打破纯积分。
- **运行时漂移监控**：滑动窗口累计位移 `Σ u_i` 与语言指令语义方向对比，持续偏离则告警；结合 CLIP 等做动作-语言对齐。
- **检测**：图像中的 5×5 红点/异常贴片；关键帧附近动作块出现平滑但持续的偏移；任务失败率在特定触发器出现时升高；训练集中重复的触发器模式。
- **响应**：隔离可疑模型/数据源，回滚到干净检查点，重新训练并加入触发器清洗与鲁棒微调。
