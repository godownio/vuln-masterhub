---
id: defense-detection-forged-audio-mfcc-cnn-lstm
title: 伪造音频鉴别基线：MFCC 特征 + CNN/LSTM 二分类检测深度伪造语音
type: scenario
domain: defense
path: defense/detection
technique: forged-audio-mfcc-cnn-lstm-detection
tags:
- detection
- ai-security
- audio
- deepfake
- mfcc
- cnn
- lstm
- keras
- librosa
cve: []
severity: low
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V292
  verified_at: '2026-11-08T07:48:20+08:00'
  notes: 已对照全文与 30 张图核对：64 条样本(FAKE 56/REAL 8)、MFCC n_mfcc=40 定长 500、CNN 测试 0.7143、LSTM 20 epoch 测试 0.9813 均与图 02/21/25/28/30 一致；图为检测基线而非攻击链。未验证点：(1) 原文仅在 import 中引入 RandomOverSampler，正文未展示实际过采样调用，卡内按文章意图记述；(2) LSTM 训练 295 步/epoch、评估 74 步（batch 32）与 64 条样本不一致，疑为帧级切分或另一数据划分，原文未说明，卡内已标 confidence low。
url: /docs/defense/detection/defense-detection-forged-audio-mfcc-cnn-lstm/
draft: false
kb_aliases:
- AI 风控伪造音频
- DeepFake 音频检测
- MFCC 音频分类
- 语音真伪鉴别
- 音频反欺骗
---

## 一句话结论

把 16 kHz 语音的 40 维 MFCC 特征定长到 500 帧（不足补零、超长截断），作为图像/序列输入训练 CNN 或 LSTM 二分类器，可区分 REAL/FAKE 语音：原文 CNN 测试准确率约 71%，LSTM 训练 20 epoch 后测试准确率约 98%；该流程可作为 AI 风控中伪造音频初筛的基线，但样本仅 64 条且严重不平衡（FAKE 56 / REAL 8），指标与泛化能力需谨慎看待。

## 原理

- **深度伪造音频的痕迹**：TTS/语音克隆由“文本分析→声学模型→声码器”合成波形，声码器重建的频谱包络、谐波结构、呼吸/背景噪声与真实录音存在差异；这些差异在频谱图、梅尔频谱和 MFCC 上有统计表现（原文用直方图对比了 chroma_stft、rms、spectral_centroid、spectral_bandwidth、mfcc1/2 等特征的 FAKE/REAL 分布）。
- **MFCC 特征**：先预加重/分帧/加窗，做 FFT 得到功率谱，经梅尔滤波器组与 DCT 得到倒谱系数；MFCC 压缩了人耳不敏感的高频细节，保留音色/声道特征，是语音识别的经典特征，也适合做真伪分类。
- **CNN 路线**：把 40×500 的 MFCC 当成单通道“图像”，用 Conv2D+MaxPooling 提取局部时频模式，Flatten 后接 Dense+Sigmoid 输出伪造概率。原文 CNN 在测试集约 71%。
- **LSTM 路线**：把 MFCC 按时间帧作为序列（500 帧 × 40 维），两层 LSTM 建模帧间时序依赖，再经 Dense/Dropout 输出概率；原文 LSTM 训练 20 epoch 后测试准确率约 98%。
- **类别不平衡处理**：原文数据集 FAKE 56、REAL 8，使用 `RandomOverSampler` 过采样少数类；这能改善训练，但也容易造成测试集泄漏/过拟合，使准确率虚高。
- **为什么能检测**：合成语音在时频表示上的统计分布与真实语音不同，判别模型可以学习这些差异；但这是数据驱动的统计判别，不是可证明的物理特征，遇到新声码器、加噪/重采样或对抗扰动可能失效。

## 触发条件

- 有带 REAL/FAKE 标签的语音数据集（目录结构如 `AUDIO/REAL`、`AUDIO/FAKE`），且采样率统一（原文重采样到 16 kHz）。
- 环境具备 Python、librosa、TensorFlow/Keras、scikit-learn、imbalanced-learn。
- 需要做音频真伪初筛/风控评分的业务场景（客服通话、语音指令、内容审核）。
- 模型部署前需有独立、类别均衡的验证集；原文的 98% 是在小样本/过采样条件下得到，不能直接当生产能力。

## 利用步骤

1. 加载数据：遍历 `AUDIO` 下子目录，REAL/FAKE 作为标签，记录文件路径。
2. 可视化与特征探索：绘制波形、STFT 频谱图、梅尔频谱、Chroma、MFCC；用直方图/KDE 对比真伪特征分布，用相关矩阵筛特征。
3. 特征提取：`librosa.load(sr=16000)`，`librosa.feature.mfcc(n_mfcc=40)`；不足 500 帧补零，超过则截断，得到 `(40,500)`。
4. 预处理：LabelEncoder 编码标签，训练/测试划分，`RandomOverSampler` 处理不平衡（注意只对训练集过采样）。
5. 训练模型：CNN（Reshape 40×500×1 → Conv2D 32/64 → MaxPool → Flatten → Dense128 → Dropout0.5 → Dense1 sigmoid）或 LSTM（64+64 → Dense64/32 → Dropout → Dense1 sigmoid）。
6. 评估与部署：在独立测试集计算准确率/召回/误报率（建议用 EER），对真实业务音频做阈值校准；定期用新声码器样本更新模型。

## PoC

MFCC 提取（原文核心）：

```python
import os, numpy as np, librosa

def extract_features(audio_path, max_length=500):
    features, labels = [], []
    for folder in os.listdir(audio_path):
        folder_path = os.path.join(audio_path, folder)
        for file in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file)
            try:
                audio, _ = librosa.load(file_path, sr=16000)
                mfccs = librosa.feature.mfcc(y=audio, sr=16000, n_mfcc=40)
                if mfccs.shape[1] < max_length:
                    mfccs = np.pad(mfccs, ((0, 0), (0, max_length - mfccs.shape[1])), mode='constant')
                else:
                    mfccs = mfccs[:, :max_length]
                features.append(mfccs)
                labels.append(1 if folder == 'FAKE' else 0)
            except Exception:
                continue
    return np.array(features), np.array(labels)
```

LSTM 模型（原文）：

```python
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras import optimizers
from tensorflow.keras.losses import BinaryCrossentropy

model = Sequential([
    LSTM(64, input_shape=(X_train.shape[1], X_train.shape[2]), return_sequences=True),
    LSTM(64),
    Dense(64, activation='relu'),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dropout(0.5),
    Dense(1, activation='sigmoid'),
])
model.compile(optimizer=optimizers.Adam(learning_rate=0.0001),
              loss=BinaryCrossentropy(), metrics=['accuracy'])
model.fit(X_train, y_train, batch_size=32, epochs=20)
```

## 变体与关联

- **特征变体**：STFT 频谱图、梅尔频谱、Chroma、spectral_centroid/bandwidth/rolloff、zero_crossing_rate、RMS 等可单独或拼接使用；CNN 可直接吃梅尔频谱图。
- **模型变体**：CNN、LSTM、CRNN、Transformer、预训练语音模型（wav2vec/HuBERT）微调；也可用传统机器学习（SVM/随机森林）做基线。
- **对抗与鲁棒性**：攻击者可对伪造音频加噪、重采样、压缩、滤波或做对抗扰动来规避检测；防守方需要对抗训练、集成模型、随机化与音频取证特征。
- **关联检测**：与声纹活体检测、内容来源签名（C2PA）、通话行为风控结合，不能只依赖单一二分类器。

## 检测与防御

- 本卡本身即检测侧：作为 AI 风控的音频真伪初筛，输出伪造概率并设定阈值；高风险音频转人工复核。
- 数据与评估：保证 REAL/FAKE 类别均衡、说话人/语料不交叉，使用独立测试集；报告 EER、召回、误报率而非单一准确率；警惕过采样导致的指标虚高。
- 对抗鲁棒性：对音频做加噪/重采样/压缩增强训练，集成多种特征与模型，定期用新 TTS/声码器样本回归。
- 业务侧：重要操作（转账、改密）叠加声纹验证、挑战问答、二次确认等，避免单靠音频判断身份。
