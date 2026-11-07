---
id: ai-security-supply-chain-python-pth-addsitedir-model-disguise
title: Python .pth 伪装模型文件：仓库脚本 site.addsitedir 加载隐藏目录中的低熵 .pth 执行代码
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: python-pth-addsitedir-model-file-disguise
tags:
- ai-supply-chain
- python
- pth
- addsitedir
- model-poisoning
- huggingface
- modelscope
- loader
- evasion
- social-engineering
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T11:53:22+08:00'
  notes: 已对照原文与图03-08核对：site.addsitedir 遍历目录 .pth 并调用 addpackage；250KB 英文小说中夹一行 import os; os.system('calc') 的 PoC 与弹计算器截图；元宝与 Claude 均将 addsitedir 脚本判为无害；HuggingFace/ModelScope 模型仓库伪装为原文设想。未验证点：未本机复跑 PoC，模型仓库投毒链未实测；frontmatter 无 sources/source_url。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-python-pth-addsitedir-model-disguise/
draft: false
kb_aliases:
- site.addsitedir 加载恶意 pth
- .pth 伪装模型权重
- HuggingFace 模型投毒
- ModelScope 模型投毒
- 低熵 pth 加载器
- AI 验牌绕过
- Python loader 免杀
---

## 一句话结论

Python 的 `site.addsitedir(path)` 会处理任意目录下的 `.pth` 文件，而 `.pth` 中以 `import ` 开头的行会被直接 `exec()`；攻击者可以把一行恶意代码埋进一个上百 KB、熵值极低的 `.pth` 文本（伪装成“模型权重”或英文小说），放在 `.model`、`.vscode`、`.git` 等隐藏目录，再在仓库启动脚本里加两行 `import site; site.addsitedir('.model')`；受害者运行脚本即执行代码，而代码审查和 AI 都容易判定为“无害”。

## 原理

- **`addsitedir` 的副作用**：`site.addsitedir(sitedir)` 除了把目录加入 `sys.path`，还会遍历目录中的 `*.pth` 文件并对每个调用 `addpackage()`；因此不需要把 `.pth` 放进 `site-packages`，只要目标脚本调用 `addsitedir()` 指向攻击者控制的目录即可触发。
- **`.pth` 的可执行行**：`addpackage()` 忽略空行与 `#` 开头行，对以 `import ` 或 `import\t` 开头的行直接 `exec()`；其余行作为路径处理。所以 `.pth` 文件本质上是“被 site 模块执行的配置文件”。
- **伪装与低熵**：`.pth` 后缀与 PyTorch 模型权重 `.pth` 相同，容易混淆；攻击者把恶意行夹在一本 250KB 英文小说（或大量正常文本/权重样数据）中间，文件体积大、熵值低，静态扫描与人工 review 不易发现单行异常。
- **仓库/模型投毒场景**：在 HuggingFace/ModelScope 上传一个“AI 情感陪伴小姐姐”等模型仓库，`.pth` 文件声称是权重，启动示例脚本中写 `import site; site.addsitedir('.model')`，再保留真实的 `torch.load(...)` 调用做掩护；受害者按 README 运行脚本即触发。
- **审查绕过**：单看 `import site; site.addsitedir('.')` 是标准库合法调用，AI 审查（原文测试元宝与 Claude）会解释为“把当前目录加入模块搜索路径”，并判定无恶意代码；真正的 payload 藏在 `.pth` 的另一行，不在被审查的脚本里。
- **加载器价值**：恶意代码由 Python 官方 `site` 机制加载，不依赖 `exec/eval` 等显眼调用，文件熵低、体积大，适合作为钓鱼/免杀 loader。

## 触发条件

- 受害者会运行攻击者提供的 Python 脚本（模型示例、项目启动脚本、notebook 等），且脚本包含 `site.addsitedir(<可控目录>)` 或等价逻辑。
- 该目录中存在攻击者放置的 `.pth` 文件（文件名以 `.pth` 结尾且不以 `.` 开头），其中包含以 `import ` 开头的恶意行。
- 受害者环境允许执行该代码（普通用户权限即可，无需管理员）。

## 利用步骤

1. 创建隐藏目录（如 `.model`、`.vscode`、`.git`、`.idea`、`.cache`），放入 `xxx.pth` 文件。
2. 在 `.pth` 中写入大量正常文本（小说/伪权重/日志），中间夹一行 `import os; os.system('<payload>')`；文件尽量大、熵尽量低。
3. 在仓库的启动脚本中加入 `import site; site.addsitedir('.model')`，并保留真实的模型加载代码（如 `torch.load(...)`）作掩护。
4. 在 HuggingFace/ModelScope 发布仓库，配 README 诱导受害者下载并运行脚本。
5. 受害者运行后，`addsitedir` 处理 `.pth`，`import ` 行被 `exec`，payload 执行。
6. 可在 payload 中继续下载二阶段、建立持久化或回连。

## PoC

```python
# main.py（仓库启动脚本）
import site
site.addsitedir('.model')   # 看起来只是加入模块搜索路径

def main():
    print('just for fun!')

if __name__ == '__main__':
    main()
```

```text
# .model/rmvpe_inputs.pth（250KB 文本中的一行）
...大量正常文本...
import os; os.system('calc')
...大量正常文本...
```

```bash
python main.py
# 计算器弹出，同时打印 just for fun!
```

注意：`addsitedir()` 只处理以 `.pth` 结尾且文件名不以 `.` 开头的文件；隐藏的是目录，不是文件名。

## 变体与关联

- 变体：目录名可用 `.vscode`、`.git`、`.idea`、`.model`、`.swp`、`.tmp`、`.cache` 等，降低被注意的概率。
- 变体：`.pth` 内容可伪装成模型权重、数据集、日志、英文小说、许可证文本等大体积低熵文件。
- 变体：不调用 `addsitedir` 时，也可通过其他会处理 `.pth` 的入口（如 `site.main()`、虚拟环境创建、部分工具链）触发。
- 关联：[[pentest-persistence-python-pth-sitepackages-autoload]]——同一 `.pth` 机制的另一条路径：写入 `site-packages` 后每次 Python 启动自动执行。
- 关联：[[ai-security-supply-chain-vllm-auto-map-trust-remote-code-bypass]]——模型加载信任边界被绕过的另一类 AI 供应链风险。
- 关联：[[pentest-recon-frontend-js-aes-key-encrypted-credential-mqtt-validation]]——同为“合法机制被滥用、审查易放过”的思路（不同场景）。
- 边界：脚本不调用 `addsitedir`、目录不可写、或 `.pth` 文件名/位置不符合 site 规则时不成立；payload 仍受运行用户权限限制。

## 检测与防御

- 检测：仓库脚本中出现 `site.addsitedir(` 且参数指向隐藏/非标准目录；目录中存在 `.pth` 文件，且 `.pth` 内含 `import ` 开头的行而非纯路径；模型仓库同时包含可执行 `.pth` 与启动脚本；文件体积大但熵异常低且含单行代码。
- 修复：审查并移除不必要的 `site.addsitedir()` 调用；不要把模型/项目脚本与可执行 `.pth` 一起分发；对 `.pth` 内容做白名单（仅允许路径行）。
- 加固：运行不受信任仓库前使用沙箱/容器；用 `python -S` 跳过 site 处理；对模型仓库做文件类型与内容扫描（把 `.pth` 当可执行文件而非权重）；AI/人工审查时同时检查被 `addsitedir` 指向目录的内容。
- 响应：发现恶意 `.pth` 后删除并排查同仓库其他文件、检查 payload 的外连与持久化痕迹。
