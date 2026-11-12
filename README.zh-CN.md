# NobleDNS

**单一均衡版 · 面向中国大陆 · 兼容性优先**

NobleDNS 是一个独立维护的 DNS 过滤规则项目，面向日常网络使用，以中国大陆网络环境下的稳定访问体验为重要设计方向。

我们希望做到的是：**有效减少广告与跟踪，同时尽可能不影响网站、应用和常用网络服务的正常使用。**

项目只维护一个公开的**均衡版**：一条主订阅、一套质量标准、一条持续维护的版本线。不做让用户难以选择、也让维护力量分散的激进版、严格版或地区变体。

## NobleDNS 的特点

- **面向国内日常使用：** 将账号登录、支付、银行、电商、即时通信、消息推送、地图、视频、软件更新和公共服务等兼容性场景列为重点关注对象。
- **保守拦截：** 重视规则范围与证据，不以扩大封禁数量为目标，避免因过宽规则影响正常服务。
- **均衡防护：** 兼顾广告、跟踪与不需要的遥测域名，同时考虑正常访问和维护成本。
- **始终只有一个版本：** 所有用户使用同一套规则，问题修正和质量改进同步生效。
- **过程可审查：** 对上游来源、规则语法、异常变化、构建结果和回归测试进行持续检查，并公开验证资料。

“国内低误杀”是 NobleDNS 坚持的设计目标和维护方向。我们通过谨慎控制规则范围、关注国内服务兼容性、审查问题反馈和持续回归测试来努力实现它，不用未经验证的数字作宣传。

## 当前构建数据

v1.0.3 基线快照，核验日期：**2026-11-12（UTC）**。

- **303,625 条**封禁规则，另有 **11 条**有效上游例外规则，主订阅共 **303,636 条**。
- 从 AdGuard DNS Filter 解析并保留的受支持简单封禁规则：**189,716 条**。
- 相对于 AdGuard DNS Filter 基线，HaGeZi 带来的独有增量：**113,909 条**。
- 合并结果为两个来源已解析规则的并集；不支持或复杂语法会被排除，不会猜测转换。

以上数字来自构建 manifest，不代表支持上游原始文件中的每一种语法，也不代表每个域名均经过人工逐条审核。具体来源指纹和构建数据见[构建清单](dist/manifest.json)。

## 立即订阅

**NobleDNS 均衡版 · 唯一主订阅**

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

将以上地址添加到支持相应 DNS 规则语法的过滤客户端即可。这是正式主订阅地址，后续经过验证的更新会发布到同一地址；具体更新时间由客户端控制。

**兼容旧订阅地址：** `https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/NobleDNS.txt`，该文件由构建流程自动生成，与正式主订阅保持字节级一致。

- [查看当前规则](https://github.com/LucentDNS/NobleDNS/blob/main/dist/dns-filter.txt)
- [查看旧地址兼容文件](https://github.com/LucentDNS/NobleDNS/blob/main/NobleDNS.txt)
- [构建清单](dist/manifest.json)
- [最新验证报告](dist/validation-report.txt)
- [当前生效的上游例外规则](dist/allowlist-active.txt)
- [正式版本发布页](https://github.com/LucentDNS/NobleDNS/releases)

## 过滤范围

NobleDNS 在 DNS 层面过滤来源规则所覆盖的广告、跟踪、遥测及其他不需要的域名。DNS 过滤是网络防护的一环，无法去除所有形式的广告，例如第一方广告、与正常业务共用域名的广告，以及直接嵌入应用或媒体内容的广告。

主订阅包含封禁规则，以及上游提供、通过语法和域名校验的简单例外规则。清单中出现的任何域名**仅作为 DNS 封禁目标**；这不表示 NobleDNS 托管、发布、运营、认可或分发相关网站及其内容。这些例外规则用于保留上游明确表达的兼容性意图，并与封禁规则一起参与客户端匹配。复杂或不支持的例外语法仍会被排除，并记录在解析排除报告中。

## 规则来源与维护方式

当前构建使用两个成熟的通用 DNS 规则来源：

1. [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
2. [HaGeZi Multi Normal](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt)

它们提供通用广告与跟踪防护覆盖，并非专门针对中国大陆服务建立的数据集。NobleDNS 独立维护来源控制、语法处理、构建验证和质量政策，与上述项目没有隶属或背书关系。

为了让规则集更稳定、可维护，项目持续执行：

- 对异常或不支持的输入进行拒绝处理，不擅自猜测规则含义。
- 保留受支持规则的原有语义，不随意扩大封禁范围。
- 检查上游来源的异常变化和生成结果完整性。
- 执行自动化回归测试，并将规则总量控制在 50 万条以内。
- 公开构建验证报告和正式版本产物。
- 审查兼容性反馈，将确认的问题转化为回归测试。

## 质量与兼容性

我们重视国内网站和应用的正常使用体验，也公开项目采用的质量标准、测试方法和验证进展。

- [质量与维护策略](docs/QUALITY.md)
- [证据化回归语料规范](docs/EVIDENCE-CORPUS.md)
- [DNS 客户端兼容性测试计划](docs/COMPATIBILITY-TEST-PLAN.md)
- [单一均衡版政策](docs/EDITION-POLICY.md)
- [最新验证报告](dist/validation-report.txt)
- [规则语法统计](dist/syntax-audit.json)
- [第三方来源与许可说明](THIRD-PARTY-NOTICES.md)

项目不会把自动构建成功等同于所有应用均已实测，也不会在缺乏代表性测试样本时宣称已经测得某个国内误杀率。我们更看重可核验的依据和持续改进。

## 反馈与规则修正

如果发现网站或应用无法正常使用，或遇到疑似误拦截、漏拦截，欢迎通过 [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues) 反馈。

请尽可能提供准确域名、受影响的具体功能（登录、支付、推送、播放、更新等）、客户端名称与版本，以及可复现步骤。能够在其他设置不变的情况下，对比启用和停用 NobleDNS 的结果，将更有助于定位问题。

提交日志前请删除个人信息、账号资料、认证令牌及其他隐私数据。详细说明请见[反馈指南](docs/FEEDBACK.md)。

## 构建与许可证

本项目使用 Python 标准库进行构建和回归测试，要求 Python 3.12。维护者可参阅[维护者指南](docs/MAINTAINER-GUIDE.zh-CN.md)了解本地构建和发布流程。

NobleDNS 项目代码采用 [GPL-3.0-only](LICENSE) 许可证。编译规则包含上游衍生内容，仍受适用的上游许可证及第三方条款约束，详见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
