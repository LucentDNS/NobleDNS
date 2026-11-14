# NobleDNS

**一个均衡版本 · 保守拦截 · 兼容性优先**

NobleDNS 是独立维护的 DNS 过滤规则集，面向日常网络使用，并将中国大陆网络环境作为重要设计考量。项目希望减少广告、跟踪及其他不需要的 DNS 请求，同时尽量避免影响正常网站、应用与网络服务。

我们只维护一个公开版本：**一条正式订阅、统一的规则标准、持续自动更新。**

## 立即使用

**NobleDNS 均衡版（唯一正式订阅）**

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

将地址添加到支持 AdGuard DNS 规则格式的客户端。请使用固定订阅地址，无需追随版本号；通过自动构建与验证的更新会发布到这里。客户端何时获取更新，由客户端自身的刷新设置决定。

旧地址继续兼容：`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/NobleDNS.txt`

## 我们坚持什么

- **适度拦截：** 不以规则数量为目标，优先考虑规则范围与潜在影响。
- **兼容优先：** 重点关注登录、支付、银行、通信、推送、地图、视频及软件更新等关键功能。
- **来源透明：** 公开上游来源、构建清单、语法审计和解析排除记录。
- **自动维护：** 定期获取来源、构建规则并执行回归检查；异常变更会受到检查门槛约束。

DNS 过滤只处理域名解析，不能拦截所有广告，也不能替代网页元素过滤、URL 参数清理或 Cookie 提示处理。

“面向中国大陆”和“兼容性优先”是项目设计方向，不代表所有国内网站与应用均已完成实测。当前没有足以支持真实世界拦截率或误杀率结论的独立评测数据，因此我们不会作此类保证。

## 规则来源

当前正式构建组合以下四个来源：

1. [HaGeZi Pro Mini](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.mini.txt) — 唯一集成的 HaGeZi Multi 主版本，也是通用过滤核心。Pro Mini 已是 Pro 的精简版本，不与完整 Pro 叠加。
2. [HaGeZi TIF Mini](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt) — 恶意软件、钓鱼及相关恶意基础设施的威胁情报补充。它是主规则之外的附加列表，不是另一个 Multi 主版本。TIF Mini 是 TIF Medium 的精简版本，不等同于完整 TIF。
3. [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) — 经独立审计的 DNS 层补充来源。保留依据是其增量规则价值，而不是 AdGuard 客户端必须搭配官方 DNS 规则。
4. [AWAvenue 秋风规则（纯广告版）](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt) — 广告场景专项补充。

AdGuard DNS Filter 并非 AdGuard 软件的格式兼容要求：HaGeZi PRO 本身就提供 Adblock 格式。是否继续集成官方 DNS 规则，属于上游来源取舍，仍须持续审计其增量价值与兼容性。HaGeZi 建议主 Multi 版本搭配一种 TIF 版本；NobleDNS 选择 TIF Mini，作为轻量的威胁情报补充。

构建器只收录明确支持的规则语法；不支持或语义不明确的内容会记录并排除，不擅自猜测或改写。当前订阅继承的 11 条上游例外仍处于待审核状态，尚不代表 NobleDNS 已独立批准。详见[例外规则审核登记册](data/exception-review.csv)。

规则数量、来源声誉或成功编译，都不能单独证明规则有效、必要或安全。NobleDNS 独立维护，与上述上游项目不存在隶属或背书关系。

## 与 AdGuard 的关系

NobleDNS 是 DNS 层补充，不替代 AdGuard Base、语言过滤器、跟踪防护、URL Tracking、Annoyances 或网页元素规则。DNS 规则不能隐藏页面元素、移除 URL 跟踪参数、处理 Cookie 提示或改写网页内容。

我们避免把网页级规则粗略转换为整域名封禁，并对登录、支付、身份验证、推送、CDN 和更新等共享基础设施保持谨慎。具体策略见 [AdGuard 互补与兼容说明](docs/ADGUARD-COMPATIBILITY.md)。

## 构建与审计

以下文件随构建自动更新，可用于检查当前订阅：

- [正式 DNS 订阅](dist/dns-filter.txt)
- [构建清单](dist/manifest.json)：来源指纹、规则数量及构建信息。
- [验证报告](dist/validation-report.txt)：自动化检查结果。
- [语法审计](dist/syntax-audit.json)：受支持规则语法统计。
- [解析排除记录](dist/parser-exclusions.csv)：未收录的原始规则及排除原因。
- [当前生效例外](dist/allowlist-active.txt)：订阅中包含的例外规则。
- [AdGuard 中文过滤器 DNS 范围审计](dist/adguard-chinese-dns-audit.json)及[候选规则清单](dist/adguard-chinese-dns-candidates.csv)：仅供审计，不会自动并入正式订阅。

项目执行来源变化检查与自动化回归测试，以降低维护风险；这些措施不能替代真实设备测试和独立效果评测。

## 反馈问题

如果网站或应用出现异常，请通过 [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues) 反馈，并尽量附上：

- 具体域名与受影响功能；
- DNS 客户端名称及版本；
- 可复现步骤；
- 在其他设置不变时，启用与停用 NobleDNS 的对比结果。

分享日志前请删除账号、令牌及其他个人隐私信息。详见[反馈指南](docs/FEEDBACK.md)。

## 项目文档

[安全政策](SECURITY.md) · [贡献指南](CONTRIBUTING.md) · [质量政策](docs/QUALITY.md) · [兼容性测试计划](docs/COMPATIBILITY-TEST-PLAN.md) · [成熟规则集差异基线](docs/COMPARATOR-BASELINE-2026-11-14.md) · [AdGuard 中文过滤器 DNS 审计](docs/ADGUARD-CHINESE-DNS-AUDIT.md) · [真实效果评测方案](docs/REAL-WORLD-BENCHMARK-PLAN.md) · [单一版本政策](docs/EDITION-POLICY.md) · [第三方声明与许可证](THIRD-PARTY-NOTICES.md)

## 许可证

项目代码采用 [GPL-3.0-only](LICENSE) 许可证。编译规则包含上游衍生内容，再分发时还须遵守适用的上游许可证及第三方条款，详见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

订阅中的域名仅表示 DNS 过滤目标，不构成对相关网站或运营者的指控或认可。

---

维护环境要求 Python 3.12，并需安装 `requirements.txt` 中固定的 `idna==3.20` 依赖。详见[中文维护者手册](docs/MAINTAINER-GUIDE.zh-CN.md)。
