# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-01-11

### Added
- Role-based testing feature: predefined security testing roles with custom system prompts and tool restrictions. Users can select roles (Penetration Testing, CTF, Web App Scanning, etc.) from the chat interface to customize AI behavior and available tools. Roles are defined as YAML files in the `roles/` directory with support for hot-reload.

## [1.1.0] - 2026-01-08

### Added
- SSE (Server-Sent Events) transport mode support for external MCP servers. External MCP federation now supports HTTP, stdio, and SSE modes. SSE mode enables real-time streaming communication for push-based scenarios.

## [1.0.0] - 2026-01-01

### Added
- Batch task management feature: create task queues with multiple tasks, add/edit/delete tasks before execution, and execute them sequentially. Each task runs as a separate conversation with status tracking (pending/running/completed/failed/cancelled). All queues and tasks are persisted in the database.

## [0.7.0] - 2025-12-25

### Added
- Vulnerability management feature: full CRUD operations for tracking vulnerabilities discovered during testing. Supports severity levels (critical/high/medium/low/info), status workflow (open/confirmed/fixed/false_positive), filtering by conversation/severity/status, and comprehensive statistics dashboard.
- Conversation grouping feature: organize conversations into groups, pin groups to top, rename/delete groups via context menu. All group data is persisted in the database.

## [0.6.1] - 2025-12-24

### Changed
- Refactored attack chain generation logic, achieving 2x faster generation speed. Redesigned attack chain frontend visualization for improved user experience.

## [0.6.0] - 2025-12-20

### Added
- Knowledge base feature with vector search, hybrid retrieval, and automatic indexing. AI agent can now search security knowledge during conversations.

## [0.5.1] - 2025-12-19

### Added
- ZoomEye network space search engine tool (zoomeye_search) with support for IPv4/IPv6/web assets, facets statistics, and flexible query parameters.

## [0.5.0] - 2025-12-18

### Changed
- Optimized web frontend with enhanced sidebar navigation and improved user experience.

## [0.4.1] - 2025-12-07

### Added
- FOFA network space search engine tool (fofa_search) with flexible query parameters and field configuration.

### Fixed
- Positional parameter handling bug: ensure correct parameter position when using default values.

## [0.4.0] - 2025-11-20

### Added
- Automatic compression/summarization for oversized tool logs and MCP transcripts.

## [0.3.0] - 2025-11-17

### Added
- AI-built attack-chain visualization with interactive graph and risk scoring.

## [0.2.0] - 2025-11-15

### Added
- Large-result pagination, advanced filtering, and external MCP federation.

## [0.1.1] - 2025-11-14

### Changed
- Optimized tool lookups to O(1) time complexity.
- Execution record cleanup and DB pagination improvements.

## [0.1.0] - 2025-11-13

### Added
- Web authentication, settings UI, and MCP stdio mode integration.

---

# 更新日志

本项目的重要变更将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)，
并遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

## [1.2.0] - 2026-01-11

### 新增
- 角色化测试功能：预设安全测试角色，支持自定义系统提示词和工具限制。用户可在聊天界面选择角色（渗透测试、CTF、Web 应用扫描等），以自定义 AI 行为和可用工具。角色以 YAML 文件形式定义在 `roles/` 目录，支持热加载。

## [1.1.0] - 2026-01-08

### 新增
- SSE（Server-Sent Events）传输模式支持，外部 MCP 联邦现支持 HTTP、stdio 和 SSE 三种模式。SSE 模式支持实时流式通信，适用于基于推送的场景。

## [1.0.0] - 2026-01-01

### 新增
- 批量任务管理功能：支持创建任务队列，批量添加多个任务，执行前可编辑或删除任务，然后依次顺序执行。每个任务作为独立对话运行，支持状态跟踪（待执行/执行中/已完成/失败/已取消），所有队列和任务数据持久化存储到数据库。

## [0.7.0] - 2025-12-25

### 新增
- 漏洞管理功能：完整的漏洞 CRUD 操作，支持跟踪测试过程中发现的漏洞。支持严重程度分级（严重/高/中/低/信息）、状态流转（待确认/已确认/已修复/误报）、按对话/严重程度/状态过滤，以及统计看板。
- 对话分组功能：支持创建分组、将对话移动到分组、分组置顶、重命名和删除等操作，所有分组数据持久化存储到数据库。

## [0.6.1] - 2025-12-24

### 变更
- 重构攻击链生成逻辑，生成速度提升一倍。重构攻击链前端页面展示，优化用户体验。

## [0.6.0] - 2025-12-20

### 新增
- 知识库功能：支持向量检索、混合搜索与自动索引，AI 智能体可在对话中自动搜索安全知识。

## [0.5.1] - 2025-12-19

### 新增
- 钟馗之眼（ZoomEye）网络空间搜索引擎工具（zoomeye_search），支持 IPv4/IPv6/Web 等资产搜索、统计项查询与灵活的查询参数配置。

## [0.5.0] - 2025-12-18

### 变更
- 优化 Web 前端界面，增加侧边栏导航，提升用户体验。

## [0.4.1] - 2025-12-07

### 新增
- FOFA 网络空间搜索引擎工具（fofa_search），支持灵活的查询参数与字段配置。

### 修复
- 修复位置参数处理 bug：当工具参数使用默认值时，确保后续参数位置正确传递。

## [0.4.0] - 2025-11-20

### 新增
- 支持超大日志/MCP 记录的自动压缩与摘要回写。

## [0.3.0] - 2025-11-17

### 新增
- 上线 AI 驱动的攻击链图谱与风险评分。

## [0.2.0] - 2025-11-15

### 新增
- 提供大结果分页检索与外部 MCP 挂载能力。

## [0.1.1] - 2025-11-14

### 变更
- 工具检索优化至 O(1) 时间复杂度。
- 执行记录清理、数据库分页优化。

## [0.1.0] - 2025-11-13

### 新增
- Web 鉴权、Settings 面板与 MCP stdio 模式发布。
