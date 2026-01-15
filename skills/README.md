# Skills 系统使用指南

## 概述

Skills系统允许你为角色配置专业知识和技能文档。当角色执行任务时，系统会自动将这些skills的内容注入到系统提示词中，帮助AI更好地理解和执行相关任务。

## Skills结构

每个skill是一个目录，包含一个`SKILL.md`文件：

```
skills/
├── sql-injection-testing/
│   └── SKILL.md
├── xss-testing/
│   └── SKILL.md
└── ...
```

## SKILL.md格式

SKILL.md文件支持YAML front matter格式（可选）：

```markdown
---
name: skill-name
description: Skill的简短描述
version: 1.0.0
---

# Skill标题

这里是skill的详细内容，可以包含：
- 测试方法
- 工具使用
- 最佳实践
- 示例代码
- 等等...
```

如果不使用front matter，整个文件内容都会被作为skill内容。

## 在角色中配置Skills

在角色配置文件中添加`skills`字段：

```yaml
name: 渗透测试
description: 专业渗透测试专家
user_prompt: 你是一个专业的网络安全渗透测试专家...
tools:
  - nmap
  - sqlmap
  - burpsuite
skills:
  - sql-injection-testing
  - xss-testing
enabled: true
```

`skills`字段是一个字符串数组，每个字符串是skill目录的名称。

## 工作原理

1. **加载阶段**：系统启动时，会扫描`skills_dir`目录下的所有skill
2. **执行阶段**：当使用某个角色执行任务时：
   - 系统会加载该角色配置的所有skills
   - 将skills内容合并并注入到系统提示词中
   - AI在执行任务前会阅读这些skills内容
3. **按需调用**：即使角色没有配置skills，AI也可以通过以下工具按需调用：
   - `list_skills`: 获取所有可用的skills列表
   - `read_skill`: 读取指定skill的详细内容
   
   这样AI可以在执行任务过程中，根据实际需要自主调用相关skills获取专业知识。

## 示例Skills

### sql-injection-testing

包含SQL注入测试的专业方法、工具使用、绕过技术等。

### xss-testing

包含XSS测试的各种类型、payload、绕过技术等。

## 创建自定义Skill

1. 在`skills`目录下创建新目录，例如`my-skill`
2. 在该目录下创建`SKILL.md`文件
3. 编写skill内容
4. 在角色配置中添加该skill名称

```bash
mkdir -p skills/my-skill
cat > skills/my-skill/SKILL.md << 'EOF'
---
name: my-skill
description: 我的自定义技能
---

# 我的自定义技能

这里是技能内容...
EOF
```

## 注意事项

- Skill内容会被注入到系统提示词中，注意控制长度避免超过token限制
- Skill内容应该清晰、结构化，便于AI理解
- 可以包含代码示例、命令示例等
- 建议每个skill专注于一个特定领域或技能

## 配置

在`config.yaml`中配置skills目录：

```yaml
skills_dir: skills  # 相对于配置文件所在目录
```

如果未配置，默认使用`skills`目录。
