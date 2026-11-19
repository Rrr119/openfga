# RBAC -> ReBAC 迁移能力

## 交付物
1. pkg/migration/rbac — RBAC 模型/分配 JSON(YAML) -> OpenFGA DSL + 关系元组
2. pkg/migration/batchwriter — 基于现有 Write API 的分片并发批量写入
3. cmd/rbacmigrate — CLI（dry-run 输出 / 经现有 HTTP API 写 store）
4. tests/rbacmigration — 10 万关系迁移+查询端到端测试 + 单测
