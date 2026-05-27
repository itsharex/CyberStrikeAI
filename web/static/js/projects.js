/**
 * 项目管理与事实黑板
 */
let projectsCache = [];
let projectsCacheAll = [];
let currentProjectId = null;
let currentProjectTab = 'facts';
const projectNameById = {};
let _projectsListReady = false;
let _projectsFetchPromise = null;

const PROJECT_ACTIVE_KEY = 'cyberstrike.activeProjectId';

/** 与后端 internal/project/fact_template.go 对齐 */
const FACT_ATTACK_CHAIN_BODY_TEMPLATE = `## 结论（可验证，一句话）
<勿仅写「存在漏洞」；写明类型 + 位置 + 触发条件>

## 目标与入口
- 目标: <URL / IP:Port / 主机名>
- 入口: <路径 / 接口 / 参数>
- 前置条件: <匿名 / 角色 / Cookie / 其他依赖>

## 攻击链（逐步可复现）
1. <侦察/发现>
2. <利用/触发>
3. <影响证明（读文件、RCE 回显、越权数据等）>

## Exploit / POC
### 请求
\`\`\`http
<METHOD> <path> HTTP/1.1
Host: ...
...

<body>
\`\`\`

### 响应 / 现象
<关键响应片段、状态码、差异点>

### 命令 / 脚本（如有）
\`\`\`bash
<command>
\`\`\`

## 关键证据
- <工具输出摘要 / 截图路径 / 会话或消息 ID>

## 关联
- related_vulnerability_id: <可选>
- 依赖事实: <fact_key，如 auth/session_cookie>

## 备注与不确定性
<待验证假设、环境差异、绕过尝试记录>`;

const FACT_ENV_BODY_TEMPLATE = `## 摘要
<该事实的核心认知>

## 细节
<端口/版本/路径/凭据特征/业务规则等>

## 来源与证据
<命令输出、响应片段、发现时间>

## 关联
- 相关 fact_key: <可选>`;

const FACT_ATTACK_CHAIN_PREFIXES = ['finding/', 'chain/', 'exploit/', 'poc/'];
const FACT_ATTACK_CHAIN_CATEGORIES = new Set(['finding', 'chain', 'exploit', 'poc', 'vuln']);

function requiresAttackChainFact(category, factKey) {
    const c = (category || '').trim().toLowerCase();
    if (FACT_ATTACK_CHAIN_CATEGORIES.has(c)) return true;
    const key = (factKey || '').trim().toLowerCase();
    return FACT_ATTACK_CHAIN_PREFIXES.some((p) => key.startsWith(p));
}

function isSparseFactBody(category, factKey, body) {
    if (!requiresAttackChainFact(category, factKey)) return false;
    const text = (body || '').trim();
    if (!text) return true;
    const lower = text.toLowerCase();
    const hasSteps =
        lower.includes('攻击链') ||
        lower.includes('## 攻击') ||
        lower.includes('## exploit') ||
        lower.includes('## poc');
    const hasHTTP =
        lower.includes('```http') ||
        lower.includes('```bash') ||
        lower.includes('curl ') ||
        lower.includes('get ') ||
        lower.includes('post ');
    const hasReq = lower.includes('请求') || lower.includes('响应') || lower.includes('payload');
    return !(hasSteps || hasHTTP || hasReq);
}

function formatFactBodyBadge(f) {
    if (!requiresAttackChainFact(f.category, f.fact_key)) {
        const hasBody = !!(f.body || '').trim();
        return `<span class="projects-fact-badge projects-fact-badge--na" title="环境类事实">${hasBody ? '有详情' : '—'}</span>`;
    }
    if (isSparseFactBody(f.category, f.fact_key, f.body)) {
        return '<span class="projects-fact-badge projects-fact-badge--warn" title="缺少攻击链/POC 结构">待补全</span>';
    }
    return '<span class="projects-fact-badge projects-fact-badge--ok" title="含可复现结构">可复现</span>';
}

function updateFactFormHints() {
    const cat = document.getElementById('fact-modal-category')?.value || '';
    const key = document.getElementById('fact-modal-key')?.value || '';
    const body = document.getElementById('fact-modal-body')?.value || '';
    const hint = document.getElementById('fact-modal-body-hint');
    if (!hint) return;
    if (requiresAttackChainFact(cat, key)) {
        const sparse = isSparseFactBody(cat, key, body);
        hint.textContent = sparse
            ? '⚠ 攻击链类事实：请填写完整 body（步骤、HTTP/命令、响应现象），勿仅写结论。可点「插入攻击链模板」。'
            : '攻击链类：body 将用于审计复现，请保留原始请求/响应与逐步步骤。';
        hint.classList.toggle('projects-field-hint--warn', sparse);
    } else {
        hint.textContent = '环境认知类：body 建议记录来源证据；发现/利用请改用 finding|chain|exploit|poc 分类。';
        hint.classList.remove('projects-field-hint--warn');
    }
}

function insertFactBodyTemplate(kind) {
    const ta = document.getElementById('fact-modal-body');
    if (!ta) return;
    const tpl = kind === 'env' ? FACT_ENV_BODY_TEMPLATE : FACT_ATTACK_CHAIN_BODY_TEMPLATE;
    if (ta.value.trim() && !confirm('将覆盖当前 body 内容为模板，是否继续？')) return;
    ta.value = tpl;
    updateFactFormHints();
    ta.focus();
}

function getActiveProjectId() {
    try {
        return localStorage.getItem(PROJECT_ACTIVE_KEY) || '';
    } catch (e) {
        return '';
    }
}

function setActiveProjectId(id) {
    try {
        if (id) localStorage.setItem(PROJECT_ACTIVE_KEY, id);
        else localStorage.removeItem(PROJECT_ACTIVE_KEY);
    } catch (e) { /* ignore */ }
}

function rebuildProjectNameMap(list) {
    Object.keys(projectNameById).forEach((k) => delete projectNameById[k]);
    (list || []).forEach((p) => {
        if (p && p.id) projectNameById[p.id] = p.name || p.id;
    });
}

async function fetchProjectsList(includeArchived) {
    const showArchived = includeArchived || document.getElementById('projects-show-archived')?.checked;
    const url = showArchived ? '/api/projects?limit=200' : '/api/projects?status=active&limit=200';
    const res = await apiFetch(url);
    if (!res.ok) throw new Error('加载项目失败');
    const data = await res.json();
    projectsCache = Array.isArray(data) ? data : [];
    rebuildProjectNameMap(projectsCache);
    _projectsListReady = true;
    return projectsCache;
}

/** 对话页等项目选择器：确保列表已拉取（去重并发请求） */
async function ensureProjectsLoaded(force) {
    if (!force && _projectsListReady) return projectsCache;
    if (!force && _projectsFetchPromise) return _projectsFetchPromise;
    _projectsFetchPromise = fetchProjectsList(false)
        .catch((e) => {
            _projectsListReady = false;
            throw e;
        })
        .finally(() => {
            _projectsFetchPromise = null;
        });
    return _projectsFetchPromise;
}

function prefetchProjectsForChat() {
    ensureProjectsLoaded().catch(() => {});
}

/** 新对话时：保留有效 activeProjectId，否则默认选中第一个进行中的项目 */
async function ensureDefaultActiveProjectForNewChat() {
    try {
        await ensureProjectsLoaded();
        const cur = getActiveProjectId();
        if (cur && isActiveChatProjectId(cur)) return cur;
        const first =
            projectsCache.find((p) => p.pinned && p.status !== 'archived') ||
            projectsCache.find((p) => p.status !== 'archived');
        if (first) {
            setActiveProjectId(first.id);
            return first.id;
        }
    } catch (e) {
        console.warn(e);
    }
    return '';
}

function getProjectName(id) {
    return projectNameById[id] || id || '';
}

function initProjectsModalEscape() {
    if (window._projectsModalEscapeBound) return;
    window._projectsModalEscapeBound = true;
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (document.getElementById('project-modal')?.style.display === 'flex') closeProjectModal();
        else if (document.getElementById('fact-modal')?.style.display === 'flex') closeFactModal();
        else if (document.getElementById('fact-detail-modal')?.style.display === 'flex') closeFactDetailModal();
    });
}

async function initProjectsPage() {
    const page = document.getElementById('page-projects');
    if (!page || page.style.display === 'none') return;
    initProjectsModalEscape();
    updateProjectsDetailVisibility();
    await loadProjectsList();
    if (!currentProjectId && projectsCache.length) {
        const fromHash = new URLSearchParams(window.location.hash.split('?')[1] || '').get('id');
        currentProjectId = fromHash || projectsCache[0].id;
    }
    renderProjectsSidebar();
    if (currentProjectId) {
        await selectProject(currentProjectId);
    }
}

async function loadProjectsList() {
    await fetchProjectsList();
    renderProjectsSidebar();
    if (typeof refreshChatProjectSelector === 'function') {
        refreshChatProjectSelector();
    }
    if (typeof refreshVulnerabilityProjectFilter === 'function') {
        refreshVulnerabilityProjectFilter();
    }
}

function projectInitial(name) {
    const s = (name || 'P').trim();
    return s ? s.charAt(0).toUpperCase() : 'P';
}

function updateProjectsDetailVisibility() {
    const main = document.getElementById('projects-detail-main');
    const placeholder = document.getElementById('projects-detail-placeholder');
    const inner = document.getElementById('projects-detail-inner');
    const show = !!currentProjectId;
    if (main) main.classList.toggle('has-project', show);
    if (placeholder) placeholder.hidden = show;
    if (inner) inner.hidden = !show;
}

function updateProjectsListCount() {
    const el = document.getElementById('projects-list-count');
    if (el) el.textContent = String(projectsCache.length);
}

/** 事实分类 → 徽章样式（与 fact_template.go 常量对齐） */
const FACT_CATEGORY_BADGE = {
    target: 'projects-category--target',
    auth: 'projects-category--auth',
    infra: 'projects-category--infra',
    business: 'projects-category--business',
    finding: 'projects-category--finding',
    chain: 'projects-category--chain',
    exploit: 'projects-category--exploit',
    poc: 'projects-category--poc',
    note: 'projects-category--note',
    vuln: 'projects-category--exploit',
};

function formatCategoryBadge(category) {
    const raw = (category || '').trim();
    const c = raw.toLowerCase() || 'note';
    const cls = FACT_CATEGORY_BADGE[c] || 'projects-category--custom';
    return `<span class="projects-category ${cls}">${escapeHtml(raw || '—')}</span>`;
}

function formatConfidenceBadge(confidence) {
    const c = (confidence || '').toLowerCase();
    let cls = 'projects-confidence--tentative';
    let label = c || '—';
    if (c === 'confirmed') {
        cls = 'projects-confidence--confirmed';
        label = '已确认';
    } else if (c === 'deprecated') {
        cls = 'projects-confidence--deprecated';
        label = '已废弃';
    } else if (c === 'tentative') {
        label = '待确认';
    }
    return `<span class="projects-confidence ${cls}">${escapeHtml(label)}</span>`;
}

function renderProjectFactActions(keyEsc, idEsc, confidence) {
    const isDeprecated = (confidence || '').toLowerCase() === 'deprecated';
    const toggleBtn = isDeprecated
        ? `<button type="button" class="projects-action-btn projects-action-btn--restore" data-fact-key="${keyEsc}" onclick="restoreProjectFactByKey(this.dataset.factKey)" title="恢复为待确认并重新进入黑板索引">恢复</button>`
        : `<button type="button" class="projects-action-btn projects-action-btn--mute" data-fact-key="${keyEsc}" onclick="deprecateProjectFactByKey(this.dataset.factKey)" title="标记为已废弃">废弃</button>`;
    return `<div class="projects-table-actions">
        <button type="button" class="projects-action-btn projects-action-btn--edit" data-fact-key="${keyEsc}" onclick="showEditFactModal(this.dataset.factKey)" title="编辑各字段">编辑</button>
        <button type="button" class="projects-action-btn projects-action-btn--view" data-fact-key="${keyEsc}" onclick="viewProjectFactBody(this.dataset.factKey)" title="查看完整 body">详情</button>
        ${toggleBtn}
        <button type="button" class="projects-action-btn projects-action-btn--danger" data-fact-id="${idEsc}" onclick="deleteProjectFact(this.dataset.factId)" title="永久删除">删除</button>
    </div>`;
}

function formatSeverityBadge(severity) {
    const s = (severity || 'info').toLowerCase();
    const cls = 'projects-severity--' + (['critical', 'high', 'medium', 'low', 'info'].includes(s) ? s : 'info');
    return `<span class="projects-severity ${cls}">${escapeHtml(severity || '—')}</span>`;
}

function getProjectsListFilter() {
    return (document.getElementById('projects-list-search')?.value || '').trim().toLowerCase();
}

function filterProjectsList() {
    renderProjectsSidebar();
}

function renderProjectsSidebar() {
    const el = document.getElementById('projects-list');
    if (!el) return;
    updateProjectsListCount();
    const q = getProjectsListFilter();
    const list = q
        ? projectsCache.filter((p) => (p.name || '').toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q))
        : projectsCache;
    if (!projectsCache.length) {
        el.innerHTML =
            '<div class="projects-empty">暂无项目<br><button type="button" class="btn-primary btn-small projects-empty-btn" onclick="showNewProjectModal()">新建项目</button></div>';
        updateProjectsDetailVisibility();
        return;
    }
    if (!list.length) {
        el.innerHTML = '<div class="projects-empty">无匹配项目</div>';
        updateProjectsDetailVisibility();
        return;
    }
    el.innerHTML = list.map((p) => {
        const active = p.id === currentProjectId ? ' is-active' : '';
        const archived = p.status === 'archived' ? ' is-archived' : '';
        const badges = [
            p.pinned ? '<span class="projects-list-item-badge">置顶</span>' : '',
            p.status === 'archived' ? '<span class="projects-list-item-badge">归档</span>' : '',
        ].join('');
        return `<div class="projects-list-item${active}${archived}" data-id="${escapeHtml(p.id)}" onclick="selectProject('${escapeHtml(p.id)}')">
            <div class="projects-list-item-body">
                <div class="projects-list-item-name">${escapeHtml(p.name)}${badges}</div>
                <div class="projects-list-item-meta">${formatProjectTime(p.updated_at)}</div>
            </div>
        </div>`;
    }).join('');
    updateProjectsDetailVisibility();
}

function updateProjectStatusPill(status) {
    const el = document.getElementById('projects-detail-status');
    if (!el) return;
    const archived = status === 'archived';
    el.textContent = archived ? '已归档' : '进行中';
    el.className = 'projects-status-pill ' + (archived ? 'projects-status-pill--archived' : 'projects-status-pill--active');
}

function updateProjectStats(stats) {
    const s = stats || {};
    const f = document.getElementById('project-stat-facts');
    const v = document.getElementById('project-stat-vulns');
    const c = document.getElementById('project-stat-conversations');
    const sparse = document.getElementById('project-stat-sparse');
    const fc = s.fact_count ?? s.factCount ?? 0;
    const vc = s.vuln_count ?? s.vulnCount ?? 0;
    const cc = s.conversation_count ?? s.conversationCount ?? 0;
    const sc = s.sparse_fact_count ?? s.sparseFactCount ?? 0;
    if (f) f.textContent = `${fc} 条事实`;
    if (v) v.textContent = `${vc} 个漏洞`;
    if (c) c.textContent = `${cc} 个对话`;
    if (sparse) {
        if (sc > 0) {
            sparse.hidden = false;
            sparse.textContent = `${sc} 待补全`;
        } else {
            sparse.hidden = true;
        }
    }
}

async function selectProject(id) {
    currentProjectId = id;
    const searchEl = document.getElementById('project-facts-search');
    const catEl = document.getElementById('project-facts-filter-category');
    const confEl = document.getElementById('project-facts-filter-confidence');
    const sparseEl = document.getElementById('project-facts-filter-sparse');
    if (searchEl) searchEl.value = '';
    if (catEl) catEl.value = '';
    if (confEl) confEl.value = '';
    if (sparseEl) sparseEl.checked = false;
    renderProjectsSidebar();
    updateProjectsDetailVisibility();
    try {
        const res = await apiFetch(`/api/projects/${id}`);
        if (!res.ok) throw new Error('项目不存在');
        const p = await res.json();
        const titleEl = document.getElementById('projects-detail-title');
        if (titleEl) titleEl.textContent = p.name || '项目';
        document.getElementById('project-edit-name').value = p.name || '';
        document.getElementById('project-edit-description').value = p.description || '';
        document.getElementById('project-edit-scope').value = p.scope_json || '';
        const statusEl = document.getElementById('project-edit-status');
        if (statusEl) statusEl.value = p.status || 'active';
        const pinEl = document.getElementById('project-edit-pinned');
        if (pinEl) pinEl.checked = !!p.pinned;
        updateProjectStatusPill(p.status || 'active');
        const metaEl = document.getElementById('projects-detail-meta');
        if (metaEl) metaEl.textContent = `更新于 ${formatProjectTime(p.updated_at)}`;
        const descEl = document.getElementById('projects-detail-desc');
        if (descEl) {
            const desc = (p.description || '').trim();
            if (desc) {
                descEl.textContent = desc;
                descEl.hidden = false;
            } else {
                descEl.textContent = '';
                descEl.hidden = true;
            }
        }
        projectNameById[p.id] = p.name || p.id;
    } catch (e) {
        console.warn(e);
    }
    await refreshProjectHeaderStats();
    switchProjectTab(currentProjectTab);
}

function switchProjectTab(tab) {
    currentProjectTab = tab;
    ['facts', 'conversations', 'vulns', 'settings'].forEach((t) => {
        const btn = document.getElementById(`project-tab-${t}`);
        const panel = document.getElementById(`project-panel-${t}`);
        if (btn) btn.classList.toggle('is-active', t === tab);
        if (panel) panel.hidden = t !== tab;
    });
    if (tab === 'facts') loadProjectFacts();
    if (tab === 'conversations') loadProjectConversations();
    if (tab === 'vulns') loadProjectVulnerabilities();
}

function buildProjectFactsQueryParams() {
    const params = new URLSearchParams();
    params.set('limit', '200');
    const search = document.getElementById('project-facts-search')?.value?.trim();
    const category = document.getElementById('project-facts-filter-category')?.value?.trim();
    const confidence = document.getElementById('project-facts-filter-confidence')?.value?.trim();
    const sparseOnly = document.getElementById('project-facts-filter-sparse')?.checked;
    const hideDeprecated = document.getElementById('project-facts-filter-hide-deprecated')?.checked;
    if (search) params.set('search', search);
    if (category) params.set('category', category);
    if (confidence) params.set('confidence', confidence);
    if (sparseOnly) params.set('sparse_only', 'true');
    if (hideDeprecated) params.set('exclude_deprecated', 'true');
    return params;
}

function debouncedLoadProjectFacts() {
    if (_projectFactsFilterDebounce) clearTimeout(_projectFactsFilterDebounce);
    _projectFactsFilterDebounce = setTimeout(() => {
        _projectFactsFilterDebounce = null;
        loadProjectFacts();
    }, 280);
}

async function loadProjectFacts() {
    const tbody = document.getElementById('project-facts-tbody');
    if (!tbody || !currentProjectId) return;
    tbody.innerHTML = '<tr class="is-empty-row"><td colspan="7">加载中…</td></tr>';
    const qs = buildProjectFactsQueryParams().toString();
    const res = await apiFetch(`/api/projects/${currentProjectId}/facts?${qs}`);
    if (!res.ok) {
        tbody.innerHTML = '<tr class="is-empty-row"><td colspan="7">加载失败</td></tr>';
        return;
    }
    const facts = await res.json();
    if (!facts.length) {
        const hasFilter =
            document.getElementById('project-facts-search')?.value?.trim() ||
            document.getElementById('project-facts-filter-category')?.value ||
            document.getElementById('project-facts-filter-confidence')?.value ||
            document.getElementById('project-facts-filter-sparse')?.checked;
        tbody.innerHTML = `<tr class="is-empty-row"><td colspan="7">${
            hasFilter ? '无匹配事实，请调整筛选条件' : '暂无事实，点击「添加事实」或由 Agent 自动写入'
        }</td></tr>`;
        refreshProjectHeaderStats();
        return;
    }
    tbody.innerHTML = facts.map((f) => {
        const keyEsc = escapeHtml(f.fact_key);
        const idEsc = escapeHtml(f.id);
        const vulnLink = f.related_vulnerability_id
            ? `<span class="projects-fact-vuln-link" title="关联漏洞 ID">${escapeHtml(f.related_vulnerability_id.slice(0, 8))}…</span>`
            : '';
        return `<tr>
            <td><code>${keyEsc}</code>${vulnLink}</td>
            <td>${formatCategoryBadge(f.category)}</td>
            <td class="cell-summary" title="${escapeHtml(f.summary)}">${escapeHtml(f.summary)}</td>
            <td>${formatFactBodyBadge(f)}</td>
            <td>${formatConfidenceBadge(f.confidence)}</td>
            <td>${formatProjectTime(f.updated_at, f.created_at)}</td>
            <td class="col-actions">${renderProjectFactActions(keyEsc, idEsc, f.confidence)}</td>
        </tr>`;
    }).join('');
    refreshProjectHeaderStats();
}

async function refreshProjectHeaderStats() {
    if (!currentProjectId) return;
    try {
        const res = await apiFetch(`/api/projects/${currentProjectId}/stats`);
        if (!res.ok) return;
        const stats = await res.json();
        updateProjectStats(stats);
    } catch (e) {
        console.warn(e);
    }
}

async function loadProjectConversations() {
    const tbody = document.getElementById('project-conversations-tbody');
    if (!tbody || !currentProjectId) return;
    tbody.innerHTML = '<tr class="is-empty-row"><td colspan="3">加载中…</td></tr>';
    const res = await apiFetch(`/api/projects/${currentProjectId}/conversations?limit=100`);
    if (!res.ok) {
        tbody.innerHTML = '<tr class="is-empty-row"><td colspan="3">加载失败</td></tr>';
        return;
    }
    const data = await res.json();
    const items = data.conversations || [];
    if (!items.length) {
        tbody.innerHTML =
            '<tr class="is-empty-row"><td colspan="3">暂无绑定对话；在对话页选择本项目即可关联</td></tr>';
        return;
    }
    tbody.innerHTML = items
        .map((conv) => {
            const id = conv.id;
            const idEsc = escapeHtml(id);
            const title = escapeHtml(conv.title || '未命名对话');
            const updated = formatProjectTime(conv.updatedAt || conv.updated_at, conv.createdAt || conv.created_at);
            return `<tr>
            <td class="cell-summary" title="${title}">${title}</td>
            <td>${escapeHtml(updated)}</td>
            <td class="col-actions">
                <div class="projects-table-actions">
                    <button type="button" class="projects-action-btn projects-action-btn--view" data-conv-id="${idEsc}" onclick="openProjectConversation(this.dataset.convId)">打开</button>
                    <button type="button" class="projects-action-btn projects-action-btn--mute" data-conv-id="${idEsc}" onclick="unbindConversationFromProject(this.dataset.convId)" title="解除项目绑定">解绑</button>
                </div>
            </td>
        </tr>`;
        })
        .join('');
}

function openProjectConversation(conversationId) {
    if (!conversationId) return;
    if (typeof switchPage === 'function') {
        switchPage('chat');
    }
    setTimeout(() => {
        if (typeof loadConversation === 'function') {
            loadConversation(conversationId);
        }
    }, 200);
}

async function unbindConversationFromProject(conversationId) {
    if (!conversationId || !confirm('解除该对话与当前项目的绑定？')) return;
    const res = await apiFetch(`/api/conversations/${encodeURIComponent(conversationId)}/project`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId: '' }),
    });
    if (!res.ok) return alert('解绑失败');
    loadProjectConversations();
    refreshProjectHeaderStats();
}

let _factDetailKey = null;
let _factDetailFact = null;
let _projectFactsFilterDebounce = null;

async function viewProjectFactBody(factKey) {
    const res = await apiFetch(`/api/projects/${currentProjectId}/facts?fact_key=${encodeURIComponent(factKey)}`);
    if (!res.ok) return alert('加载失败');
    const f = await res.json();
    _factDetailKey = f.fact_key;
    _factDetailFact = f;
    document.getElementById('fact-detail-title').textContent = `[${f.fact_key}]`;
    const metaParts = [
        `分类: ${f.category}`,
        `置信度: ${f.confidence}`,
        `更新: ${formatProjectTime(f.updated_at, f.created_at)}`,
    ];
    if (f.related_vulnerability_id) metaParts.push(`关联漏洞: ${f.related_vulnerability_id}`);
    if (f.source_conversation_id) metaParts.push(`来源对话: ${f.source_conversation_id}`);
    if (f.supersedes_fact_id) metaParts.push('含上一版本');
    document.getElementById('fact-detail-meta').textContent = metaParts.join(' · ');
    document.getElementById('fact-detail-body').textContent = f.body || '(无 body)';
    const warnEl = document.getElementById('fact-detail-sparse-warn');
    if (warnEl) {
        if (isSparseFactBody(f.category, f.fact_key, f.body)) {
            warnEl.hidden = false;
            warnEl.textContent =
                '⚠ 该事实属于攻击链/利用类，但 body 缺少可复现结构（攻击链步骤、HTTP/命令、请求响应等）。建议编辑后补全以便审计复现。';
        } else {
            warnEl.hidden = true;
            warnEl.textContent = '';
        }
    }
    const prevWrap = document.getElementById('fact-detail-prev-wrap');
    if (prevWrap) {
        prevWrap.hidden = true;
        if (f.id && f.supersedes_fact_id) {
            try {
                const prevRes = await apiFetch(
                    `/api/projects/${currentProjectId}/facts/${encodeURIComponent(f.id)}/previous-version`,
                );
                if (prevRes.ok) {
                    const prev = await prevRes.json();
                    prevWrap.hidden = false;
                    document.getElementById('fact-detail-prev-meta').textContent =
                        `归档于 ${formatProjectTime(prev.archived_at)} · 摘要: ${prev.summary || '—'} · 置信度: ${prev.confidence || '—'}`;
                    document.getElementById('fact-detail-prev-body').textContent = prev.body || '(无 body)';
                }
            } catch (e) {
                console.warn(e);
            }
        }
    }
    const linkBtn = document.getElementById('fact-detail-link-vuln-btn');
    const createBtn = document.getElementById('fact-detail-create-vuln-btn');
    if (linkBtn) linkBtn.hidden = false;
    if (createBtn) createBtn.hidden = false;
    openProjectsOverlay('fact-detail-modal');
}

function editFactFromDetail() {
    const key = _factDetailKey;
    closeFactDetailModal();
    if (key) showEditFactModal(key);
}

function closeFactDetailModal() {
    closeProjectsOverlay('fact-detail-modal');
    _factDetailKey = null;
    _factDetailFact = null;
}

async function linkFactToExistingVulnerability() {
    const f = _factDetailFact;
    if (!f || !currentProjectId) return;
    const res = await apiFetch(`/api/vulnerabilities?project_id=${encodeURIComponent(currentProjectId)}&limit=50`);
    if (!res.ok) return alert('加载漏洞列表失败');
    const data = await res.json();
    const items = data.Vulnerabilities || data.vulnerabilities || data.items || [];
    if (!items.length) return alert('本项目暂无漏洞，请先创建或让 Agent 记录漏洞');
    const lines = items.map((v, i) => `${i + 1}. [${v.severity}] ${v.title} (${v.id})`);
    const pick = prompt(`输入序号以关联事实「${f.fact_key}」：\n\n${lines.join('\n')}`);
    if (pick == null || pick === '') return;
    const idx = parseInt(pick, 10) - 1;
    if (Number.isNaN(idx) || idx < 0 || idx >= items.length) return alert('序号无效');
    const vulnId = items[idx].id;
    const upd = await apiFetch(`/api/projects/${currentProjectId}/facts/${encodeURIComponent(f.id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            fact_key: f.fact_key,
            category: f.category,
            summary: f.summary,
            body: f.body || '',
            confidence: f.confidence,
            related_vulnerability_id: vulnId,
        }),
    });
    if (!upd.ok) return alert('关联失败');
    alert('已关联漏洞');
    closeFactDetailModal();
    loadProjectFacts();
}

async function createVulnerabilityFromCurrentFact() {
    const f = _factDetailFact;
    if (!f || !currentProjectId) return;
    let convId =
        (f.source_conversation_id || '').trim() ||
        (typeof window.currentConversationId === 'string' ? window.currentConversationId.trim() : '');
    if (!convId) {
        convId = prompt('创建漏洞需要对话 ID（可与来源会话一致）：', '')?.trim() || '';
    }
    if (!convId) return alert('已取消：未提供 conversation_id');
    const severity = inferSeverityFromFact(f);
    const body = {
        conversation_id: convId,
        project_id: currentProjectId,
        title: (f.summary || f.fact_key).slice(0, 200),
        description: `由项目事实 ${f.fact_key} 生成`,
        severity,
        status: 'open',
        type: f.category || 'finding',
        target: '',
        proof: f.body || '',
        impact: '',
        recommendation: '',
    };
    const res = await apiFetch('/api/vulnerabilities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        return alert(err.error || '创建漏洞失败');
    }
    const vuln = await res.json();
    await apiFetch(`/api/projects/${currentProjectId}/facts/${encodeURIComponent(f.id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            fact_key: f.fact_key,
            category: f.category,
            summary: f.summary,
            body: f.body || '',
            confidence: f.confidence,
            related_vulnerability_id: vuln.id,
        }),
    });
    alert(`已创建漏洞并关联：${vuln.title || vuln.id}`);
    closeFactDetailModal();
    loadProjectFacts();
    if (currentProjectTab === 'vulns') loadProjectVulnerabilities();
}

function inferSeverityFromFact(f) {
    const c = (f.category || '').toLowerCase();
    const key = (f.fact_key || '').toLowerCase();
    if (c === 'exploit' || c === 'poc' || key.includes('rce') || key.includes('sqli')) return 'high';
    if (c === 'finding' || c === 'chain') return 'medium';
    return 'medium';
}

async function deprecateProjectFactByKey(factKey) {
    if (!confirm(`将事实 ${factKey} 标记为已废弃？`)) return;
    const res = await apiFetch(`/api/projects/${currentProjectId}/facts/deprecate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fact_key: factKey }),
    });
    if (!res.ok) return alert('操作失败');
    loadProjectFacts();
}

async function restoreProjectFactByKey(factKey) {
    if (!confirm(`恢复事实 ${factKey}？将重新进入黑板索引（状态：待确认）。`)) return;
    const res = await apiFetch(`/api/projects/${currentProjectId}/facts/restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fact_key: factKey, confidence: 'tentative' }),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        return alert(err.error || '操作失败');
    }
    loadProjectFacts();
}

function openVulnerabilitiesForProject(projectId) {
    const pid = projectId || currentProjectId;
    if (!pid) return;
    if (typeof switchPage === 'function') {
        switchPage('vulnerabilities');
    }
    if (typeof window.setVulnerabilityProjectFilter === 'function') {
        window.setVulnerabilityProjectFilter(pid);
    } else {
        window.location.hash = `vulnerabilities?project_id=${encodeURIComponent(pid)}`;
    }
}

async function loadProjectVulnerabilities() {
    const tbody = document.getElementById('project-vulns-tbody');
    if (!tbody || !currentProjectId) return;
    tbody.innerHTML = '<tr class="is-empty-row"><td colspan="4">加载中…</td></tr>';
    const res = await apiFetch(`/api/vulnerabilities?project_id=${encodeURIComponent(currentProjectId)}&limit=100`);
    if (!res.ok) {
        tbody.innerHTML = '<tr class="is-empty-row"><td colspan="4">加载失败</td></tr>';
        return;
    }
    const data = await res.json();
    const items = data.Vulnerabilities || data.vulnerabilities || data.items || [];
    if (!items.length) {
        tbody.innerHTML = '<tr class="is-empty-row"><td colspan="4">本项目暂无漏洞记录</td></tr>';
        refreshProjectHeaderStats();
        return;
    }
    tbody.innerHTML = items.map((v) => {
        const idEsc = escapeHtml(v.id);
        return `<tr>
            <td class="cell-summary" title="${escapeHtml(v.title)}">${escapeHtml(v.title)}</td>
            <td>${formatSeverityBadge(v.severity)}</td>
            <td>${escapeHtml(v.status)}</td>
            <td class="col-actions">
                <div class="projects-table-actions">
                    <button type="button" class="projects-action-btn projects-action-btn--view" data-vuln-id="${idEsc}" onclick="openVulnerabilityDetail(this.dataset.vulnId)">查看</button>
                    <button type="button" class="projects-action-btn projects-action-btn--view" data-vuln-id="${idEsc}" onclick="viewFactsForVulnerability(this.dataset.vulnId)" title="查看关联事实">事实</button>
                </div>
            </td>
        </tr>`;
    }).join('');
    refreshProjectHeaderStats();
}

function openVulnerabilityDetail(vulnId) {
    openVulnerabilitiesForProject(currentProjectId);
    if (typeof window.setVulnerabilityIdFilter === 'function') {
        setTimeout(() => window.setVulnerabilityIdFilter(vulnId), 300);
    }
}

async function viewFactsForVulnerability(vulnId) {
    if (!currentProjectId) return;
    switchProjectTab('facts');
    const searchEl = document.getElementById('project-facts-search');
    const catEl = document.getElementById('project-facts-filter-category');
    const confEl = document.getElementById('project-facts-filter-confidence');
    const sparseEl = document.getElementById('project-facts-filter-sparse');
    const hideDepEl = document.getElementById('project-facts-filter-hide-deprecated');
    if (searchEl) searchEl.value = '';
    if (catEl) catEl.value = '';
    if (confEl) confEl.value = '';
    if (sparseEl) sparseEl.checked = false;
    if (hideDepEl) hideDepEl.checked = true;
    const params = new URLSearchParams({ limit: '50', related_vulnerability_id: vulnId });
    const res = await apiFetch(`/api/projects/${currentProjectId}/facts?${params}`);
    if (!res.ok) return alert('加载关联事实失败');
    const facts = await res.json();
    if (!facts.length) {
        alert('该漏洞暂无关联事实，可在事实详情中「关联漏洞」或「生成漏洞草稿」建立链接');
        loadProjectFacts();
        return;
    }
    if (facts.length === 1) {
        viewProjectFactBody(facts[0].fact_key);
        return;
    }
    const pick = prompt(
        `该漏洞关联 ${facts.length} 条事实，输入序号查看：\n${facts.map((f, i) => `${i + 1}. ${f.fact_key}`).join('\n')}`,
    );
    if (pick == null || pick === '') {
        loadProjectFacts();
        return;
    }
    const idx = parseInt(pick, 10) - 1;
    if (facts[idx]) viewProjectFactBody(facts[idx].fact_key);
    else loadProjectFacts();
}

function openProjectsOverlay(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = 'flex';
    document.body.classList.add('projects-modal-open');
    const focusTarget = el.querySelector('input.form-input, textarea.form-input, select.form-input');
    if (focusTarget) {
        setTimeout(() => focusTarget.focus(), 80);
    }
}

function closeProjectsOverlay(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
    const anyOpen = document.querySelector('.projects-modal-overlay[style*="flex"]');
    if (!anyOpen) document.body.classList.remove('projects-modal-open');
}

function showNewProjectModal() {
    document.getElementById('project-modal-title').textContent = '新建项目';
    const sub = document.getElementById('project-modal-subtitle');
    if (sub) sub.textContent = '创建后可绑定对话，跨会话共享事实黑板';
    const submitBtn = document.getElementById('project-modal-submit-btn');
    if (submitBtn) submitBtn.textContent = '创建项目';
    document.getElementById('project-modal-name').value = '';
    document.getElementById('project-modal-description').value = '';
    window._projectModalEditId = null;
    openProjectsOverlay('project-modal');
}

/** 从对话区「选择项目」面板打开新建项目，创建成功后自动绑定当前对话 */
function showNewProjectModalFromChat() {
    closeChatProjectPanel();
    window._projectModalFromChat = true;
    showNewProjectModal();
}

async function saveProjectModal() {
    const name = document.getElementById('project-modal-name').value.trim();
    if (!name) return alert('请输入项目名称');
    const body = {
        name,
        description: document.getElementById('project-modal-description').value.trim(),
    };
    const editId = window._projectModalEditId;
    const res = editId
        ? await apiFetch(`/api/projects/${editId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        : await apiFetch('/api/projects', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || '保存失败');
        return;
    }
    const fromChat = !!window._projectModalFromChat;
    window._projectModalFromChat = false;
    closeProjectModal();
    const saved = await res.json();
    await loadProjectsList();
    if (saved.id) {
        if (fromChat && !editId) {
            await applyChatProjectSelection(saved.id);
        } else {
            await selectProject(saved.id);
        }
    }
}

function closeProjectModal() {
    window._projectModalFromChat = false;
    closeProjectsOverlay('project-modal');
}

function formatProjectScopeJson() {
    const el = document.getElementById('project-edit-scope');
    if (!el) return;
    const raw = el.value.trim();
    if (!raw) return;
    try {
        el.value = JSON.stringify(JSON.parse(raw), null, 2);
    } catch (e) {
        alert('JSON 格式无效：' + (e.message || String(e)));
    }
}

function insertProjectScopeExample() {
    const el = document.getElementById('project-edit-scope');
    if (!el) return;
    const example = {
        targets: ['https://example.com'],
        exclude: ['*.cdn.example.com'],
        notes: '仅授权 Web 应用层测试',
    };
    el.value = JSON.stringify(example, null, 2);
    el.focus();
}

async function saveProjectSettings() {
    if (!currentProjectId) return;
    const scopeRaw = document.getElementById('project-edit-scope').value.trim();
    if (scopeRaw) {
        try {
            JSON.parse(scopeRaw);
        } catch (e) {
            alert('测试范围 JSON 无效，请先修正或点击「格式化」：' + (e.message || String(e)));
            return;
        }
    }
    const body = {
        name: document.getElementById('project-edit-name').value.trim(),
        description: document.getElementById('project-edit-description').value.trim(),
        scope_json: scopeRaw,
        status: document.getElementById('project-edit-status')?.value || 'active',
        pinned: !!document.getElementById('project-edit-pinned')?.checked,
    };
    const res = await apiFetch(`/api/projects/${currentProjectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!res.ok) return alert('保存失败');
    await loadProjectsList();
    await selectProject(currentProjectId);
    alert('已保存');
}

async function archiveCurrentProject() {
    if (!currentProjectId) return;
    const statusEl = document.getElementById('project-edit-status');
    const cur = statusEl?.value || 'active';
    const next = cur === 'archived' ? 'active' : 'archived';
    if (!confirm(next === 'archived' ? '归档后默认不再出现在活跃列表，是否继续？' : '恢复为 active？')) return;
    const res = await apiFetch(`/api/projects/${currentProjectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: next }),
    });
    if (!res.ok) return alert('操作失败');
    await loadProjectsList();
    await selectProject(currentProjectId);
}

async function deleteCurrentProject() {
    if (!currentProjectId || !confirm('确定删除该项目？事实将一并删除，对话将解除绑定。')) return;
    const deletedId = currentProjectId;
    const deletedIndex = projectsCache.findIndex((p) => p.id === deletedId);
    const res = await apiFetch(`/api/projects/${deletedId}`, { method: 'DELETE' });
    if (!res.ok) return alert('删除失败');
    if (getActiveProjectId() === deletedId) setActiveProjectId('');
    currentProjectId = null;
    await loadProjectsList();
    if (projectsCache.length) {
        const nextIndex = Math.min(deletedIndex >= 0 ? deletedIndex : 0, projectsCache.length - 1);
        await selectProject(projectsCache[nextIndex].id);
    } else {
        updateProjectsDetailVisibility();
    }
}

function resetFactModalForm() {
    window._factModalEditId = null;
    const keyEl = document.getElementById('fact-modal-key');
    if (keyEl) keyEl.disabled = false;
    document.getElementById('fact-modal-title').textContent = '添加事实';
    document.getElementById('fact-modal-submit-btn').textContent = '保存事实';
    document.getElementById('fact-modal-key').value = '';
    document.getElementById('fact-modal-category').value = 'note';
    document.getElementById('fact-modal-summary').value = '';
    document.getElementById('fact-modal-body').value = '';
    document.getElementById('fact-modal-confidence').value = 'tentative';
    const rel = document.getElementById('fact-modal-related-vuln');
    if (rel) rel.value = '';
    updateFactFormHints();
}

function fillFactModalForm(f) {
    window._factModalEditId = f.id;
    document.getElementById('fact-modal-title').textContent = '编辑事实';
    document.getElementById('fact-modal-submit-btn').textContent = '保存修改';
    document.getElementById('fact-modal-key').value = f.fact_key || '';
    const catEl = document.getElementById('fact-modal-category');
    const cat = (f.category || 'note').trim().toLowerCase();
    if (catEl) {
        const known = Array.from(catEl.options).some((o) => o.value === cat);
        if (known) catEl.value = cat;
        else {
            const opt = document.createElement('option');
            opt.value = f.category;
            opt.textContent = `${f.category}（自定义）`;
            catEl.appendChild(opt);
            catEl.value = f.category;
        }
    }
    document.getElementById('fact-modal-summary').value = f.summary || '';
    document.getElementById('fact-modal-body').value = f.body || '';
    const conf = (f.confidence || 'tentative').toLowerCase();
    const confEl = document.getElementById('fact-modal-confidence');
    if (confEl) {
        const allowed = ['tentative', 'confirmed', 'deprecated'];
        confEl.value = allowed.includes(conf) ? conf : 'tentative';
    }
    const rel = document.getElementById('fact-modal-related-vuln');
    if (rel) rel.value = f.related_vulnerability_id || '';
    updateFactFormHints();
}

function showAddFactModal() {
    if (!currentProjectId) return alert('请先选择项目');
    resetFactModalForm();
    openProjectsOverlay('fact-modal');
}

async function showEditFactModal(factKey) {
    if (!currentProjectId) return alert('请先选择项目');
    const res = await apiFetch(
        `/api/projects/${currentProjectId}/facts?fact_key=${encodeURIComponent(factKey)}`,
    );
    if (!res.ok) return alert('加载事实失败');
    const f = await res.json();
    resetFactModalForm();
    fillFactModalForm(f);
    openProjectsOverlay('fact-modal');
}

function closeFactModal() {
    closeProjectsOverlay('fact-modal');
    resetFactModalForm();
}

async function saveFactModal() {
    const fact_key = document.getElementById('fact-modal-key').value.trim();
    const summary = document.getElementById('fact-modal-summary').value.trim();
    const category = document.getElementById('fact-modal-category').value.trim() || 'note';
    const body = document.getElementById('fact-modal-body').value;
    if (!fact_key || !summary) return alert('fact_key 与 summary 必填');
    if (isSparseFactBody(category, fact_key, body)) {
        const ok = confirm(
            '该事实属于攻击链/利用类，但 body 尚未包含可复现结构（步骤、HTTP/命令、请求响应等）。\n仍要保存吗？建议先插入攻击链模板并填写 POC。',
        );
        if (!ok) return;
    }
    const payload = {
        fact_key,
        category,
        summary,
        body,
        confidence: document.getElementById('fact-modal-confidence').value,
        related_vulnerability_id: document.getElementById('fact-modal-related-vuln')?.value?.trim() || '',
    };
    const editId = window._factModalEditId;
    const res = editId
        ? await apiFetch(`/api/projects/${currentProjectId}/facts/${editId}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
          })
        : await apiFetch(`/api/projects/${currentProjectId}/facts`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
          });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        return alert(err.error || '保存失败');
    }
    closeFactModal();
    loadProjectFacts();
}

async function deleteProjectFact(id) {
    if (!confirm('删除该事实？')) return;
    await apiFetch(`/api/projects/${currentProjectId}/facts/${id}`, { method: 'DELETE' });
    loadProjectFacts();
}

function parseProjectDate(t) {
    if (t == null || t === '') return null;
    if (typeof t === 'number' && Number.isFinite(t)) {
        const d = new Date(t);
        return isNaN(d.getTime()) || d.getFullYear() < 2000 ? null : d;
    }
    let s = String(t).trim();
    if (!s || s.startsWith('0001-01-01')) return null;
    let d = new Date(s);
    if (!isNaN(d.getTime()) && d.getFullYear() >= 2000) return d;
    const m = s.match(
        /^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz]|([+-])(\d{2}):?(\d{2}))?)?$/,
    );
    if (m) {
        const ms = m[7] ? parseInt(String(m[7]).slice(0, 3).padEnd(3, '0'), 10) : 0;
        let offMin = 0;
        if (m[8] && m[9] && m[10]) {
            offMin = parseInt(m[10], 10) * 60 + parseInt(m[11] || '0', 10);
            if (m[9] === '-') offMin = -offMin;
        }
        d = new Date(
            Date.UTC(
                parseInt(m[1], 10),
                parseInt(m[2], 10) - 1,
                parseInt(m[3], 10),
                parseInt(m[4], 10),
                parseInt(m[5], 10),
                parseInt(m[6], 10),
                ms,
            ) - offMin * 60 * 1000,
        );
        if (!isNaN(d.getTime()) && d.getFullYear() >= 2000) return d;
    }
    return null;
}

function formatProjectTime(t, fallback) {
    const d = parseProjectDate(t) || (fallback != null ? parseProjectDate(fallback) : null);
    if (!d) return '尚未更新';
    const now = Date.now();
    const diff = now - d.getTime();
    if (diff < 60000) return '刚刚';
    if (diff < 3600000) return `${Math.floor(diff / 60000)} 分钟前`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} 小时前`;
    if (diff < 604800000) return `${Math.floor(diff / 86400000)} 天前`;
    return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function getChatProjectSelection() {
    const convId = window.currentConversationId;
    if (convId) {
        return window._loadedConversationProjectId || '';
    }
    return getActiveProjectId();
}

function isActiveChatProjectId(id) {
    if (!id) return false;
    return projectsCache.some((p) => p.id === id && p.status !== 'archived');
}

/** 用于 UI：无效/已删除/无可用项目时视为未绑定 */
function resolveChatProjectSelection() {
    const raw = getChatProjectSelection();
    if (!raw) return '';
    if (!_projectsListReady) return raw;
    return isActiveChatProjectId(raw) ? raw : '';
}

let _normalizingStaleProject = false;

/** 项目列表加载后，清除 localStorage 或对话上残留的失效项目 ID */
async function normalizeStaleChatProjectSelection() {
    if (!_projectsListReady || _normalizingStaleProject) return;
    const raw = getChatProjectSelection();
    if (!raw || isActiveChatProjectId(raw)) return;

    _normalizingStaleProject = true;
    try {
        if (window.currentConversationId) {
            window._loadedConversationProjectId = '';
            try {
                const res = await apiFetch(
                    `/api/conversations/${encodeURIComponent(window.currentConversationId)}/project`,
                    {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ projectId: '' }),
                    }
                );
                if (!res.ok) console.warn('清除失效的项目绑定失败');
            } catch (e) {
                console.warn(e);
            }
        } else {
            setActiveProjectId('');
        }
    } finally {
        _normalizingStaleProject = false;
    }
}

function updateChatProjectButtonLabel() {
    const textEl = document.getElementById('chat-project-text');
    if (!textEl) return;
    const id = resolveChatProjectSelection();
    textEl.textContent = id && projectNameById[id] ? projectNameById[id] : '无项目';
}

function renderChatProjectPanelList() {
    const list = document.getElementById('chat-project-list');
    if (!list) return;
    const selected = resolveChatProjectSelection();
    const activeProjects = projectsCache.filter((p) => p.status !== 'archived');
    const items = [{ id: '', name: '无项目', description: '不绑定项目黑板' }, ...activeProjects];
    if (!items.length) {
        list.innerHTML = '<div class="chat-project-panel-empty">暂无项目，点击下方「新建项目」</div>';
        return;
    }
    list.innerHTML = '';
    items.forEach((p) => {
        const isNone = !p.id;
        const isSelected = isNone ? !selected : selected === p.id;
        const desc = isNone
            ? (p.description || '')
            : (p.description || '').trim().slice(0, 80) || '共享事实黑板';
        const projectId = p.id || '';
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'role-selection-item-main' + (isSelected ? ' selected' : '');
        btn.setAttribute('role', 'option');
        btn.onclick = () => {
            selectChatProject(projectId);
        };
        btn.innerHTML = `
                <div class="role-selection-item-icon-main">${isNone ? '—' : '📁'}</div>
                <div class="role-selection-item-content-main">
                    <div class="role-selection-item-name-main">${escapeHtml(p.name || '未命名')}</div>
                    <div class="role-selection-item-description-main">${escapeHtml(desc)}</div>
                </div>
                ${isSelected ? '<div class="role-selection-checkmark-main">✓</div>' : ''}
            `;
        list.appendChild(btn);
    });
}

async function renderChatProjectPanel() {
    const list = document.getElementById('chat-project-list');
    if (!list) return;
    list.innerHTML = '<div class="chat-project-panel-loading">加载中…</div>';
    try {
        await ensureProjectsLoaded();
    } catch (e) {
        console.warn(e);
        list.innerHTML = '<div class="chat-project-panel-empty">加载失败，请稍后重试</div>';
        return;
    }
    renderChatProjectPanelList();
}

function closeChatProjectPanel() {
    const panel = document.getElementById('chat-project-panel');
    const btn = document.getElementById('chat-project-btn');
    if (panel) panel.style.display = 'none';
    if (btn) {
        btn.classList.remove('active');
        btn.setAttribute('aria-expanded', 'false');
    }
}

async function toggleChatProjectPanel() {
    const panel = document.getElementById('chat-project-panel');
    const btn = document.getElementById('chat-project-btn');
    if (!panel) return;
    const isHidden = panel.style.display === 'none' || !panel.style.display;
    if (!isHidden) {
        closeChatProjectPanel();
        return;
    }
    if (typeof closeRoleSelectionPanel === 'function') closeRoleSelectionPanel();
    if (typeof closeAgentModePanel === 'function') closeAgentModePanel();
    if (typeof closeChatReasoningPanel === 'function') closeChatReasoningPanel();
    panel.style.display = 'flex';
    if (btn) {
        btn.classList.add('active');
        btn.setAttribute('aria-expanded', 'true');
    }
    await renderChatProjectPanel();
}

async function selectChatProject(projectId) {
    closeChatProjectPanel();
    await applyChatProjectSelection(projectId || '');
}

async function applyChatProjectSelection(projectId) {
    const prev = getChatProjectSelection();
    if (projectId === prev) {
        updateChatProjectButtonLabel();
        return;
    }
    if (window.currentConversationId) {
        try {
            const res = await apiFetch(`/api/conversations/${encodeURIComponent(window.currentConversationId)}/project`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ projectId }),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.error || res.statusText);
            }
            window._loadedConversationProjectId = projectId;
            if (typeof showNotification === 'function') {
                showNotification(projectId ? '已绑定项目' : '已解除项目绑定', 'success');
            }
        } catch (e) {
            console.error(e);
            alert('更新项目绑定失败: ' + (e.message || e));
            updateChatProjectButtonLabel();
            return;
        }
    } else {
        setActiveProjectId(projectId);
    }
    updateChatProjectButtonLabel();
}

/** 对话页项目选择器：同步按钮文案；若浮层已打开则刷新列表 */
async function refreshChatProjectSelector() {
    if (!document.getElementById('chat-project-btn')) return;
    try {
        await ensureProjectsLoaded();
        await normalizeStaleChatProjectSelection();
    } catch (e) {
        console.warn(e);
    }
    updateChatProjectButtonLabel();
    const panel = document.getElementById('chat-project-panel');
    if (panel && panel.style.display === 'flex') {
        renderChatProjectPanelList();
    }
}

async function onChatProjectChange() {
    /* 兼容旧调用；新 UI 使用 selectChatProject */
    await applyChatProjectSelection(getChatProjectSelection());
}

function initChatProjectSelector() {
    if (window._chatProjectSelectorInited) return;
    window._chatProjectSelectorInited = true;
    refreshChatProjectSelector().catch(() => {});
    document.addEventListener('click', (e) => {
        const panel = document.getElementById('chat-project-panel');
        const wrapper = document.querySelector('.project-selector-wrapper');
        if (!panel || panel.style.display === 'none' || !panel.style.display) return;
        if (!wrapper?.contains(e.target)) {
            closeChatProjectPanel();
        }
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initChatProjectSelector);
} else {
    initChatProjectSelector();
}

window.initProjectsPage = initProjectsPage;
window.showNewProjectModal = showNewProjectModal;
window.showNewProjectModalFromChat = showNewProjectModalFromChat;
window.saveProjectModal = saveProjectModal;
window.closeProjectModal = closeProjectModal;
window.selectProject = selectProject;
window.switchProjectTab = switchProjectTab;
window.showAddFactModal = showAddFactModal;
window.showEditFactModal = showEditFactModal;
window.editFactFromDetail = editFactFromDetail;
window.saveFactModal = saveFactModal;
window.closeFactModal = closeFactModal;
window.closeFactDetailModal = closeFactDetailModal;
window.saveProjectSettings = saveProjectSettings;
window.archiveCurrentProject = archiveCurrentProject;
window.deleteCurrentProject = deleteCurrentProject;
window.refreshChatProjectSelector = refreshChatProjectSelector;
window.onChatProjectChange = onChatProjectChange;
window.toggleChatProjectPanel = toggleChatProjectPanel;
window.closeChatProjectPanel = closeChatProjectPanel;
window.selectChatProject = selectChatProject;
window.prefetchProjectsForChat = prefetchProjectsForChat;
window.ensureDefaultActiveProjectForNewChat = ensureDefaultActiveProjectForNewChat;
window.getActiveProjectId = getActiveProjectId;
window.getProjectName = getProjectName;
window.viewProjectFactBody = viewProjectFactBody;
window.insertFactBodyTemplate = insertFactBodyTemplate;
window.updateFactFormHints = updateFactFormHints;
window.deprecateProjectFactByKey = deprecateProjectFactByKey;
window.restoreProjectFactByKey = restoreProjectFactByKey;
window.openVulnerabilitiesForProject = openVulnerabilitiesForProject;
window.openVulnerabilityDetail = openVulnerabilityDetail;
window.filterProjectsList = filterProjectsList;
window.debouncedLoadProjectFacts = debouncedLoadProjectFacts;
window.linkFactToExistingVulnerability = linkFactToExistingVulnerability;
window.createVulnerabilityFromCurrentFact = createVulnerabilityFromCurrentFact;
window.viewFactsForVulnerability = viewFactsForVulnerability;
window.openProjectConversation = openProjectConversation;
window.unbindConversationFromProject = unbindConversationFromProject;
window.loadProjectConversations = loadProjectConversations;
window.rebuildProjectNameMap = rebuildProjectNameMap;
window.projectNameById = projectNameById;
