
/* dashboard-v3.js — 7 页签 / 玻璃主题 / Canvas 图表 / 可用性标记 / 移动端增强
   不重写原有渲染函数：移动 section、装饰行、独立拉取图表数据，降低回归风险。 */
(function(){
  'use strict';
  const $ = id => document.getElementById(id);
  const state = {accounts:[], models:[], analytics:null, daily:null, recent:null, tasks:null, discovery:null, probe:null, loaded:{}};
  const TIP = '#traeChartTip';
  function realm(){ return window.VIEW_REALM || 'cn'; }
  function esc(v){ return (typeof window.esc === 'function') ? window.esc(v) : String(v == null ? '' : v).replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s])); }
  function fmt(v){ return (typeof window.fmt === 'function') ? window.fmt(v) : (Number(v)||0).toLocaleString(); }
  async function get(url){ try{ return await getJSON(url); }catch(e){ console.warn('v3 fetch failed', url, e); return null; } }
  function num(v){ return Number(v) || 0; }
  function daysLeft(ts){ if(!ts) return null; return Math.ceil((ts*1000 - Date.now())/86400000); }

  function icon(name){
    const p = {
      grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
      users:'<circle cx="9" cy="8" r="3.2"/><path d="M2.8 20c.6-3.3 3-5.2 6.2-5.2s5.6 1.9 6.2 5.2"/><path d="M16 5.2a3 3 0 0 1 0 5.6M18.2 20c-.2-2.1-1-3.7-2.2-4.8 2.9.1 4.8 1.9 5.2 4.8"/>',
      layers:'<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5"/><path d="m3 16 9 5 9-5"/>',
      chart:'<path d="M4 19V5"/><path d="M4 19h16"/><path d="m7 15 4-5 3 3 5-7"/>',
      pulse:'<path d="M3 12h4l2.5-6 4 12 2.5-6h5"/>',
      terminal:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
      sliders:'<path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h10M18 18h2"/><circle cx="16" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="16" cy="18" r="2"/>'
    };
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' + (p[name]||p.grid) + '</svg>';
  }

  function chartCard(id, title, sub, badge, cls, legend){
    return '<div class="chart-card ' + (cls||'') + '">'
      + '<div class="chart-head"><div><div class="chart-title">' + title + '</div><div class="chart-sub">' + sub + '</div></div>'
      + (badge ? '<span class="chart-badge">' + badge + '</span>' : '') + '</div>'
      + '<div class="chart-canvas"><canvas id="' + id + '" role="img" aria-label="' + esc(title) + '"></canvas></div>'
      + '<div class="chart-legend" id="' + (legend || (id + 'Legend')) + '"></div>'
      + '</div>';
  }

  function moveSection(selector, pageId, newId){
    const node = document.querySelector(selector);
    const page = $(pageId);
    if(!node || !page) return null;
    const section = node.closest('section');
    if(!section) return null;
    if(newId) section.id = newId;
    page.appendChild(section);
    return section;
  }

  function initLayout(){
    if(window.__v3Layout) return;
    window.__v3Layout = true;

    // 智能体配置并入设置（7 页签：总览/账号池/模型库/数据指标/维护任务/日志/设置）
    const agents = $('pageAgents'), settings = $('pageSettings');
    if(agents && settings){
      while(agents.firstChild) settings.insertBefore(agents.firstChild, settings.firstChild);
      agents.remove();
    }
    const navAgents = $('btnNavAgents');
    if(navAgents && navAgents.parentElement) navAgents.remove();

    // 把账号/模型/维护任务从总览拆成独立页
    moveSection('#accounts', 'pageAccounts', 'sectionAccounts');
    moveSection('#modelsTable', 'pageModels', 'sectionModels');
    const growthSection = moveSection('#sectionGrowthTasks', 'pageTasks');
    if(growthSection) growthSection.style.display = '';

    const accountsPage = $('pageAccounts');
    if(accountsPage && !$('accountsHero')){
      accountsPage.insertAdjacentHTML('afterbegin',
        '<div class="page-hero" id="accountsHero"><div><div class="eyebrow">ACCOUNT POOL</div><h2>账号池</h2>'
        + '<p>按区域、冷却、凭证到期与用量看每个账号的真实状态；停用、测试、续期、导出都在行内完成。</p></div>'
        + '<div class="hero-stats" id="accountHeroStats"></div></div>'
        + '<div class="chart-grid">'
        + chartCard('chartAccountHealth','账号健康','可用 / 冷却 / 停用 · 悬停看明细','LIVE','narrow')
        + chartCard('chartAccountUsage','账号用量 TOP','按当日 Token 排序 · 悬停看请求数','TOKENS','wide')
        + '</div>');
    }

    const modelsPage = $('pageModels');
    if(modelsPage && !$('modelsHero')){
      modelsPage.insertAdjacentHTML('afterbegin',
        '<div class="page-hero" id="modelsHero"><div><div class="eyebrow">MODEL CATALOG</div><h2>模型库</h2>'
        + '<p>双区模型可用性、上下文窗口、能力与参考价一屏对齐；表格按当前视图，筛选即时生效。</p></div>'
        + '<div class="hero-stats" id="modelHeroStats"></div></div>'
        + '<div class="filter-bar" id="modelFilterBar">'
        + '<input id="modelSearch" type="search" placeholder="搜索模型 / 官方名 / 别名 / 分组" autocomplete="off">'
        + '<select id="modelRealmFilter"><option value="">当前视图</option><option value="cn">国内版</option><option value="intl">国际版</option></select>'
        + '<select id="modelAvailFilter"><option value="">全部状态</option><option value="1">仅可用</option><option value="0">仅不可用</option></select>'
        + '<button type="button" class="filter-chip" data-cap="vision">视觉</button>'
        + '<button type="button" class="filter-chip" data-cap="tools">工具</button>'
        + '<button type="button" class="filter-chip" data-cap="reasoning">推理</button>'
        + '<button type="button" class="filter-chip" data-probe="1" title="只看最近一次探测成功的模型">探测可用</button>'
        + '<span class="result-count" id="modelResultCount"></span>'
        + '<button class="sec" id="btnDiscoverModels" type="button">刷新目录</button>'
        + '<button class="primary" id="btnProbeModels" type="button">自动探测</button></div>'
        + '<div class="discovery-line" id="modelDiscoveryLine">正在读取模型发现状态…</div>'
        + '<div class="chart-grid">'
        + chartCard('chartModelHealth','可用性分布','可用 / 未开通/升级 · 双区合并','CATALOG','narrow')
        + chartCard('chartModelCaps','能力覆盖','视觉 / 工具 / 推理 / 长上下文 模型数','CAPS','wide')
        + '</div>');
    }

    const tasksPage = $('pageTasks');
    if(tasksPage && !$('tasksHero')){
      tasksPage.insertAdjacentHTML('afterbegin',
        '<div class="page-hero" id="tasksHero"><div><div class="eyebrow">MAINTENANCE</div><h2>维护任务</h2>'
        + '<p>每日签到、Token 保活、权益/用量刷新、目录同步、自动探测、到期提醒；每次执行都有真实结果。</p></div>'
        + '<div class="hero-stats" id="taskHeroStats"></div></div>'
        + '<div class="chart-grid">'
        + chartCard('chartTaskHealth','任务健康','成功 / 失败 / 待执行','RUNS','narrow')
        + chartCard('chartTaskDuration','最近执行耗时','按任务排序 · 悬停看上次执行','MS','wide')
        + '</div>');
    }

    // 总览图表：KPI 卡片之后
    const cards = $('cards');
    if(cards && !$('overviewCharts')){
      cards.insertAdjacentHTML('afterend',
        '<div class="chart-grid" id="overviewCharts">'
        + chartCard('chartOverviewTrend','近 14 天 Token 趋势','按模型堆叠 · 悬停看当日明细','14D','wide')
        + chartCard('chartOverviewModels','模型用量占比','当日 Token · 点击图例无跳转','SHARE','narrow')
        + '</div>');
    }

    // 数据指标：KPI 之后插入 Canvas 图表；旧 HTML 柱状图隐藏，保留其数据逻辑
    const kpi = $('analyticsKpiCards');
    if(kpi && !$('analyticsCharts')){
      kpi.insertAdjacentHTML('afterend',
        '<div class="chart-grid" id="analyticsCharts">'
        + chartCard('chartTokens','Token 用量趋势','按模型堆叠 · 近 14 / 30 天','TOKENS','wide')
        + chartCard('chartModels','模型用量占比','时间窗口内 Token 份额','SHARE','narrow')
        + chartCard('chartAccounts','账号用量','按 Token 排序 · 悬停看请求','ACCOUNTS','narrow')
        + chartCard('chartPerf','模型生成速度','tok/s · 仅统计有生成耗时的请求','SPEED','wide')
        + chartCard('chartCost','参考花费趋势','OpenRouter 公开价 · USD/CNY','COST','wide')
        + chartCard('chartCache','缓存命中构成','命中 / 未命中 Token','CACHE','narrow')
        + chartCard('chartHeat','请求热力','最近 1000 条请求 · 星期 × 小时','HEAT','full')
        + '</div>');
      const oldDaily = $('dailyChartBody');
      if(oldDaily){
        const oldSection = oldDaily.closest('section');
        if(oldSection) oldSection.style.display = 'none';
      }
    }

    // 设置页：外观与动效
    if(settings && !$('sectionAppearance')){
      settings.insertAdjacentHTML('afterbegin',
        '<section id="sectionAppearance"><h2>外观与动效</h2>'
        + '<div class="appearance-grid">'
        + '<button type="button" class="theme-card" data-theme-card="light"><div class="theme-preview light"></div><b>浅色</b><small>清爽、适合白天</small></button>'
        + '<button type="button" class="theme-card" data-theme-card="dark"><div class="theme-preview dark"></div><b>深色</b><small>低光、适合夜间</small></button>'
        + '<button type="button" class="theme-card" data-theme-card="system"><div class="theme-preview system"></div><b>跟随系统</b><small>自动切换</small></button>'
        + '</div>'
        + '<div class="switch-row"><div><b style="font-size:12px">玻璃拟态</b><div style="font-size:11px;color:var(--dim);margin-top:2px">半透明磨砂表面与背景光晕</div></div><label class="switch"><input type="checkbox" id="setGlass" checked><i></i></label></div>'
        + '<div class="switch-row"><div><b style="font-size:12px">动效</b><div style="font-size:11px;color:var(--dim);margin-top:2px">页面入场、图表绘制与悬停过渡</div></div><label class="switch"><input type="checkbox" id="setMotion" checked><i></i></label></div>'
        + '</section>');
    }

    // 导航图标（正文已渲染后再补，避免改大段 HTML）
    const icons = {Gateway:'grid',Accounts:'users',Models:'layers',Analytics:'chart',Tasks:'pulse',Logs:'terminal',Settings:'sliders'};
    Object.keys(icons).forEach(k=>{
      const btn = $('btnNav' + k);
      if(btn && !btn.querySelector('svg')) btn.insertAdjacentHTML('afterbegin', icon(icons[k]));
    });

    initAppearance();
    bindFilters();
    observe();
    updateNavLabels();
  }

  function updateNavLabels(){
    const map = {btnNavGateway:'总览',btnNavAccounts:'账号池',btnNavModels:'模型库',btnNavAnalytics:'数据指标',btnNavTasks:'维护任务',btnNavLogs:'运行日志',btnNavSettings:'设置'};
    Object.keys(map).forEach(id=>{
      const btn = $(id);
      if(btn){ const svg = btn.querySelector('svg'); btn.innerHTML = (svg?svg.outerHTML:'') + map[id]; }
    });
  }

  function initAppearance(){
    document.querySelectorAll('[data-theme-card]').forEach(card=>{
      card.addEventListener('click',()=>{
        const pref = card.getAttribute('data-theme-card');
        if(typeof window.selectTheme === 'function') window.selectTheme(pref);
        else if(window.applyTheme) window.applyTheme(pref);
        syncAppearance();
      });
    });
    const glass = $('setGlass'), motion = $('setMotion');
    try{
      const g = localStorage.getItem('trae-glass');
      const m = localStorage.getItem('trae-motion');
      if(g === 'off') document.documentElement.setAttribute('data-glass','off');
      else document.documentElement.removeAttribute('data-glass');
      if(m === 'off') document.documentElement.setAttribute('data-motion','off');
      else document.documentElement.removeAttribute('data-motion');
      if(glass) glass.checked = g !== 'off';
      if(motion) motion.checked = m !== 'off';
    }catch(e){}
    if(glass) glass.addEventListener('change',()=>{
      document.documentElement.setAttribute('data-glass', glass.checked ? 'on' : 'off');
      try{ localStorage.setItem('trae-glass', glass.checked ? 'on' : 'off'); }catch(e){}
      syncAppearance();
    });
    if(motion) motion.addEventListener('change',()=>{
      document.documentElement.setAttribute('data-motion', motion.checked ? 'on' : 'off');
      try{ localStorage.setItem('trae-motion', motion.checked ? 'on' : 'off'); }catch(e){}
      syncAppearance();
    });
    syncAppearance();
    new MutationObserver(syncAppearance).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme','data-theme-pref']});
  }
  function syncAppearance(){
    const pref = document.documentElement.getAttribute('data-theme-pref') || 'system';
    document.querySelectorAll('[data-theme-card]').forEach(card=>{
      card.classList.toggle('active', card.getAttribute('data-theme-card') === pref);
    });
    const glass = $('setGlass'), motion = $('setMotion');
    if(glass) glass.checked = document.documentElement.getAttribute('data-glass') !== 'off';
    if(motion) motion.checked = document.documentElement.getAttribute('data-motion') !== 'off';
  }

  function bindFilters(){
    const search = $('modelSearch'), realmSel = $('modelRealmFilter'), availSel = $('modelAvailFilter');
    if(search) search.addEventListener('input', applyModelFilter);
    if(realmSel) realmSel.addEventListener('change', async ()=>{
      const v = realmSel.value;
      if(v && typeof switchViewRealm === 'function') await switchViewRealm(v);
      await loadModelsPage(true);
    });
    if(availSel) availSel.addEventListener('change', applyModelFilter);
    document.querySelectorAll('#modelFilterBar .filter-chip').forEach(btn=>{
      btn.addEventListener('click',()=>{ btn.classList.toggle('active'); applyModelFilter(); });
    });
    const btnDiscover=$('btnDiscoverModels'), btnProbe=$('btnProbeModels');
    if(btnDiscover) btnDiscover.addEventListener('click',()=>discoverModels(false,btnDiscover));
    if(btnProbe) btnProbe.addEventListener('click',()=>openProbeModal());
    ['btnRangeToday','btnRangeAll'].forEach(id=>{
      const btn=$(id);
      if(btn) btn.addEventListener('click',()=>setTimeout(()=>loadAnalyticsPage(true),260));
    });
    ['tabIntl','tabCn'].forEach(id=>{
      const card=$(id);
      if(card) card.addEventListener('click',()=>setTimeout(()=>{
        if((typeof currentMainTab!=='undefined'?currentMainTab:'')==='gateway') loadOverviewPage(true);
        if((typeof currentMainTab!=='undefined'?currentMainTab:'')==='accounts') loadAccountsPage(true);
        if((typeof currentMainTab!=='undefined'?currentMainTab:'')==='models') loadModelsPage(true);
      },420));
    });
  }

  function chartEmpty(id, msg){
    const cv = $(id);
    if(!cv) return;
    const c = cv.getContext('2d');
    if(!c) return;
    const rect = cv.getBoundingClientRect();
    cv.width = rect.width * (window.devicePixelRatio||1);
    cv.height = rect.height * (window.devicePixelRatio||1);
    c.scale(window.devicePixelRatio||1, window.devicePixelRatio||1);
    c.clearRect(0,0,rect.width,rect.height);
    c.fillStyle = (getComputedStyle(document.documentElement).getPropertyValue('--dim')||'#64748b').trim();
    c.font = '12px sans-serif'; c.textAlign='center'; c.textBaseline='middle';
    c.fillText(msg || '暂无数据', rect.width/2, rect.height/2);
  }

  function topGroups(daily, limit){
    const groups = (daily && daily.groups) || [];
    const ids = groups.slice(0, limit).map(g=>g.id);
    const out = ids.map(id=>({name:id, values:(daily.series||[]).map(s=>(s.groups&&s.groups[id])||0)}));
    if(groups.length > limit){
      out.push({name:'其他', values:(daily.series||[]).map(s=>{
        const known = ids.reduce((a,id)=>a+((s.groups&&s.groups[id])||0),0);
        return Math.max(0,(s.total_tokens||0)-known);
      })});
    }
    return out;
  }
  function dailyLabels(daily){ return ((daily&&daily.series)||[]).map(s=>s.label||s.day||''); }

  function renderOverview(){
    const daily = state.daily;
    const labels = dailyLabels(daily);
    const series = topGroups(daily, 4);
    if(daily && series.length){
      TraeCharts.render('chartOverviewTrend', {type:'stacked', labels, series, legend:'chartOverviewTrendLegend', yFormat:fmt});
    } else chartEmpty('chartOverviewTrend','近 14 天暂无请求');
    const models = ((state.analytics&&state.analytics.models)||[]).map(m=>({
      label:m.model, value:(m.all_time&&m.all_time.total_tokens)||(m.today&&m.today.total_tokens)||0
    })).filter(x=>x.value>0).sort((a,b)=>b.value-a.value).slice(0,6);
    if(models.length) TraeCharts.render('chartOverviewModels',{type:'donut',data:{items:models},legend:'chartOverviewModelsLegend',centerLabel:'Token'});
    else chartEmpty('chartOverviewModels','暂无模型用量');
    renderKpiSparks();
  }

  function renderKpiSparks(){
    const cards = document.querySelectorAll('#cards .card');
    const daily = state.daily;
    if(!cards.length || !daily) return;
    const vals = (daily.series||[]).map(s=>num(s.total_tokens));
    const reqs = (daily.series||[]).map(s=>num(s.requests));
    if(cards[1]) addSpark(cards[1], vals, 'var(--v3-chart-1)');
    if(cards[2]) addSpark(cards[2], reqs, 'var(--v3-chart-2)');
    if(cards[3]) addSpark(cards[3], (daily.series||[]).map(s=>s.requests ? 100*(s.requests-(s.errors||0))/s.requests : 0), 'var(--v3-chart-3)');
  }
  function addSpark(card, values, color){
    let cv = card.querySelector('.kpi-spark');
    if(cv) return;                 // 已画过：避免 MutationObserver 反复重绘把 tooltip 关掉
    cv = document.createElement('canvas'); cv.className='kpi-spark'; card.appendChild(cv);
    TraeCharts.spark(cv, values, color || 'var(--v3-chart-1)');
  }

  async function loadOverviewPage(force){
    if(state.loaded.overview && !force){ renderOverview(); return; }
    const [daily, analytics] = await Promise.all([
      get('/usage/daily?days=14&group=model&realm=' + encodeURIComponent(realm())),
      get('/usage/analytics?range=day')
    ]);
    state.daily = daily || state.daily;
    state.analytics = analytics || state.analytics;
    state.loaded.overview = true;
    renderOverview();
    decorateKpi();
  }

  function decorateKpi(){
    const cards = document.querySelectorAll('#analyticsKpiCards .card');
    if(!cards.length || !state.daily) return;
    const vals = (state.daily.series||[]).map(s=>num(s.total_tokens));
    const reqs = (state.daily.series||[]).map(s=>num(s.requests));
    const costs = (state.daily.series||[]).map(s=>num(s.cost_usd));
    const cache = (state.daily.series||[]).map(s=>s.prompt_tokens ? 100*num(s.cached_tokens)/s.prompt_tokens : 0);
    const speed = (state.daily.series||[]).map(s=>s.requests ? num(s.total_tokens)/Math.max(1,num(s.completion_tokens)) : 0);
    if(cards[0]) addSpark(cards[0], vals, 'var(--v3-chart-1)');
    if(cards[1]) addSpark(cards[1], vals, 'var(--v3-chart-3)');
    if(cards[2]) addSpark(cards[2], speed, 'var(--v3-chart-2)');
    if(cards[3]) addSpark(cards[3], cache, 'var(--v3-chart-6)');
    if(cards[4]) addSpark(cards[4], costs, 'var(--v3-chart-4)');
    if(cards[5]) addSpark(cards[5], reqs, 'var(--v3-chart-5)');
  }

  async function loadAccountsPage(force){
    if(force || !state.loaded.accounts){
      if(typeof loadAccounts === 'function'){ try{ await loadAccounts(); }catch(e){} }
      state.accounts = window.ACCOUNTS || [];
      state.analytics = state.analytics || await get('/usage/analytics?range=day');
      state.loaded.accounts = true;
    }
    renderAccountHero();
    renderAccountCharts();
    decorateAccounts();
  }
  function renderAccountHero(){
    const list = (window.ACCOUNTS||[]).filter(a=>!a.realm || a.realm===realm());
    const ready = list.filter(a=>a.enabled && a.status==='ready').length;
    const cool = list.filter(a=>a.cooldownFor||a.breakerFor).length;
    const exp = list.filter(a=>{const d=daysLeft(a.expiresAt);return d!==null&&d<=3;}).length;
    const el = $('accountHeroStats');
    if(el) el.innerHTML =
      '<div class="hero-stat blue"><div class="hv">'+list.length+'</div><div class="hk">账号总数</div></div>'
      + '<div class="hero-stat ok"><div class="hv">'+ready+'</div><div class="hk">健康可用</div></div>'
      + '<div class="hero-stat warn"><div class="hv">'+cool+'</div><div class="hk">冷却 / 风控</div></div>'
      + '<div class="hero-stat '+(exp?'bad':'')+'"><div class="hv">'+exp+'</div><div class="hk">3 天内到期</div></div>';
  }
  function renderAccountCharts(){
    const list = (window.ACCOUNTS||[]).filter(a=>!a.realm || a.realm===realm());
    const ready = list.filter(a=>a.enabled && a.status==='ready').length;
    const cool = list.filter(a=>a.enabled && (a.cooldownFor||a.breakerFor)).length;
    const off = list.length - ready - cool;
    TraeCharts.render('chartAccountHealth',{type:'donut',data:{items:[
      {label:'健康',value:ready,color:'var(--v3-chart-2)'},
      {label:'冷却',value:cool,color:'var(--v3-chart-4)'},
      {label:'停用',value:Math.max(0,off),color:'var(--v3-chart-5)'}
    ]},legend:'chartAccountHealthLegend',centerLabel:'账号'});
    const accts = (state.analytics&&state.analytics.accounts)||[];
    const max = Math.max(1,...accts.map(a=>num((a.today&&a.today.total_tokens)||(a.all_time&&a.all_time.total_tokens))));
    const items = accts.filter(a=>a.uid!=='(unattributed)').map(a=>{
      const tokens = num((a.today&&a.today.total_tokens)||(a.all_time&&a.all_time.total_tokens));
      return {label:a.nickname||a.uid, value:tokens, display:fmt(tokens), metric:'Token', sub:(a.today&&a.today.requests||0)+' 请求'};
    }).sort((a,b)=>b.value-a.value).slice(0,8);
    if(items.length) TraeCharts.render('chartAccountUsage',{type:'hbar',data:{items},legend:'chartAccountUsageLegend'});
    else chartEmpty('chartAccountUsage','暂无账号用量');
  }

  async function loadModelsPage(force){
    if(force || !state.loaded.models){
      if(typeof loadModels === 'function'){ try{ await loadModels(); }catch(e){} }
      state.models = window.MODELS_DATA || [];
      state.mergedModels = await get('/v1/models?merge_realms=1');
      state.loaded.models = true;
    }
    await loadDiscoveryStatus();
    renderModelHero();
    renderModelCharts();
    decorateModels();
    applyModelFilter();
  }
  function renderModelHero(){
    const merged = (state.mergedModels&&state.mergedModels.data)||state.models||[];
    const avail = merged.filter(m=>m.available!==false&&m.enabled!==false).length;
    const disabled = merged.filter(m=>m.available===false||m.enabled===false).length;
    const cn = merged.filter(m=>m.realm==='cn').length, intl = merged.filter(m=>m.realm==='intl').length;
    const el = $('modelHeroStats');
    if(el) el.innerHTML =
      '<div class="hero-stat blue"><div class="hv">'+merged.length+'</div><div class="hk">双区模型</div></div>'
      + '<div class="hero-stat ok"><div class="hv">'+avail+'</div><div class="hk">可用模型</div></div>'
      + '<div class="hero-stat warn"><div class="hv">'+disabled+'</div><div class="hk">未开通/升级</div></div>'
      + '<div class="hero-stat"><div class="hv">'+cn+' / '+intl+'</div><div class="hk">国内 / 国际</div></div>';
  }
  function renderModelCharts(){
    const merged = (state.mergedModels&&state.mergedModels.data)||state.models||[];
    const avail = merged.filter(m=>m.available!==false&&m.enabled!==false).length;
    const disabled = Math.max(0,merged.length-avail);
    TraeCharts.render('chartModelHealth',{type:'donut',data:{items:[
      {label:'可用',value:avail,color:'var(--v3-chart-2)'},
      {label:'未开通/升级',value:disabled,color:'var(--v3-chart-4)'}
    ]},legend:'chartModelHealthLegend',centerLabel:'模型'});
    const caps = [
      {label:'视觉', value:merged.filter(m=>m.multimodal||m.supports_vision||(m.capabilities&&m.capabilities.vision)).length, color:'var(--v3-chart-1)'},
      {label:'工具调用', value:merged.filter(m=>m.supports_tool_calls||(m.capabilities&&m.capabilities.tool_calls)).length, color:'var(--v3-chart-2)'},
      {label:'推理', value:merged.filter(m=>m.supports_reasoning||(m.capabilities&&m.capabilities.reasoning)).length, color:'var(--v3-chart-3)'},
      {label:'长上下文', value:merged.filter(m=>num(m.context_length||m.max_input_tokens)>=100000).length, color:'var(--v3-chart-4)'}
    ];
    TraeCharts.render('chartModelCaps',{type:'hbar',data:{items:caps.map(c=>({label:c.label,value:c.value,display:c.value+' 个',color:c.color,metric:'模型'})),legend:'chartModelCapsLegend'}});
  }

  function probeStatusLabel(status){
    return ({ok:'可用', risk_control:'风控', unavailable:'不可用', auth:'鉴权失败',
             rate_limited:'限流', no_account:'无账号', error:'失败'})[status] || status || '未知';
  }
  function renderDiscoveryLine(){
    const el=$('modelDiscoveryLine');
    if(!el) return;
    const d=(state.discovery&&state.discovery.realms&&state.discovery.realms[realm()])||{};
    const p=(state.discovery&&state.discovery.probe&&state.discovery.probe.realms&&state.discovery.probe.realms[realm()])||{};
    const when=d.at?new Date(d.at*1000).toLocaleString():'尚未发现';
    const age=d.age_seconds==null?'':(' · '+Math.max(0,Math.round(d.age_seconds/60))+' 分钟前');
    el.innerHTML='自动发现：<b>'+(d.count||0)+'</b> 个动态可用 · 目录 <b>'+((window.MODELS_DATA||[]).length)+'</b> 个 · 来源 '+(d.source||'—')
      + ' · '+when+age
      + ' · 探测 <b style="color:var(--accent2)">'+(p.ok||0)+'</b> / '+(p.total||0)
      + (d.added&&d.added.length?(' · 新增 '+d.added.slice(0,3).map(esc).join('、')+(d.added.length>3?(' 等 '+d.added.length+' 个'):'')):'')
      + (state.probe&&state.probe.job&&state.probe.job.state==='running'?' · <span style="color:var(--warn)">探测中…</span>':'');
  }
  async function loadDiscoveryStatus(){
    const [disc, status] = await Promise.all([get('/models/discovery'), get('/models/probe/status')]);
    if(disc) state.discovery=disc;
    if(status) state.probe=status;
    renderDiscoveryLine();
    if(status && status.job && status.job.state==='running') pollProbe();
    // 自动发现：CN 动态目录超过 30 分钟就后台刷新一次（INTL 没有动态接口，不刷）
    const d=disc&&disc.realms&&disc.realms[realm()];
    if(realm()==='cn' && (!d || d.age_seconds==null || d.age_seconds>1800)
       && !state.discovering && Date.now() - (state.lastDiscoverAt||0) > 600000){
      state.lastDiscoverAt = Date.now();
      discoverModels(true);
    }
  }
  async function discoverModels(silent, btn){
    if(state.discovering) return;
    state.discovering=true;
    if(btn){ btn.disabled=true; btn.textContent='发现中…'; }
    try{
      const r=await postJSON('/models/discover', {realm:realm()});
      const added=(r.added||[]).length;
      if(!silent) toast('模型目录已刷新：'+(r.count||0)+' 个'+(added?('，新增 '+added):''), added?'ok':'');
      state.loaded.models=false;
      await loadModelsPage(true);
    }catch(e){
      if(!silent) toast('模型目录刷新失败：'+e.message,'bad');
    }finally{
      state.discovering=false;
      if(btn){ btn.disabled=false; btn.textContent='刷新目录'; }
    }
  }

  function ensureProbeModal(){
    if($('probeModal')) return;
    const html='<div class="modal-mask" id="probeModal" onclick="if(event.target===this)closeProbeModal()">'
      + '<div class="modal" style="max-width:840px;width:min(94vw,840px)">'
      + '<div class="modal-hd"><h2>模型自动探测</h2><button class="modal-x" type="button" onclick="closeProbeModal()">×</button></div>'
      + '<div class="modal-bd">'
      + '<div class="probe-controls">'
      + '<select id="probeScope"><option value="current">当前区域</option><option value="all">双区合并</option></select>'
      + '<label style="display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--dim)"><input type="checkbox" id="probeForce"> 忽略 24h 缓存</label>'
      + '<button class="primary" id="btnProbeStart" type="button">开始探测</button>'
      + '<span id="probeJobHint" class="hint" style="margin-left:auto"></span>'
      + '</div>'
      + '<div class="probe-progress"><div id="probeBar"></div></div>'
      + '<div class="hint" style="margin-top:7px;font-size:10.5px">探测会消耗账号额度；INTL 风控账号会记录为 risk_control，不伪造可用。</div>'
      + '<div id="probeSummary" class="hint" style="margin:10px 0"></div>'
      + '<div class="table-wrap" style="max-height:360px;overflow:auto"><table><thead><tr>'
      + '<th style="text-align:left">模型</th><th style="width:70px">区域</th><th style="width:90px">状态</th><th style="width:90px">耗时</th><th style="text-align:left">说明</th>'
      + '</tr></thead><tbody id="probeTbody"><tr><td colspan="5" class="empty">尚未探测</td></tr></tbody></table></div>'
      + '</div><div class="modal-ft"><button class="sec" type="button" onclick="closeProbeModal()">关闭</button></div>'
      + '</div></div>';
    document.body.insertAdjacentHTML('beforeend', html);
    const start=$('btnProbeStart');
    if(start) start.addEventListener('click', startProbe);
  }
  function openProbeModal(){
    ensureProbeModal();
    const modal=$('probeModal');
    if(modal) modal.classList.add('show');
    if(state.probe&&state.probe.job) renderProbeJob(state.probe.job);
    if(state.probe&&state.probe.job&&state.probe.job.state==='running') pollProbe();
  }
  function closeProbeModal(){
    const modal=$('probeModal');
    if(modal) modal.classList.remove('show');
  }
  async function startProbe(){
    const scope=($('probeScope')&&$('probeScope').value)||'current';
    const force=!!($('probeForce')&&$('probeForce').checked);
    try{
      const r=await postJSON('/models/probe',{scope:scope,limit:0,force:force});
      if(!r.started && r.reason==='already running') toast('已有探测任务在运行','warn');
      else toast('模型探测已启动','ok');
      if(r.job) renderProbeJob(r.job);
      pollProbe();
    }catch(e){ toast('探测启动失败：'+e.message,'bad'); }
  }
  let probeTimer=null;
  function pollProbe(){
    if(probeTimer) return;
    const tick=async()=>{
      const r=await get('/models/probe/status');
      if(r&&r.job){ state.probe=r; renderProbeJob(r.job); if(r.job.state!=='running'){ clearInterval(probeTimer); probeTimer=null; state.loaded.models=false; loadModelsPage(true); } }
      else { clearInterval(probeTimer); probeTimer=null; }
    };
    probeTimer=setInterval(tick,900);
    tick();
  }
  function renderProbeJob(job){
    if(!job) return;
    const done=Number(job.done||0), total=Number(job.total||0);
    const pct=total?Math.min(100,Math.round(done/total*100)):(job.state==='done'?100:0);
    const bar=$('probeBar'); if(bar) bar.style.width=pct+'%';
    const hint=$('probeJobHint');
    if(hint) hint.textContent=job.state==='running'?('探测中 '+(job.current||'')+' · '+done+'/'+total):(job.state==='done'?'探测完成':'空闲');
    const summary=$('probeSummary');
    if(summary) summary.innerHTML='成功 <b style="color:var(--accent2)">'+(job.ok||0)+'</b> · 失败 <b style="color:var(--bad)">'+(job.failed||0)+'</b> · 跳过 '+(job.skipped||0)+(job.error?(' · '+esc(job.error)):'');
    const tbody=$('probeTbody');
    if(!tbody) return;
    const rows=(job.results||[]).slice().reverse();
    if(!rows.length){ tbody.innerHTML='<tr><td colspan="5" class="empty">'+(job.state==='running'?'等待第一个结果…':'尚未探测')+'</td></tr>'; return; }
    tbody.innerHTML=rows.map(r=>'<tr>'
      + '<td style="text-align:left"><b>'+esc(r.model)+'</b></td>'
      + '<td>'+(r.realm==='cn'?'国内':'国际')+'</td>'
      + '<td><span class="badge '+(r.ok?'ok':((r.status==='risk_control')?'warn':'bad'))+'">'+esc(probeStatusLabel(r.status))+'</span></td>'
      + '<td>'+(r.elapsed_ms?((r.elapsed_ms/1000).toFixed(2)+'s'):'—')+'</td>'
      + '<td style="text-align:left;font-size:11px;color:var(--dim)">'+esc(r.error||r.reply||'—')+'</td>'
      + '</tr>').join('');
  }
  window.openProbeModal=openProbeModal;
  window.closeProbeModal=closeProbeModal;

  async function loadTasksPage(force){
    if(force || !state.loaded.tasks){
      if(typeof loadGrowthTasks === 'function'){ try{ await loadGrowthTasks(); }catch(e){} }
      state.tasks = await get('/tasks?realm=' + encodeURIComponent(realm()));
      state.loaded.tasks = true;
    }
    renderTaskHero();
    renderTaskCharts();
    decorateTasks();
  }
  function taskList(){ return (state.tasks&&state.tasks.tasks)||[]; }
  function renderTaskHero(){
    const list = taskList();
    const ok = list.filter(t=>t.ok||t.state==='ok'||t.status==='completed').length;
    const failed = list.filter(t=>t.state==='fail'||t.status==='failed').length;
    const last = list.reduce((a,t)=>Math.max(a,num(t.last_run_ts)),0);
    const el = $('taskHeroStats');
    if(el) el.innerHTML =
      '<div class="hero-stat blue"><div class="hv">'+list.length+'</div><div class="hk">维护任务</div></div>'
      + '<div class="hero-stat ok"><div class="hv">'+ok+'</div><div class="hk">执行成功</div></div>'
      + '<div class="hero-stat '+(failed?'bad':'')+'"><div class="hv">'+failed+'</div><div class="hk">失败</div></div>'
      + '<div class="hero-stat"><div class="hv" style="font-size:13px">'+(last?new Date(last*1000).toLocaleTimeString():'—')+'</div><div class="hk">上次执行</div></div>';
  }
  function renderTaskCharts(){
    const list = taskList();
    const ok = list.filter(t=>t.ok||t.state==='ok'||t.status==='completed').length;
    const failed = Math.max(0,list.length-ok);
    TraeCharts.render('chartTaskHealth',{type:'donut',data:{items:[
      {label:'成功',value:ok,color:'var(--v3-chart-2)'},
      {label:'失败 / 待执行',value:failed,color:'var(--v3-chart-5)'}
    ]},legend:'chartTaskHealthLegend',centerLabel:'任务'});
    const items = list.map(t=>({
      label:t.name||t.task_code, value:num(t.duration_ms), display:(num(t.duration_ms)/1000).toFixed(2)+'s',
      metric:'上次耗时', sub:(t.last_run||'未执行') + ' · ' + (t.ok?'成功':'失败'), color:t.ok?'var(--v3-chart-2)':'var(--v3-chart-5)'
    })).sort((a,b)=>b.value-a.value);
    if(items.length) TraeCharts.render('chartTaskDuration',{type:'hbar',data:{items},legend:'chartTaskDurationLegend'});
    else chartEmpty('chartTaskDuration','暂无任务记录');
  }

  async function loadAnalyticsPage(force){
    if(state.loaded.analytics && !force && state.analyticsRange === ((typeof analyticsRange !== 'undefined') ? analyticsRange : 'today')) return;
    const range = (typeof analyticsRange !== 'undefined') ? analyticsRange : 'today';
    const days = range === 'all' ? 30 : 14;
    const [daily, analytics, recent] = await Promise.all([
      get('/usage/daily?days='+days+'&group=model&realm='+encodeURIComponent(realm())),
      get('/usage/analytics?range='+encodeURIComponent(range)),
      get('/usage/recent?limit=1000&realm='+encodeURIComponent(realm()))
    ]);
    state.daily = daily || state.daily;
    state.analytics = analytics || state.analytics;
    state.recent = recent || state.recent;
    state.loaded.analytics = true;
    state.analyticsRange = range;
    renderAnalyticsCharts();
    decorateKpi();
  }
  function renderAnalyticsCharts(){
    const daily = state.daily;
    const labels = dailyLabels(daily);
    const series = topGroups(daily, 4);
    if(series.length) TraeCharts.render('chartTokens',{type:'stacked',labels,series,legend:'chartTokensLegend',yFormat:fmt});
    else chartEmpty('chartTokens','暂无 Token 数据');

    const models = ((state.analytics&&state.analytics.models)||[]).map(m=>({
      label:m.model, value:num((m.all_time&&m.all_time.total_tokens)||(m.today&&m.today.total_tokens))
    })).filter(x=>x.value>0).sort((a,b)=>b.value-a.value).slice(0,6);
    if(models.length) TraeCharts.render('chartModels',{type:'donut',data:{items:models},legend:'chartModelsLegend',centerLabel:'Token'});
    else chartEmpty('chartModels','暂无模型用量');

    const accts = ((state.analytics&&state.analytics.accounts)||[]).filter(a=>a.uid!=='(unattributed)').map(a=>({
      label:a.nickname||a.uid, value:num((a.today&&a.today.total_tokens)||(a.all_time&&a.all_time.total_tokens)),
      display:fmt(num((a.today&&a.today.total_tokens)||(a.all_time&&a.all_time.total_tokens))),
      metric:'Token', sub:num((a.today&&a.today.requests)||(a.all_time&&a.all_time.requests))+' 请求'
    })).sort((a,b)=>b.value-a.value).slice(0,8);
    if(accts.length) TraeCharts.render('chartAccounts',{type:'hbar',data:{items:accts},legend:'chartAccountsLegend'});
    else chartEmpty('chartAccounts','暂无账号用量');

    const perf = ((state.analytics&&state.analytics.models)||[]).map(m=>({
      label:m.model, value:num((m.all_time&&m.all_time.speed_avg)||(m.today&&m.today.speed_avg)),
      display:(num((m.all_time&&m.all_time.speed_avg)||(m.today&&m.today.speed_avg))).toFixed(1)+' tok/s', metric:'生成速度',
      sub:'TTFT '+(num((m.all_time&&m.all_time.ttft_ms_avg)||(m.today&&m.today.ttft_ms_avg)))+' ms'
    })).filter(x=>x.value>0).sort((a,b)=>b.value-a.value).slice(0,8);
    if(perf.length) TraeCharts.render('chartPerf',{type:'hbar',data:{items:perf},legend:'chartPerfLegend'});
    else chartEmpty('chartPerf','暂无生成速度数据');

    const costs = (daily&&daily.series||[]).map(s=>num(s.cost_usd));
    if(costs.some(v=>v>0)) TraeCharts.render('chartCost',{type:'line',labels,series:[{name:'USD',values:costs,color:'var(--v3-chart-4)'}],legend:'chartCostLegend',yFormat:v=>'$'+(v<1?v.toFixed(3):v.toFixed(1))});
    else chartEmpty('chartCost','暂无已定价模型的请求');

    const summary = (state.analytics&&state.analytics.summary)||{};
    const stat = summary.window || summary.today || summary.all_time || {};
    const prompt = num(stat.prompt_tokens) || num(daily&&daily.totals&&daily.totals.prompt_tokens);
    const cached = num(stat.cached_tokens) || num(daily&&daily.totals&&daily.totals.cached_tokens);
    const miss = Math.max(0,prompt-cached);
    TraeCharts.render('chartCache',{type:'donut',data:{items:[
      {label:'缓存命中',value:cached,color:'var(--v3-chart-2)'},
      {label:'未命中',value:miss,color:'var(--v3-chart-4)'}
    ]},legend:'chartCacheLegend',centerLabel:'Prompt'});

    renderHeat();
  }
  function renderHeat(){
    const rows = (state.recent&&state.recent.rows)||[];
    const cells = [];
    const map = new Map();
    rows.forEach(r=>{
      const d = new Date((r.at||0)*1000);
      if(isNaN(d.getTime())) return;
      const day = (d.getDay()+6)%7, hour = d.getHours();
      const key = day+':'+hour;
      map.set(key,(map.get(key)||0)+1);
    });
    for(let d=0;d<7;d++) for(let h=0;h<24;h++) cells.push({d,h,v:map.get(d+':'+h)||0});
    if(rows.length) TraeCharts.render('chartHeat',{type:'heatmap',data:{cells},legend:null});
    else chartEmpty('chartHeat','暂无最近请求');
  }

  function decorateAccounts(){
    const rows = document.querySelectorAll('#accounts table tbody tr');
    if(!rows.length) return;
    const list = (window.ACCOUNTS||[]).filter(a=>!a.realm || a.realm===realm());
    const analytics = (state.analytics&&state.analytics.accounts)||[];
    const maxTok = Math.max(1,...analytics.map(a=>num((a.today&&a.today.total_tokens)||(a.all_time&&a.all_time.total_tokens))));
    rows.forEach((row,idx)=>{
      if(row.classList.contains('v3-decorated')) return;
      const tds = row.children;
      if(tds.length < 4) return;
      let acct = list[idx];
      if(!acct){
        const m = (row.innerHTML.match(/toggleAccount\("([^"]+)"/)||[])[1];
        if(m) acct = list.find(a=>a.uidTail===m);
      }
      if(!acct) return;
      row.classList.add('account-row','v3-decorated');
      const status = !acct.enabled ? 'off' : (acct.breakerFor||acct.cooldownFor||acct.lastError ? 'risk' : 'ready');
      row.classList.add(status);
      row.title = '状态: '+status+' · 令牌: '+(acct.expiresIn||'未知')+' · 最近错误: '+(acct.lastError||'无');
      // 头像 / 名称
      const nameTd = tds[1];
      if(nameTd && !nameTd.querySelector('.acct-avatar')){
        const initial = (acct.account && (acct.account.username||acct.account.email) || 'T').replace(/\*/g,'').slice(0,1) || 'T';
        const avatar = document.createElement('span');
        avatar.className='acct-avatar';
        if(acct.account && acct.account.avatar_url){
          avatar.innerHTML='<img src="'+esc(acct.account.avatar_url)+'" alt="" style="width:100%;height:100%;border-radius:9px;object-fit:cover">';
        } else avatar.textContent = initial;
        nameTd.insertBefore(avatar, nameTd.firstChild);
      }
      // 状态圈
      const statusTd = tds[2];
      if(statusTd && !statusTd.querySelector('.health-ring')){
        const ring = document.createElement('span'); ring.className='health-ring';
        statusTd.insertBefore(ring, statusTd.firstChild);
      }
      // 到期 chip + 用量条
      const entTd = tds[3];
      if(entTd && !entTd.querySelector('.expiry-chip')){
        const d = daysLeft(acct.expiresAt);
        if(d !== null){
          const chip=document.createElement('span');
          chip.className='expiry-chip '+(d<=0?'bad':(d<=3?'warn':''));
          chip.textContent = d<=0 ? '已过期' : (d+' 天到期');
          entTd.appendChild(chip);
        }
      }
      if(nameTd && !nameTd.querySelector('.quota-bar')){
        const u = analytics.find(a=>a.uid===acct.uid || String(a.uid).endsWith(acct.uidTail));
        const tokens = num(u&&((u.today&&u.today.total_tokens)||(u.all_time&&u.all_time.total_tokens)));
        const bar=document.createElement('div'); bar.className='quota-bar';
        bar.innerHTML='<i style="width:'+Math.max(2,Math.round(tokens/maxTok*100))+'%"></i>';
        nameTd.appendChild(bar);
        const note=document.createElement('div'); note.className='acct-note';
        const reqs = u ? num((u.today&&u.today.requests)||(u.all_time&&u.all_time.requests)) : 0;
        note.textContent = fmt(tokens)+' token · '+reqs+' 次';
        nameTd.appendChild(note);
      }
      if(acct.lastError && !row.querySelector('.risk-pill')){
        const pill=document.createElement('span'); pill.className='risk-pill'; pill.textContent='风控/异常';
        tds[2].appendChild(pill);
      }
    });
  }

  function decorateModels(){
    const rows = document.querySelectorAll('#modelsTable tbody tr');
    const list = window.MODELS_DATA || [];
    rows.forEach((row,i)=>{
      if(row.classList.contains('v3-decorated')) return;
      const m = list[i]; if(!m) return;
      const tds=row.children; if(tds.length<6) return;
      const avail = m.available!==false && m.enabled!==false;
      row.classList.add('model-row','v3-decorated');
      row.classList.toggle('unavailable',!avail);
      row.dataset.search = [m.id,m.name,m.upstream_key,(m.aliases||[]).join(' '),(m.groups||[]).join(' '),m.description||''].join(' ').toLowerCase();
      row.dataset.available = avail ? '1' : '0';
      row.dataset.realm = m.realm || realm();
      const caps=[];
      if(m.multimodal||m.supports_vision||(m.capabilities&&m.capabilities.vision)) caps.push('vision');
      if(m.supports_tool_calls||(m.capabilities&&m.capabilities.tool_calls)) caps.push('tools');
      if(m.supports_reasoning||(m.capabilities&&m.capabilities.reasoning)) caps.push('reasoning');
      row.dataset.caps = caps.join(',');
      row.dataset.probe = m.probe ? (m.probe.ok ? '1' : '0') : '';
      const availCell = tds[1];
      if(availCell && m.probe && !availCell.querySelector('.probe-chip')){
        const chip=document.createElement('span');
        chip.className='probe-chip '+(m.probe.ok?'ok':'bad');
        chip.textContent=m.probe.ok?('✓ '+(Number(m.probe.elapsed_ms||0)/1000).toFixed(1)+'s'):('✕ '+probeStatusLabel(m.probe.status));
        chip.title=m.probe.error||'';
        availCell.appendChild(chip);
      }
      row.title = (m.description||'') + (m.disabled_reason ? ('\n不可用：'+m.disabled_reason) : '');
      const nameCell=tds[0];
      if(nameCell && !nameCell.querySelector('.availability-dot')){
        const dot=document.createElement('span'); dot.className='availability-dot';
        const wrapper=nameCell.querySelector('div') || nameCell;
        wrapper.insertBefore(dot, wrapper.firstChild);
      }
      const capCell=tds[3];
      if(capCell) capCell.querySelectorAll('.badge').forEach(b=>{
        const txt=b.textContent.trim();
        b.classList.add('model-cap');
        if(txt==='推理') b.classList.add('think');
        if(txt==='视觉'||txt==='工具') b.classList.add('on');
      });
    });
  }

  function applyModelFilter(){
    const q=($('modelSearch')&&$('modelSearch').value||'').trim().toLowerCase();
    const realmF=$('modelRealmFilter')&&$('modelRealmFilter').value;
    const availF=$('modelAvailFilter')&&$('modelAvailFilter').value;
    const caps=[...document.querySelectorAll('#modelFilterBar .filter-chip.active')].map(b=>b.getAttribute('data-cap')).filter(Boolean);
    const probeOnly=[...document.querySelectorAll('#modelFilterBar .filter-chip[data-probe].active')].length>0;
    let shown=0;
    document.querySelectorAll('#modelsTable tbody tr').forEach(row=>{
      if(!row.classList.contains('model-row')) return;
      let ok=true;
      if(q && !(row.dataset.search||'').includes(q)) ok=false;
      if(realmF && row.dataset.realm!==realmF) ok=false;
      if(availF && row.dataset.available!==availF) ok=false;
      if(caps.length && !caps.every(c=>(row.dataset.caps||'').includes(c))) ok=false;
      if(probeOnly && row.dataset.probe!=='1') ok=false;
      row.style.display=ok?'':'none';
      if(ok) shown++;
    });
    updateModelResultCount(shown);
  }
  function updateModelResultCount(shown){
    const el=$('modelResultCount');
    if(!el) return;
    const total=document.querySelectorAll('#modelsTable tbody tr.model-row').length;
    el.textContent='显示 '+(shown==null?total:shown)+' / '+total+' 个模型';
  }

  function decorateTasks(){
    const rows=document.querySelectorAll('#growthTable tbody tr');
    rows.forEach(row=>{
      if(row.classList.contains('v3-decorated')) return;
      const tds=row.children; if(tds.length<5) return;
      row.classList.add('v3-decorated');
      const status=tds[3];
      if(status && !status.querySelector('.health-ring')){
        const ring=document.createElement('span'); ring.className='health-ring';
        const ok=row.textContent.includes('成功')||row.textContent.includes('完成');
        if(!ok) ring.style.background='var(--warn)';
        status.insertBefore(ring,status.firstChild);
      }
    });
  }

  function observe(){
    let queued=false;
    const run=()=>{
      queued=false;
      decorateAccounts();
      decorateModels();
      decorateTasks();
      if(state.daily) renderKpiSparks();
    };
    const obs=new MutationObserver(()=>{
      if(queued) return;
      queued=true;
      requestAnimationFrame(run);
    });
    obs.observe(document.body,{childList:true,subtree:true});
  }

  function onTab(tab){
    initLayout();
    if(tab==='gateway') loadOverviewPage(false);
    else if(tab==='accounts') loadAccountsPage(false);
    else if(tab==='models') loadModelsPage(false);
    else if(tab==='analytics') loadAnalyticsPage(false);
    else if(tab==='tasks') loadTasksPage(false);
    else if(tab==='settings' && typeof loadAgentsPage==='function') loadAgentsPage(false);
  }

  function init(){
    initLayout();
    // 拦截主脚本的页签切换；原函数保留，追加图表与装饰
    if(typeof window.switchMainTab==='function' && !window.__v3SwitchPatched){
      window.__v3SwitchPatched=true;
      const orig=window.switchMainTab;
      window.switchMainTab=function(tab){ const r=orig.apply(this,arguments); try{ onTab(tab); }catch(e){ console.warn('v3 tab failed',e); } return r; };
    }
    setTimeout(()=>onTab((typeof currentMainTab !== 'undefined' ? currentMainTab : window.__MAIN_TAB__) || 'gateway'), 500);
    setInterval(()=>{
      if((typeof currentMainTab !== 'undefined' ? currentMainTab : '')==='accounts'){ state.accounts=window.ACCOUNTS||[]; renderAccountHero(); decorateAccounts(); }
      if((typeof currentMainTab !== 'undefined' ? currentMainTab : '')==='models'){ decorateModels(); }
    }, 12000);
    setInterval(()=>{
      if((typeof currentMainTab !== 'undefined' ? currentMainTab : '')==='models'){ loadDiscoveryStatus(); }
    }, 30000);
  }

  window.V3={init,onTab,state,decorateAccounts,decorateModels,loadAnalyticsPage,loadOverviewPage};
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',()=>setTimeout(init,0));
  else setTimeout(init,0);
})();
