
/* dashboard-charts.js — 零依赖 Canvas 图表引擎
   line / area / bar / stacked-bar / donut / hbar / heatmap / spark
   全部 DPR 自适应、主题联动、入场动画、悬停 tooltip / 十字线 / 高亮。 */
(function(global){
  'use strict';
  const reduceMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const DPR = () => Math.min(3, window.devicePixelRatio || 1);
  const registry = new Map();
  let tipEl = null;
  let tipTimer = 0;

  function css(name, fallback){
    try{
      const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return v || fallback || '#2563eb';
    }catch(e){ return fallback || '#2563eb'; }
  }
  function palette(){
    return [css('--v3-chart-1','#2563eb'), css('--v3-chart-2','#16a34a'), css('--v3-chart-3','#7c3aed'),
            css('--v3-chart-4','#f59e0b'), css('--v3-chart-5','#ec4899'), css('--v3-chart-6','#06b6d4')];
  }
  function fmt(v){
    const n = Number(v) || 0;
    if(Math.abs(n) >= 1e9) return (n/1e9).toFixed(n >= 1e10 ? 0 : 1) + 'B';
    if(Math.abs(n) >= 1e6) return (n/1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
    if(Math.abs(n) >= 1e4) return (n/1e3).toFixed(n >= 1e5 ? 0 : 1) + 'K';
    if(Math.abs(n) >= 100) return Math.round(n).toLocaleString();
    if(Math.abs(n) >= 10) return (Math.round(n*10)/10).toLocaleString();
    return (Math.round(n*100)/100).toLocaleString();
  }
  function pct(v){ return (Number(v) || 0).toFixed(1) + '%'; }
  function clamp(v,a,b){ return Math.max(a, Math.min(b, v)); }
  function easeOut(t){ return 1 - Math.pow(1 - t, 3); }
  function resolveColor(value){
    var s = String(value == null ? '' : value).trim();
    if(s.indexOf('var(') === 0){
      var end = s.indexOf(')');
      var name = s.slice(4, end > 0 ? end : s.length).split(',')[0].trim();
      return css(name, '#2563eb');
    }
    return s;
  }
  function hexA(color, alpha){
    // 支持 #rrggbb / rgb() / CSS 变量；变量先解析成真实颜色
    const c = resolveColor(color);
    let m = c.match(/^#([0-9a-f]{6})$/i);
    if(m){
      const n = parseInt(m[1], 16);
      return 'rgba(' + ((n>>16)&255) + ',' + ((n>>8)&255) + ',' + (n&255) + ',' + alpha + ')';
    }
    m = c.match(/^#([0-9a-f]{3})$/i);
    if(m){
      const h = m[1];
      return 'rgba(' + parseInt(h[0]+h[0],16) + ',' + parseInt(h[1]+h[1],16) + ',' + parseInt(h[2]+h[2],16) + ',' + alpha + ')';
    }
    return c;
  }
  function roundRect(ctx,x,y,w,h,r){
    r = Math.min(r, Math.abs(w)/2, Math.abs(h)/2);
    ctx.beginPath();
    ctx.moveTo(x+r,y); ctx.lineTo(x+w-r,y); ctx.quadraticCurveTo(x+w,y,x+w,y+r);
    ctx.lineTo(x+w,y+h-r); ctx.quadraticCurveTo(x+w,y+h,x+w-r,y+h);
    ctx.lineTo(x+r,y+h); ctx.quadraticCurveTo(x,y+h,x,y+h-r);
    ctx.lineTo(x,y+r); ctx.quadraticCurveTo(x,y,x+r,y); ctx.closePath();
  }
  function smooth(ctx, pts){
    if(!pts.length) return;
    if(pts.length === 1){ ctx.moveTo(pts[0][0], pts[0][1]); return; }
    ctx.moveTo(pts[0][0], pts[0][1]);
    for(let i=0;i<pts.length-1;i++){
      const p0 = pts[i-1] || pts[i], p1 = pts[i], p2 = pts[i+1], p3 = pts[i+2] || p2;
      const cp1x = p1[0] + (p2[0]-p0[0])/6;
      const cp1y = p1[1] + (p2[1]-p0[1])/6;
      const cp2x = p2[0] - (p3[0]-p1[0])/6;
      const cp2y = p2[1] - (p3[1]-p1[1])/6;
      ctx.bezierCurveTo(cp1x,cp1y,cp2x,cp2y,p2[0],p2[1]);
    }
  }
  function ensureTip(){
    if(tipEl && document.body.contains(tipEl)) return tipEl;
    tipEl = document.createElement('div');
    tipEl.className = 'trae-tip';
    document.body.appendChild(tipEl);
    return tipEl;
  }
  function showTip(x, y, html){
    const el = ensureTip();
    el.innerHTML = html;
    el.classList.add('show');
    el.style.opacity = '1';
    const pad = 12;
    const rect = el.getBoundingClientRect();
    const left = clamp(x, rect.width/2 + pad, window.innerWidth - rect.width/2 - pad);
    const top = clamp(y, rect.height + pad + 8, window.innerHeight - pad);
    el.style.left = left + 'px';
    el.style.top = top + 'px';
    clearTimeout(tipTimer);
    tipTimer = setTimeout(() => el.classList.remove('show'), 4200);
  }
  function hideTip(){
    if(tipEl){ tipEl.classList.remove('show'); tipEl.style.opacity = '0'; }
  }
  function legendHTML(items){
    return items.map(it => '<span class="lg"><i style="background:' + it.color + '"></i>'
      + (it.label || it.name || '') + (it.value != null ? ' <b>' + fmt(it.value) + '</b>' : '') + '</span>').join('');
  }
  const themeObserver = new MutationObserver(() => {
    registry.forEach(ch => ch.draw(true));
  });
  themeObserver.observe(document.documentElement, {attributes:true, attributeFilter:['data-theme','data-glass','data-motion']});

  class TraeChart{
    constructor(canvas, opts){
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.opts = Object.assign({type:'line', data:null, height:250, legend:null, empty:'暂无数据'}, opts || {});
      this.data = this.opts.data;
      this.progress = 0;
      this.hover = null;
      this._raf = 0;
      this._resizeObserver = null;
      this._bind();
      this.resize(true);
    }
    _bind(){
      this.canvas.addEventListener('pointermove', e => this._onMove(e));
      this.canvas.addEventListener('pointerleave', () => { this.hover = null; hideTip(); this.draw(true); });
      this.canvas.addEventListener('pointerdown', e => this._onMove(e));
      this.canvas.addEventListener('touchstart', e => { if(e.touches && e.touches[0]) this._onMove({clientX:e.touches[0].clientX, clientY:e.touches[0].clientY}); }, {passive:true});
      if(window.ResizeObserver){
        this._resizeObserver = new ResizeObserver(() => this.resize());
        this._resizeObserver.observe(this.canvas.parentElement || this.canvas);
      }
      this._onWin = () => this.resize();
      window.addEventListener('resize', this._onWin);
    }
    destroy(){
      cancelAnimationFrame(this._raf);
      if(this._resizeObserver) this._resizeObserver.disconnect();
      window.removeEventListener('resize', this._onWin);
      hideTip();
    }
    setOptions(opts){
      this.opts = Object.assign({}, this.opts, opts || {});
      this.resize(true);
    }
    setData(data, opts){
      this.data = data;
      if(opts) this.opts = Object.assign({}, this.opts, opts);
      this.resize(true);
    }
    resize(animate){
      const host = this.canvas.parentElement;
      const rect = host ? host.getBoundingClientRect() : {width:600,height:250};
      const w = Math.max(80, Math.floor(rect.width || 600));
      // 显式 height 优先（spark 仍固定 38）；否则跟随容器高度。
      // 之前只有 spark 使用 opts.height，普通图会被拉伸到整张卡片高度。
      const fixedH = (this.opts.type === 'spark')
        ? (this.opts.height || 38)
        : (this.opts.height || null);
      const h = Math.max(40, Math.floor(fixedH || rect.height || 250));
      const dpr = DPR();
      this.canvas.width = Math.floor(w*dpr);
      this.canvas.height = Math.floor(h*dpr);
      this.canvas.style.width = w + 'px';
      this.canvas.style.height = h + 'px';
      this.ctx.setTransform(dpr,0,0,dpr,0,0);
      this.W = w; this.H = h;
      this.draw(!animate);
    }
    _startAnim(){
      cancelAnimationFrame(this._raf);
      if(reduceMotion() || document.documentElement.getAttribute('data-motion') === 'off'){
        this.progress = 1; this.draw(true); return;
      }
      this.progress = 0;
      const t0 = performance.now();
      const step = (ts) => {
        const p = Math.min(1, (ts - t0) / 720);
        this.progress = easeOut(p);
        this.draw(true);
        if(p < 1) this._raf = requestAnimationFrame(step);
      };
      this._raf = requestAnimationFrame(step);
    }
    _onMove(e){
      if(!this.data) return;
      const rect = this.canvas.getBoundingClientRect();
      const x = e.clientX - rect.left, y = e.clientY - rect.top;
      const hit = this._hit(x,y);
      this.hover = hit;
      this.draw(true);
      if(hit && hit.tip){
        showTip(e.clientX, e.clientY, hit.tip);
      } else { hideTip(); }
    }
    draw(immediate){
      const ctx = this.ctx;
      if(!ctx) return;
      ctx.clearRect(0,0,this.W,this.H);
      const type = (this.opts.type || 'line').toLowerCase();
      const data = this.data;
      if(!data || this._isEmpty(data)){
        this._drawEmpty();
        if(!immediate && !this.progress) this._startAnim();
        return;
      }
      if(!immediate && this.progress === 0 && !reduceMotion()) { this._startAnim(); return; }
      if(this.progress === 0) this.progress = 1;
      try{
        if(type === 'spark') this._drawSpark();
        else if(type === 'bar' || type === 'stackedbar' || type === 'stacked') this._drawBar();
        else if(type === 'donut' || type === 'pie' || type === 'ring') this._drawDonut();
        else if(type === 'hbar' || type === 'horizontalbar') this._drawHBar();
        else if(type === 'heatmap' || type === 'heat') this._drawHeat();
        else this._drawLine();
      }catch(err){
        console.error('chart draw failed', type, err);
        this._drawEmpty('图表渲染失败');
      }
    }
    _isEmpty(d){
      if(Array.isArray(d)) return !d.length;
      if(d.items) return !d.items.length;
      if(d.cells) return !d.cells.length;
      if(d.series) return !d.series.length || !d.series.some(s => (s.values||[]).some(v => Number(v)));
      return !d.values || !d.values.length;
    }
    _drawEmpty(msg){
      const ctx = this.ctx;
      ctx.fillStyle = css('--dim','#64748b');
      ctx.font = '12px ' + (getComputedStyle(document.body).fontFamily || 'sans-serif');
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(msg || this.opts.empty || '暂无数据', this.W/2, this.H/2);
      ctx.textAlign = 'left';
    }
    _hit(){ return null; }

    /* ---------- line / area ---------- */
    _drawLine(){
      const ctx = this.ctx, d = this.data, W = this.W, H = this.H;
      const series = (d.series || []).filter(s => s && Array.isArray(s.values));
      const labels = d.labels || [];
      const n = Math.max(labels.length, ...series.map(s => s.values.length));
      if(!n) return this._drawEmpty();
      const pad = {l:44,r:16,t:16,b:28};
      const iw = W-pad.l-pad.r, ih = H-pad.t-pad.b;
      const all = series.flatMap(s => s.values.map(Number));
      const max = Math.max(1, ...all);
      const colors = palette();
      const grid = css('--v3-chart-grid','rgba(15,23,42,.08)');
      const text = css('--v3-chart-text','#64748b');
      ctx.save();
      ctx.strokeStyle = grid; ctx.lineWidth = 1;
      ctx.font = '10px ' + (getComputedStyle(document.body).fontFamily || 'sans-serif');
      ctx.fillStyle = text; ctx.textBaseline = 'middle';
      for(let g=0;g<=4;g++){
        const yy = pad.t + ih - ih*g/4;
        ctx.beginPath(); ctx.moveTo(pad.l,yy); ctx.lineTo(W-pad.r,yy); ctx.stroke();
        ctx.fillText(this.opts.yFormat ? this.opts.yFormat(max*g/4) : fmt(max*g/4), 4, yy);
      }
      const xOf = i => pad.l + (n === 1 ? iw/2 : iw*i/(n-1));
      const yOf = v => pad.t + ih - (Number(v)||0)/max*ih;
      const prog = this.progress;
      ctx.save();
      ctx.beginPath(); ctx.rect(pad.l, pad.t-2, iw*prog+2, ih+4); ctx.clip();
      series.forEach((s,si) => {
        const color = resolveColor(s.color || colors[si % colors.length]);
        const pts = s.values.map((v,i) => [xOf(i), yOf(v)]);
        if(this.opts.area !== false && s.area !== false){
          const grad = ctx.createLinearGradient(0,pad.t,0,pad.t+ih);
          grad.addColorStop(0, hexA(color,.30));
          grad.addColorStop(1, hexA(color,.01));
          ctx.beginPath(); ctx.moveTo(pts[0][0], pad.t+ih);
          smooth(ctx, pts);
          ctx.lineTo(pts[pts.length-1][0], pad.t+ih); ctx.closePath();
          ctx.fillStyle = grad; ctx.fill();
        }
        ctx.beginPath(); smooth(ctx, pts);
        ctx.strokeStyle = color; ctx.lineWidth = s.width || 2.2; ctx.lineJoin = 'round'; ctx.lineCap = 'round';
        ctx.shadowColor = hexA(color,.28); ctx.shadowBlur = 12; ctx.stroke(); ctx.shadowBlur = 0;
        if(s.dots){
          pts.forEach(p => { ctx.beginPath(); ctx.arc(p[0],p[1],2.2,0,Math.PI*2); ctx.fillStyle = color; ctx.fill(); });
        }
        const last = pts[pts.length-1];
        if(last){
          ctx.beginPath(); ctx.arc(last[0],last[1],4,0,Math.PI*2); ctx.fillStyle = color; ctx.globalAlpha=.22; ctx.fill(); ctx.globalAlpha=1;
          ctx.beginPath(); ctx.arc(last[0],last[1],2.2,0,Math.PI*2); ctx.fillStyle = color; ctx.fill();
        }
      });
      ctx.restore();
      // x labels
      ctx.fillStyle = text; ctx.textAlign = 'center'; ctx.textBaseline = 'top';
      const ticks = Math.min(6,n);
      for(let t=0;t<ticks;t++){
        const i = Math.round(t*(n-1)/Math.max(1,ticks-1));
        ctx.fillText(String(labels[i] == null ? i+1 : labels[i]).slice(0,10), clamp(xOf(i),pad.l+10,W-pad.r-10), pad.t+ih+9);
      }
      ctx.textAlign = 'left';
      // hover
      if(this.hover && this.hover.i != null){
        const i = this.hover.i, xx = xOf(i);
        ctx.strokeStyle = hexA(css('--fg','#0f172a'),.18); ctx.setLineDash([4,4]);
        ctx.beginPath(); ctx.moveTo(xx,pad.t); ctx.lineTo(xx,pad.t+ih); ctx.stroke(); ctx.setLineDash([]);
        series.forEach((s,si) => {
          const color = resolveColor(s.color || colors[si % colors.length]);
          const yy = yOf(s.values[i]);
          ctx.beginPath(); ctx.arc(xx,yy,4.2,0,Math.PI*2); ctx.fillStyle = color; ctx.fill();
          ctx.strokeStyle = css('--glass-bg-strong','#fff'); ctx.lineWidth=2; ctx.stroke();
        });
      }
      ctx.restore();
      this._hit = (x,y) => {
        if(x < pad.l || x > W-pad.r) return null;
        const i = clamp(Math.round((x-pad.l)/(iw/Math.max(1,n-1))),0,n-1);
        const rows = series.map((s,si) => {
          const color = resolveColor(s.color || colors[si % colors.length]);
          return '<div class="tt-r"><span><i style="background:'+color+'"></i>'+(s.name||('系列 '+(si+1)))+'</span><b>'+(this.opts.valueFormat ? this.opts.valueFormat(s.values[i]) : fmt(s.values[i]))+'</b></div>';
        }).join('');
        return {i, tip:'<div class="tt-t">'+(labels[i] == null ? ('#'+(i+1)) : labels[i])+'</div>'+rows};
      };
      this._drawLegend(series.map((s,si) => ({label:s.name||('系列 '+(si+1)), color:s.color||colors[si%colors.length]})));
      this._xOf = xOf; this._yOf = yOf;
    }

    /* ---------- bars ---------- */
    _drawBar(){
      const ctx = this.ctx, d = this.data, W=this.W, H=this.H;
      const labels = d.labels || [];
      const series = (d.series || []).filter(s => Array.isArray(s.values));
      const n = Math.max(labels.length, ...series.map(s => s.values.length));
      if(!n) return this._drawEmpty();
      const pad = {l:44,r:16,t:16,b:30};
      const iw=W-pad.l-pad.r, ih=H-pad.t-pad.b;
      const totals = Array.from({length:n},(_,i)=>series.reduce((a,s)=>a+(Number(s.values[i])||0),0));
      const max = Math.max(1,...totals);
      const grid = css('--v3-chart-grid','rgba(15,23,42,.08)');
      const text = css('--v3-chart-text','#64748b');
      const colors = palette();
      const stacked = (this.opts.type === 'stacked' || this.opts.type === 'stackedbar' || this.opts.stacked === true);
      ctx.save();
      ctx.strokeStyle=grid; ctx.lineWidth=1; ctx.fillStyle=text;
      ctx.font='10px ' + (getComputedStyle(document.body).fontFamily || 'sans-serif');
      ctx.textBaseline='middle';
      for(let g=0;g<=4;g++){
        const yy=pad.t+ih-ih*g/4;
        ctx.beginPath(); ctx.moveTo(pad.l,yy); ctx.lineTo(W-pad.r,yy); ctx.stroke();
        ctx.fillText(this.opts.yFormat ? this.opts.yFormat(max*g/4) : fmt(max*g/4),4,yy);
      }
      const gap = iw/n, bw = Math.max(2, Math.min(stacked ? 26 : 18, gap*.58));
      const prog = this.progress;
      const bars = [];
      for(let i=0;i<n;i++){
        const x = pad.l + gap*i + (gap-bw)/2;
        let bottom = pad.t+ih;
        const segs=[];
        if(stacked){
          series.forEach((s,si) => {
            const v = Number(s.values[i])||0;
            const h = v/max*ih*prog;
            if(h <= 0) return;
            const y = bottom-h;
            const color = resolveColor(s.color || colors[si%colors.length]);
            ctx.fillStyle = color;
            const isTop = segs.length === series.length-1;
            if(segs.length===0) { roundRect(ctx,x,y,bw,h,Math.min(5,bw/2)); ctx.fill(); }
            else { ctx.fillRect(x,y,bw,h+.5); }
            segs.push({s,color,y,h,v});
            bottom -= h;
          });
        }else{
          const v = Number(series[0]?.values[i])||0;
          const h = v/max*ih*prog;
          const y = pad.t+ih-h;
          const color = resolveColor(series[0]?.color || colors[0]);
          const grad = ctx.createLinearGradient(0,y,0,pad.t+ih);
          grad.addColorStop(0,color); grad.addColorStop(1,hexA(color,.35));
          ctx.fillStyle = grad;
          roundRect(ctx,x,y,bw,Math.max(0,h),Math.min(5,bw/2)); ctx.fill();
          segs.push({s:series[0],color,y,h,v});
        }
        bars.push({x,y:bottom,w:bw,segs,i});
      }
      // x labels
      ctx.fillStyle=text; ctx.textAlign='center'; ctx.textBaseline='top';
      const ticks=Math.min(7,n);
      for(let t=0;t<ticks;t++){
        const i=Math.round(t*(n-1)/Math.max(1,ticks-1));
        ctx.fillText(String(labels[i]==null?i+1:labels[i]).slice(0,10), pad.l+gap*i+gap/2, pad.t+ih+9);
      }
      ctx.textAlign='left';
      if(this.hover && this.hover.i != null){
        const b = bars[this.hover.i];
        if(b){
          ctx.fillStyle = hexA(css('--fg','#0f172a'), .045);
          ctx.fillRect(b.x-3,pad.t,b.w+6,ih);
        }
      }
      ctx.restore();
      this._hit = (x) => {
        if(x < pad.l || x > W-pad.r) return null;
        const i = clamp(Math.floor((x-pad.l)/gap),0,n-1);
        const rows = series.map((s,si) => '<div class="tt-r"><span><i style="background:'+(s.color||colors[si%colors.length])+'"></i>'+(s.name||('系列 '+(si+1)))+'</span><b>'+fmt(s.values[i])+'</b></div>').join('');
        return {i, tip:'<div class="tt-t">'+(labels[i]==null?('#'+(i+1)):labels[i])+'</div>'+rows+(stacked?'<div class="tt-r"><span>合计</span><b>'+fmt(totals[i])+'</b></div>':'')};
      };
      this._drawLegend(series.map((s,si)=>({label:s.name||('系列 '+(si+1)), color:s.color||colors[si%colors.length]})));
    }

    /* ---------- donut ---------- */
    _drawDonut(){
      const ctx=this.ctx,d=this.data,W=this.W,H=this.H;
      const items=(d.items||[]).filter(x=>Number(x.value)>0);
      if(!items.length) return this._drawEmpty();
      const total=items.reduce((a,x)=>a+Number(x.value||0),0);
      const cx=W/2, cy=H/2, R=Math.min(W,H)*.34, r=R*.62;
      const colors=palette();
      const start=-Math.PI/2;
      let angle=start;
      const prog=this.progress;
      const active=this.hover && this.hover.i;
      items.forEach((it,i)=>{
        const sweep=(Number(it.value)/total)*Math.PI*2*prog;
        const color=resolveColor(it.color||colors[i%colors.length]);
        const rr=i===active?R+3:R;
        ctx.beginPath();
        ctx.arc(cx,cy,rr,angle,angle+sweep);
        ctx.arc(cx,cy,r,angle+sweep,angle,true);
        ctx.closePath();
        ctx.fillStyle=color;
        ctx.globalAlpha=i===active?1:.92;
        ctx.fill(); ctx.globalAlpha=1;
        if(i===active){ ctx.shadowColor=hexA(color,.45); ctx.shadowBlur=18; ctx.fill(); ctx.shadowBlur=0; }
        angle+=sweep;
      });
      ctx.fillStyle=css('--fg','#0f172a');
      ctx.textAlign='center'; ctx.textBaseline='middle';
      ctx.font='700 22px ' + (getComputedStyle(document.body).fontFamily||'sans-serif');
      ctx.fillText(this.opts.centerFormat ? this.opts.centerFormat(total) : fmt(total),cx,cy-8);
      ctx.font='11px ' + (getComputedStyle(document.body).fontFamily||'sans-serif');
      ctx.fillStyle=css('--dim','#64748b');
      ctx.fillText(this.opts.centerLabel||'合计',cx,cy+14);
      ctx.textAlign='left';
      const segs=[]; angle=start;
      items.forEach((it,i)=>{ const sweep=(Number(it.value)/total)*Math.PI*2; segs.push({start:angle,end:angle+sweep,it,i}); angle+=sweep; });
      this._hit=(x,y)=>{
        const dx=x-cx,dy=y-cy,dist=Math.sqrt(dx*dx+dy*dy);
        if(dist<r||dist>R+6) return null;
        let a=Math.atan2(dy,dx); if(a<-Math.PI/2) a+=Math.PI*2;
        const seg=segs.find(s=>a>=s.start&&a<=s.end); if(!seg) return null;
        const p=Number(seg.it.value)/total*100;
        return {i:seg.i, tip:'<div class="tt-t">'+(seg.it.label||('项目 '+(seg.i+1)))+'</div><div class="tt-r"><span>数值</span><b>'+fmt(seg.it.value)+'</b></div><div class="tt-r"><span>占比</span><b>'+p.toFixed(1)+'%</b></div>'};
      };
      this._drawLegend(items.map((it,i)=>({label:it.label,value:it.value,color:it.color||colors[i%colors.length]})));
    }

    /* ---------- horizontal bars ---------- */
    _drawHBar(){
      const ctx=this.ctx,d=this.data,W=this.W,H=this.H;
      const items=(d.items||[]).filter(x=>Number(x.value)>=0).slice(0, d.limit || 9);
      if(!items.length) return this._drawEmpty();
      const max=Math.max(1,...items.map(x=>Number(x.value)||0));
      const pad={l:Math.min(132,W*.34),r:56,t:8,b:8};
      const ih=H-pad.t-pad.b, rowH=Math.min(34, ih/Math.max(1,items.length));
      const colors=palette();
      ctx.save();
      items.forEach((it,i)=>{
        const y=pad.t+i*rowH+(rowH-10)/2;
        const w=(pad.l? (W-pad.l-pad.r):0);
        const val=Number(it.value)||0;
        const bw=val/max*w*this.progress;
        const color=resolveColor(it.color||colors[i%colors.length]);
        // label
        ctx.fillStyle=css('--fg','#0f172a'); ctx.font='11px ' + (getComputedStyle(document.body).fontFamily||'sans-serif');
        ctx.textBaseline='middle'; ctx.textAlign='left';
        const label=String(it.label||''); const maxLabel=Math.floor(pad.l/7);
        ctx.fillText(label.length>maxLabel?label.slice(0,maxLabel-1)+'…':label, 0, y+5);
        // track
        ctx.fillStyle=hexA(css('--dim','#64748b'),.12);
        roundRect(ctx,pad.l,y,w,10,5); ctx.fill();
        // bar
        ctx.fillStyle=color; roundRect(ctx,pad.l,y,Math.max(2,bw),10,5); ctx.fill();
        if(i=== (this.hover&&this.hover.i)){ ctx.globalAlpha=.18; ctx.fillRect(pad.l-4,y-2,w+8,14); ctx.globalAlpha=1; }
        // value
        ctx.fillStyle=css('--dim','#64748b'); ctx.textAlign='right';
        ctx.fillText(it.display || fmt(val), W-2, y+5);
        ctx.textAlign='left';
      });
      ctx.restore();
      this._hit=(x,y)=>{
        if(x<pad.l-4||x>W) return null;
        const i=clamp(Math.floor((y-pad.t)/rowH),0,items.length-1);
        const it=items[i]; if(!it) return null;
        return {i, tip:'<div class="tt-t">'+it.label+'</div><div class="tt-r"><span>'+(it.metric||'数值')+'</span><b>'+fmt(it.value)+'</b></div>'+(it.sub?'<div class="tt-r"><span>明细</span><b>'+it.sub+'</b></div>':'')};
      };
      this._drawLegend([]);
    }

    /* ---------- heatmap ---------- */
    _drawHeat(){
      const ctx=this.ctx,d=this.data,W=this.W,H=this.H;
      const cells=d.cells||[]; if(!cells.length) return this._drawEmpty();
      const days=d.rowLabels||['周一','周二','周三','周四','周五','周六','周日'];
      const cols=d.colLabels||['0','3','6','9','12','15','18','21'];
      const pad={l:38,r:8,t:20,b:22};
      const iw=W-pad.l-pad.r, ih=H-pad.t-pad.b;
      const cw=iw/24, ch=ih/7;
      const max=Math.max(1,...cells.map(c=>Number(c.v)||0));
      const base=css('--v3-chart-1','#2563eb');
      const text=css('--v3-chart-text','#64748b');
      ctx.save();
      ctx.font='10px ' + (getComputedStyle(document.body).fontFamily||'sans-serif');
      ctx.fillStyle=text; ctx.textBaseline='middle'; ctx.textAlign='right';
      days.forEach((label,i)=>ctx.fillText(label, pad.l-6, pad.t+ch*i+ch/2));
      ctx.textAlign='center'; ctx.textBaseline='top';
      cols.forEach((label,i)=>{
        const hour=Number(label); const x=pad.l+cw*(hour+0.5);
        if(x<W-pad.r) ctx.fillText(label+':00', x, 2);
      });
      const cellMap=new Map(cells.map(c=>[c.d+':'+c.h,c]));
      for(let day=0;day<7;day++){
        for(let h=0;h<24;h++){
          const c=cellMap.get(day+':'+h) || {d:day,h,v:0};
          const v=Number(c.v)||0;
          const a=v?0.10+0.78*Math.pow(v/max,.6):0.035;
          ctx.fillStyle=hexA(base,a);
          roundRect(ctx,pad.l+cw*h+1.5,pad.t+ch*day+1.5,Math.max(2,cw-3),Math.max(2,ch-3),2.5); ctx.fill();
        }
      }
      ctx.restore();
      this._hit=(x,y)=>{
        if(x<pad.l||x>W-pad.r||y<pad.t||y>H-pad.b) return null;
        const h=clamp(Math.floor((x-pad.l)/cw),0,23), day=clamp(Math.floor((y-pad.t)/ch),0,6);
        const c=cellMap.get(day+':'+h)||{v:0};
        return {i:day*24+h, tip:'<div class="tt-t">'+days[day]+' '+String(h).padStart(2,'0')+':00</div><div class="tt-r"><span>请求</span><b>'+fmt(c.v||0)+'</b></div>'};
      };
      this._drawLegend([]);
    }

    /* ---------- sparkline ---------- */
    _drawSpark(){
      const ctx=this.ctx,d=this.data,W=this.W,H=this.H;
      const vals=(d.values||[]).map(Number); if(!vals.length) return;
      const max=Math.max(1,...vals),min=Math.min(0,...vals);
      const pad=4, iw=W-pad*2, ih=H-pad*2;
      const xOf=i=>pad+(vals.length===1?iw/2:iw*i/(vals.length-1));
      const yOf=v=>pad+ih-(v-min)/Math.max(1,max-min)*ih;
      const pts=vals.map((v,i)=>[xOf(i),yOf(v)]);
      const color=resolveColor(d.color||css('--v3-chart-1','#2563eb'));
      const grad=ctx.createLinearGradient(0,pad,0,H-pad);
      grad.addColorStop(0,hexA(color,.35)); grad.addColorStop(1,hexA(color,.01));
      ctx.save();
      ctx.beginPath(); ctx.moveTo(pts[0][0],H-pad); smooth(ctx,pts); ctx.lineTo(pts[pts.length-1][0],H-pad); ctx.closePath();
      ctx.fillStyle=grad; ctx.globalAlpha=this.progress; ctx.fill();
      ctx.beginPath(); smooth(ctx,pts);
      ctx.strokeStyle=color; ctx.lineWidth=1.8; ctx.lineCap='round'; ctx.lineJoin='round'; ctx.stroke();
      ctx.globalAlpha=1;
      const last=pts[pts.length-1];
      ctx.beginPath(); ctx.arc(last[0],last[1],2.4,0,Math.PI*2); ctx.fillStyle=color; ctx.fill();
      ctx.restore();
      this._hit=()=>null;
    }

    _drawLegend(items){
      if(!this.opts.legend) return;
      let el=typeof this.opts.legend==='string'?document.getElementById(this.opts.legend):this.opts.legend;
      if(!el) return;
      if(!items || !items.length){ el.innerHTML=''; return; }
      el.innerHTML=legendHTML(items);
    }
  }

  function render(id, opts){
    const canvas=typeof id==='string'?document.getElementById(id):id;
    if(!canvas) return null;
    const cfg=Object.assign({}, opts || {});
    if(!cfg.data){
      cfg.data={labels:cfg.labels, series:cfg.series, items:cfg.items,
                cells:cfg.cells, values:cfg.values, rowLabels:cfg.rowLabels,
                colLabels:cfg.colLabels, color:cfg.color};
    }
    let chart=registry.get(canvas);
    if(chart && canvas.getContext){ chart.destroy(); registry.delete(canvas); }
    chart=new TraeChart(canvas, cfg);
    registry.set(canvas, chart);
    chart.setData(cfg.data);
    return chart;
  }
  function spark(id, values, color){
    return render(id, {type:'spark', data:{values:values||[], color:color}, height:38, legend:null});
  }
  function destroy(id){
    const canvas=typeof id==='string'?document.getElementById(id):id;
    const chart=canvas&&registry.get(canvas);
    if(chart){ chart.destroy(); registry.delete(canvas); }
  }
  global.TraeCharts={render,spark,destroy,palette,css,fmt,resolveColor};
})(window);
