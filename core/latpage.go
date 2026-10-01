package fastime

import (
	"fmt"
	"net/http"
)

// serveLatency 上游延迟折线图页：与状态页/缓存页统一的浅色卡片风格，
// 纯 Canvas 手绘无外部依赖。页面打开期间每 2s 轮询数据并触发主动探测，
// 曲线实时走动；页面关闭后只剩 30s 空闲探测。
func (s *Server) serveLatency(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<title>Fastime 上游延迟</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#1a1a2e;background:#f4f6fa}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);overflow:hidden}
.hd{display:flex;align-items:center;gap:10px;padding:16px 20px;background:linear-gradient(135deg,#1a73e8,#0d47a1);color:#fff}
.hd h1{font-size:18px;margin:0;font-weight:600}
.hd .sub{font-size:11.5px;opacity:.85}
.badge{font-size:12px;background:rgba(255,255,255,.18);padding:3px 10px;border-radius:999px}
.btn{margin-left:auto;font-size:12px;color:#fff;background:rgba(255,255,255,.16);padding:4px 12px;border-radius:999px;text-decoration:none;border:1px solid rgba(255,255,255,.35);white-space:nowrap}
.btn:hover{background:rgba(255,255,255,.3)}
.legend{display:flex;flex-wrap:wrap;gap:8px 20px;padding:14px 18px 4px;font-size:13px}
.lg{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.lg .sw{width:20px;height:3px;border-radius:2px;flex:none}
.lg .name{color:#666}
.lg .val{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-weight:650}
.lg .stat{color:#999;font-size:11.5px;font-family:ui-monospace,Consolas,monospace}
.cvw{padding:6px 8px 4px}
#cv{width:100%;height:400px;display:block;cursor:crosshair}
.tip{position:fixed;pointer-events:none;background:#fff;border:1px solid #dbe2f0;border-radius:9px;
padding:7px 11px;font-size:12px;line-height:1.7;display:none;z-index:9;
box-shadow:0 4px 16px rgba(26,35,80,.14);font-family:ui-monospace,Consolas,monospace}
.empty{color:#999;text-align:center;padding:60px 0;font-size:13px}
.note{padding:10px 18px 16px;font-size:11.5px;color:#999;display:flex;gap:14px;flex-wrap:wrap}
.dotp{display:inline-block;width:7px;height:7px;border-radius:50%;vertical-align:1px;margin-right:4px}
@media (max-width:720px){
  body{margin:10px auto;padding:0 8px}
  .hd{padding:13px 14px;flex-wrap:wrap}
  .hd h1{font-size:16px}
  .btn{margin-left:0}
  #cv{height:290px}
  .legend{gap:6px 14px;padding:12px 12px 2px;font-size:12px}
  .lg .stat{flex-basis:100%}
  .note{padding:8px 12px 12px}
}
</style></head><body><div class="card">
<div class="hd"><h1>📈 上游延迟曲线</h1><span class="badge" id="live">实时</span>
<span class="sub">页面打开时每 2s 主动探测 · 关闭后 30s 空闲探测</span><a class="btn" href="/">← 返回状态页</a></div>
<div class="legend" id="legend"></div>
<div class="cvw"><canvas id="cv"></canvas></div>
<div class="empty" id="empty" style="display:none">暂无延迟数据 —— 首次探测约 2 秒后出现</div>
<div class="note">
<span><span class="dotp" style="background:#1a73e8"></span>主上游</span>
<span><span class="dotp" style="background:#f29900"></span>后备上游</span>
<span><span class="dotp" style="border:1.5px solid #999;background:transparent"></span>空心点 = 探测</span>
<span><span class="dotp" style="background:#999"></span>实心点 = 真实请求</span>
</div></div>
<div class="tip" id="tip"></div>
<script>
const cv=document.getElementById('cv'),tip=document.getElementById('tip');
const C1='#1a73e8',C2='#f29900',GRID='#e8ecf4',TXT='#98a2b8';
let DATA={primary:[],fallback:[]},hover=-1;
function fmtT(t){const d=new Date(t*1000);return d.toTimeString().slice(0,8)}
function draw(){
  const dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;
  if(cv.width!==Math.round(W*dpr)){cv.width=Math.round(W*dpr);cv.height=Math.round(H*dpr)}
  const x=cv.getContext('2d');x.setTransform(dpr,0,0,dpr,0,0);x.clearRect(0,0,W,H);
  const all=[...DATA.primary,...DATA.fallback];
  document.getElementById('empty').style.display=all.length?'none':'block';
  if(!all.length)return;
  const padL=52,padR=16,padT=12,padB=28,cw=W-padL-padR,ch=H-padT-padB;
  const t0=Math.min(...all.map(p=>p.t)),t1=Math.max(...all.map(p=>p.t));
  let mx=Math.max(...all.map(p=>p.ms))*1.15;
  const nice=v=>{const st=[10,20,50,100,200,500,1000,2000,5000,10000];for(const s of st)if(v<=s)return s;return Math.ceil(v/10000)*10000};
  mx=nice(Math.max(mx,10));
  const X=t=>padL+(t1>t0?(t-t0)/(t1-t0)*cw:cw/2), Y=v=>padT+ch-(v/mx)*ch;
  x.strokeStyle=GRID;x.fillStyle=TXT;x.font='11px ui-monospace,Consolas,monospace';x.lineWidth=1;
  for(let i=0;i<=4;i++){const v=mx*i/4,y=Y(v);
    x.beginPath();x.moveTo(padL,y);x.lineTo(W-padR,y);x.stroke();
    x.textAlign='right';x.fillText(v.toFixed(0)+' ms',padL-7,y+4);}
  const nt=Math.min(6,Math.max(2,Math.floor(cw/110)));
  x.textAlign='center';
  for(let i=0;i<nt;i++){const t=t0+(t1-t0)*i/(nt-1);x.fillText(fmtT(t),X(t),H-padB+17);}
  window._pts=[];
  [[DATA.primary,C1],[DATA.fallback,C2]].forEach(([pts,col],si)=>{
    if(!pts.length)return;
    pts=pts.slice().sort((a,b)=>a.t-b.t);
    const g=x.createLinearGradient(0,padT,0,padT+ch);
    g.addColorStop(0,col+'22');g.addColorStop(1,col+'00');
    x.beginPath();x.moveTo(X(pts[0].t),Y(pts[0].ms));
    for(let i=1;i<pts.length;i++){const xm=(X(pts[i-1].t)+X(pts[i].t))/2;
      x.bezierCurveTo(xm,Y(pts[i-1].ms),xm,Y(pts[i].ms),X(pts[i].t),Y(pts[i].ms));}
    x.lineTo(X(pts[pts.length-1].t),padT+ch);x.lineTo(X(pts[0].t),padT+ch);x.closePath();
    x.fillStyle=g;x.fill();
    x.beginPath();x.moveTo(X(pts[0].t),Y(pts[0].ms));
    for(let i=1;i<pts.length;i++){const xm=(X(pts[i-1].t)+X(pts[i].t))/2;
      x.bezierCurveTo(xm,Y(pts[i-1].ms),xm,Y(pts[i].ms),X(pts[i].t),Y(pts[i].ms));}
    x.strokeStyle=col;x.lineWidth=2;x.lineJoin='round';x.stroke();
    pts.forEach(p=>{const px=X(p.t),py=Y(p.ms);
      window._pts.push({x:px,y:py,p,col,si});
      x.beginPath();x.arc(px,py,p.p?3:2.6,0,7);
      if(p.p){x.strokeStyle=col;x.lineWidth=1.5;x.stroke();}
      else{x.fillStyle=col;x.fill();}});
  });
  if(hover>=0&&window._pts[hover]){const h=window._pts[hover];
    x.strokeStyle='#c3cbdd';x.setLineDash([4,4]);
    x.beginPath();x.moveTo(h.x,padT);x.lineTo(h.x,padT+ch);x.stroke();x.setLineDash([]);
    x.beginPath();x.arc(h.x,h.y,5,0,7);x.fillStyle=h.col;x.fill();
    x.strokeStyle='#fff';x.lineWidth=1.5;x.stroke();}
}
function legend(){
  const L=document.getElementById('legend');let h='';
  const item=(pts,name,col)=>{
    if(!pts.length)return '';
    const ms=pts.map(p=>p.ms),last=ms[ms.length-1];
    const avg=(ms.reduce((a,b)=>a+b,0)/ms.length).toFixed(0);
    return '<div class="lg"><span class="sw" style="background:'+col+'"></span><span class="name">'+name+
      '</span><span class="val" style="color:'+col+'">'+last+' ms</span><span class="stat">均值 '+avg+
      ' · 最低 '+Math.min(...ms)+' · 最高 '+Math.max(...ms)+' · '+pts.length+' 点</span></div>';};
  h+=item(DATA.primary,'主上游 '+(DATA.primaryName||''),C1);
  h+=item(DATA.fallback,'后备上游 '+(DATA.fallbackName||''),C2);
  L.innerHTML=h;
}
async function pull(){
  try{const r=await fetch('/latency.json');DATA=await r.json();legend();draw();}catch(e){}
}
cv.addEventListener('mousemove',e=>{
  if(!window._pts||!window._pts.length)return;
  const r=cv.getBoundingClientRect(),mx=e.clientX-r.left;
  let bi=-1,bd=1e9;
  window._pts.forEach((p,i)=>{const d=Math.abs(p.x-mx);if(d<bd){bd=d;bi=i}});
  if(bi>=0&&bd<40){hover=bi;const p=window._pts[bi];
    tip.style.display='block';
    tip.innerHTML=(p.si===0?'<span style="color:'+C1+'">主上游':'<span style="color:'+C2+'">后备上游')+'</span><br>'+
      fmtT(p.p.t)+'<br><b>'+p.p.ms+' ms</b>'+(p.p.p?' · 探测':' · 真实请求');
    tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY+10)+'px';}
  else{hover=-1;tip.style.display='none'}
  draw();
});
cv.addEventListener('touchstart',e=>{const t=e.touches[0];
  cv.dispatchEvent(new MouseEvent('mousemove',{clientX:t.clientX,clientY:t.clientY}));},{passive:true});
cv.addEventListener('mouseleave',()=>{hover=-1;tip.style.display='none';draw()});
window.addEventListener('resize',draw);
pull();setInterval(pull,2000);
</script></body></html>`)
}
