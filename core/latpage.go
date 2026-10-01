package fastime

import (
	"fmt"
	"net/http"
)

// serveLatency 上游延迟折线图页（精美深色大屏风，Canvas 手绘，无任何外部依赖可离线打开）。
// 数据每 5s 从 /latency.json 拉取；空心点 = 空闲探测，实心点 = 真实请求。
func (s *Server) serveLatency(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📈</text></svg>">
<title>Fastime 上游延迟</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;color:#dbe4ff;
background:radial-gradient(1200px 600px at 80% -10%,#1b2a4e 0%,transparent 60%),
radial-gradient(900px 500px at -10% 110%,#123c3a 0%,transparent 55%),#0b1020}
.wrap{max-width:960px;margin:0 auto;padding:28px 16px 40px}
.hd{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.hd h1{font-size:20px;font-weight:650;letter-spacing:.5px}
.hd .sub{font-size:12px;color:#8b98b8}
.back{font-size:12px;color:#cfe0ff;background:rgba(120,160,255,.12);border:1px solid rgba(120,160,255,.3);
padding:5px 13px;border-radius:999px;text-decoration:none;margin-left:auto}
.back:hover{background:rgba(120,160,255,.25)}
.panel{background:rgba(20,28,52,.72);border:1px solid rgba(120,160,255,.14);border-radius:16px;
padding:18px;box-shadow:0 8px 32px rgba(0,0,0,.35);backdrop-filter:blur(6px)}
.legend{display:flex;flex-wrap:wrap;gap:10px 22px;margin-bottom:12px;font-size:13px}
.lg{display:flex;align-items:center;gap:8px}
.lg .sw{width:22px;height:3px;border-radius:2px}
.lg .name{color:#aebadd}
.lg .val{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-weight:600}
.lg .stat{color:#66739a;font-size:11.5px}
#cv{width:100%;height:420px;display:block;cursor:crosshair}
.tip{position:fixed;pointer-events:none;background:rgba(10,16,34,.95);border:1px solid rgba(120,160,255,.3);
border-radius:10px;padding:8px 12px;font-size:12px;line-height:1.7;display:none;z-index:9;
box-shadow:0 6px 20px rgba(0,0,0,.5);font-family:ui-monospace,Consolas,monospace}
.empty{color:#66739a;text-align:center;padding:60px 0;font-size:13px}
.note{margin-top:12px;font-size:11.5px;color:#5a6690;display:flex;gap:16px;flex-wrap:wrap}
.dotp{display:inline-block;width:7px;height:7px;border-radius:50%;vertical-align:1px;margin-right:5px}
</style></head><body><div class="wrap">
<div class="hd"><h1>📈 上游延迟曲线</h1><span class="sub">真实请求 + 空闲探测（30s）· 每 5s 自动刷新</span>
<a class="back" href="/">← 返回状态页</a></div>
<div class="panel">
<div class="legend" id="legend"></div>
<canvas id="cv"></canvas>
<div class="empty" id="empty" style="display:none">暂无延迟数据 —— 产生首次上游请求或等待 30s 空闲探测后出现</div>
<div class="note">
<span><span class="dotp" style="background:#5b9dff"></span>主上游</span>
<span><span class="dotp" style="background:#ffb340"></span>后备上游</span>
<span><span class="dotp" style="border:1.5px solid #8b98b8;background:transparent"></span>空心点 = 空闲探测</span>
<span><span class="dotp" style="background:#8b98b8"></span>实心点 = 真实请求</span>
</div></div></div>
<div class="tip" id="tip"></div>
<script>
const cv=document.getElementById('cv'),tip=document.getElementById('tip');
const C1='#5b9dff',C2='#ffb340',GRID='rgba(139,152,184,.13)',TXT='#66739a';
let DATA={primary:[],fallback:[]},hover=-1;
function fmtT(t){const d=new Date(t*1000);return d.toTimeString().slice(0,8)}
function draw(){
  const dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;
  if(cv.width!==W*dpr){cv.width=W*dpr;cv.height=H*dpr}
  const x=cv.getContext('2d');x.setTransform(dpr,0,0,dpr,0,0);x.clearRect(0,0,W,H);
  const all=[...DATA.primary,...DATA.fallback];
  document.getElementById('empty').style.display=all.length?'none':'block';
  if(!all.length)return;
  const padL=56,padR=18,padT=14,padB=30,cw=W-padL-padR,ch=H-padT-padB;
  const t0=Math.min(...all.map(p=>p.t)),t1=Math.max(...all.map(p=>p.t));
  let mx=Math.max(...all.map(p=>p.ms));mx=Math.max(mx*1.15,10);
  const nice=v=>{const st=[10,20,50,100,200,500,1000,2000,5000];for(const s of st)if(v<=s)return s;return Math.ceil(v/5000)*5000};
  mx=nice(mx);
  const X=t=>padL+(t1>t0?(t-t0)/(t1-t0)*cw:cw/2), Y=v=>padT+ch-(v/mx)*ch;
  // 网格 + 轴
  x.strokeStyle=GRID;x.fillStyle=TXT;x.font='11px ui-monospace,Consolas,monospace';x.lineWidth=1;
  for(let i=0;i<=4;i++){const v=mx*i/4,y=Y(v);
    x.beginPath();x.moveTo(padL,y);x.lineTo(W-padR,y);x.stroke();
    x.textAlign='right';x.fillText(v.toFixed(0)+' ms',padL-8,y+4);}
  const nt=Math.min(6,Math.max(2,Math.floor(cw/110)));
  x.textAlign='center';
  for(let i=0;i<nt;i++){const t=t0+(t1-t0)*i/(nt-1);x.fillText(fmtT(t),X(t),H-padB+18);}
  // 序列
  const series=[[DATA.primary,C1],[DATA.fallback,C2]];
  window._pts=[];
  series.forEach(([pts,col],si)=>{
    if(!pts.length)return;
    pts=pts.slice().sort((a,b)=>a.t-b.t);
    // 渐变面积
    const g=x.createLinearGradient(0,padT,0,padT+ch);
    g.addColorStop(0,col+'44');g.addColorStop(1,col+'00');
    x.beginPath();x.moveTo(X(pts[0].t),Y(pts[0].ms));
    for(let i=1;i<pts.length;i++){const xm=(X(pts[i-1].t)+X(pts[i].t))/2;
      x.bezierCurveTo(xm,Y(pts[i-1].ms),xm,Y(pts[i].ms),X(pts[i].t),Y(pts[i].ms));}
    x.lineTo(X(pts[pts.length-1].t),padT+ch);x.lineTo(X(pts[0].t),padT+ch);x.closePath();
    x.fillStyle=g;x.fill();
    // 线
    x.beginPath();x.moveTo(X(pts[0].t),Y(pts[0].ms));
    for(let i=1;i<pts.length;i++){const xm=(X(pts[i-1].t)+X(pts[i].t))/2;
      x.bezierCurveTo(xm,Y(pts[i-1].ms),xm,Y(pts[i].ms),X(pts[i].t),Y(pts[i].ms));}
    x.strokeStyle=col;x.lineWidth=2;x.lineJoin='round';x.shadowColor=col;x.shadowBlur=8;x.stroke();x.shadowBlur=0;
    // 点
    pts.forEach(p=>{const px=X(p.t),py=Y(p.ms);
      window._pts.push({x:px,y:py,p,col,si});
      x.beginPath();x.arc(px,py,p.p?3:2.6,0,7);
      if(p.p){x.strokeStyle=col;x.lineWidth=1.5;x.stroke();}
      else{x.fillStyle=col;x.fill();}});
  });
  // 悬停十字线
  if(hover>=0&&window._pts[hover]){const h=window._pts[hover];
    x.strokeStyle='rgba(219,228,255,.35)';x.setLineDash([4,4]);
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
cv.addEventListener('mouseleave',()=>{hover=-1;tip.style.display='none';draw()});
window.addEventListener('resize',draw);
pull();setInterval(pull,5000);
</script></div></body></html>`)
}
