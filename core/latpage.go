package fastime

import (
	"fmt"
	"net/http"
)

// serveLatency 上游延迟监控页：与状态页/缓存页统一的浅色卡片风格，纯 Canvas
// 手绘无外部依赖。多组图表共享同一时间视窗：滚轮/双指捏合缩放、拖动平移、
// 双击/按钮重置，一处操作全部图表联动。页面打开期间每 2s 轮询数据并触发
// 主动探测；页面关闭后只剩 30s 空闲探测。
func (s *Server) serveLatency(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<title>Fastime 上游延迟</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#1a1a2e;background:#f4f6fa}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);overflow:hidden;margin-bottom:16px}
.hd{display:flex;align-items:center;gap:10px;padding:16px 20px;background:linear-gradient(135deg,#1a73e8,#0d47a1);color:#fff;flex-wrap:wrap}
.hd h1{font-size:18px;margin:0;font-weight:600}
.hd .sub{font-size:11.5px;opacity:.85}
.badge{font-size:12px;background:rgba(255,255,255,.18);padding:3px 10px;border-radius:999px}
.btn{font-size:12px;color:#fff;background:rgba(255,255,255,.16);padding:4px 12px;border-radius:999px;text-decoration:none;border:1px solid rgba(255,255,255,.35);white-space:nowrap;cursor:pointer}
.btn:hover{background:rgba(255,255,255,.3)}
.hd .sp{flex:1}
.zbtn{font-size:14px;min-width:30px;text-align:center;padding:3px 10px}
.sum{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
.sumc{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);padding:12px 16px}
.sumc h3{font-size:13px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.sumc .sw{width:16px;height:4px;border-radius:2px;display:inline-block}
.sumc table{width:100%;border-collapse:collapse}
.sumc td{font-size:12.5px;padding:2px 0;color:#555}
.sumc td:last-child{text-align:right;font-family:ui-monospace,Consolas,monospace;color:#1a1a2e}
.ct{padding:12px 14px 4px;font-size:13.5px;font-weight:600;color:#1a1a2e;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ct .hint{font-size:11px;color:#999;font-weight:400;margin-left:auto}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;padding:6px 16px 2px;font-size:12px;color:#666}
.lg{display:flex;align-items:center;gap:6px}
.lg .sw{width:18px;height:3px;border-radius:2px;flex:none}
.lg .sq{width:10px;height:10px;border-radius:3px;flex:none}
canvas{display:block;width:100%;touch-action:none;cursor:grab}
canvas:active{cursor:grabbing}
.tip{color:#999;font-size:12px;margin:4px 4px 20px}
@media (max-width:720px){
  body{margin:12px auto;padding:0 8px}
  .sum{grid-template-columns:1fr;gap:10px}
  .hd{padding:14px 14px}
  .hd h1{font-size:16px}
}
</style></head><body>
<div class="card">
<div class="hd"><h1>📈 上游延迟监控</h1><span class="badge">实时</span><span class="sub">滚轮/双指缩放 · 拖动平移 · 双击重置</span><span class="sp"></span>
<button class="btn zbtn" onclick="zoomBtn(0.8)">＋</button><button class="btn zbtn" onclick="zoomBtn(1.25)">−</button><button class="btn zbtn" onclick="resetView()">⟲</button>
<a class="btn" href="/">← 返回状态页</a></div>
</div>
<div class="sum" id="sum"></div>
<div id="charts"></div>
<p class="tip">页面打开时每 2 秒主动探测 · 关闭后 30 秒空闲探测 · 空心点=探测，实心点=真实请求 · 构成图分层：DNS→TCP→TLS→等待→传输 · 连接复用时无新建握手，前三层为 0 · 数据保留最近 1440 点</p>
<script>
"use strict";
const C1="#1a73e8",C2="#f29900";
const PH=[["dns","DNS 解析","#7c4dff"],["tcp","TCP 连通","#00acc1"],["tls","TLS/QUIC 握手","#fb8c00"],["wait","等待响应","#90a4ae"],["xfer","传输","#43a047"]];
let D={pri:[],fbk:[]},names={pri:"主上游",fbk:"后备上游"},hasFbk=true;
let view={t0:0,t1:0},follow=true,winW=180; // 默认展示最近 3 分钟
const PADL=52,PADR=12,PADT=10,PADB=24;

function phases(p){ // 分层：dns/tcp/tls 实测；wait=首字节前剩余；xfer=首字节后
  const dns=p.dns||0,tcp=p.tcp||0,tls=p.tls||0,tfb=p.tfb||0;
  let wait,xfer;
  if(tfb>0){wait=Math.max(0,tfb-dns-tcp-tls);xfer=Math.max(0,p.ms-tfb);}
  else{wait=Math.max(0,p.ms-dns-tcp-tls);xfer=0;}
  return [dns,tcp,tls,wait,xfer];
}
function valOf(p,field){
  if(field==="xfer"){const ph=phases(p);return ph[4];}
  return p[field]||0;
}
const CHARTS=[
 {id:"total", title:"总往返耗时", type:"line", field:"ms"},
 {id:"priStack", title:"主上游 · 耗时构成", type:"stack", src:"pri"},
 {id:"fbkStack", title:"后备上游 · 耗时构成", type:"stack", src:"fbk"},
 {id:"dns", title:"DNS 解析耗时", type:"line", field:"dns"},
 {id:"tls", title:"TLS/QUIC 握手耗时", type:"line", field:"tls"},
 {id:"xfer", title:"传输耗时（首字节之后）", type:"line", field:"xfer"},
];
const cvMap={};
function buildDOM(){
  const box=document.getElementById("charts");
  CHARTS.forEach(c=>{
    if(c.src==="fbk"&&!hasFbk)return;
    const card=document.createElement("div");card.className="card";
    const ct=document.createElement("div");ct.className="ct";
    ct.innerHTML=c.title+'<span class="hint" id="hint-'+c.id+'"></span>';
    card.appendChild(ct);
    const lg=document.createElement("div");lg.className="legend";
    if(c.type==="line"){
      lg.innerHTML='<span class="lg"><span class="sw" style="background:'+C1+'"></span>'+esc(names.pri)+'</span>'+
        (hasFbk?'<span class="lg"><span class="sw" style="background:'+C2+'"></span>'+esc(names.fbk)+'</span>':"")+
        '<span class="lg">○ 空心点 = 探测</span><span class="lg">● 实心点 = 真实请求</span>';
    }else{
      lg.innerHTML=PH.map(p=>'<span class="lg"><span class="sq" style="background:'+p[2]+'"></span>'+p[1]+'</span>').join("");
    }
    card.appendChild(lg);
    const cv=document.createElement("canvas");cv.height=230;cv.id="cv-"+c.id;
    card.appendChild(cv);
    box.appendChild(card);
    cvMap[c.id]=cv;
    attachGestures(cv);
  });
}
function esc(s){const d=document.createElement("div");d.textContent=s;return d.innerHTML;}

// ---------- 视窗与手势 ----------
function fullRange(){
  let t0=Infinity,t1=0;
  [D.pri,D.fbk].forEach(s=>s.forEach(p=>{if(p.t<t0)t0=p.t;if(p.t>t1)t1=p.t;}));
  if(t1===0){const n=Math.floor(Date.now()/1000);return[n-winW,n];}
  if(t1-t0<10)t0=t1-10;
  return[t0,t1];
}
function clampView(){
  const[f0,f1]=fullRange();
  const span=f1-f0;
  let w=view.t1-view.t0;
  if(w<10)w=10;
  if(w>span+60)w=span+60;
  view.t1=Math.min(view.t1,f1+30);
  view.t0=view.t1-w;
  if(view.t0<f0-30){view.t0=f0-30;view.t1=view.t0+w;}
  follow=view.t1>=f1-2;
}
function zoomAt(factor,anchorT){
  follow=false;
  const w=(view.t1-view.t0)*factor;
  const r=(anchorT-view.t0)/(view.t1-view.t0);
  view.t0=anchorT-w*r;view.t1=view.t0+w;
  clampView();drawAll();
}
function panBy(dt){follow=false;view.t0+=dt;view.t1+=dt;clampView();drawAll();}
function zoomBtn(f){zoomAt(f,(view.t0+view.t1)/2);}
function resetView(){follow=true;const[f0,f1]=fullRange();view={t0:Math.max(f0,f1-winW),t1:f1};clampView();drawAll();}
function xToT(cv,x){const w=cv.clientWidth-PADL-PADR;return view.t0+(x-PADL)/Math.max(1,w)*(view.t1-view.t0);}
function attachGestures(cv){
  cv.addEventListener("wheel",e=>{
    e.preventDefault();
    zoomAt(e.deltaY>0?1.25:0.8,xToT(cv,e.offsetX));
  },{passive:false});
  let drag=null;
  cv.addEventListener("mousedown",e=>{drag={x:e.clientX,t0:view.t0,t1:view.t1,moved:false};});
  window.addEventListener("mousemove",e=>{
    if(!drag)return;
    const dx=e.clientX-drag.x;
    if(Math.abs(dx)>3)drag.moved=true;
    if(drag.moved){
      const dt=-dx/Math.max(1,cv.clientWidth-PADL-PADR)*(drag.t1-drag.t0);
      view.t0=drag.t0+dt;view.t1=drag.t1+dt;follow=false;clampView();drawAll();
    }
  });
  window.addEventListener("mouseup",()=>{drag=null;});
  cv.addEventListener("dblclick",()=>resetView());
  // 触屏：单指平移，双指捏合缩放
  let touches={};
  cv.addEventListener("touchstart",e=>{
    e.preventDefault();
    for(const t of e.changedTouches)touches[t.identifier]={x:t.clientX,y:t.clientY};
    if(e.touches.length===1){
      const t=e.touches[0];drag={x:t.clientX,t0:view.t0,t1:view.t1,moved:false};
    }else if(e.touches.length===2){
      drag=null;
      const[a,b]=e.touches;
      pinch={d0:Math.abs(a.clientX-b.clientX),cx:(a.clientX+b.clientX)/2,t0:view.t0,t1:view.t1,rect:cv.getBoundingClientRect()};
    }
  },{passive:false});
  let pinch=null;
  cv.addEventListener("touchmove",e=>{
    e.preventDefault();
    if(e.touches.length===1&&drag){
      const t=e.touches[0],dx=t.clientX-drag.x;
      if(Math.abs(dx)>3)drag.moved=true;
      if(drag.moved){
        const dt=-dx/Math.max(1,cv.clientWidth-PADL-PADR)*(drag.t1-drag.t0);
        view.t0=drag.t0+dt;view.t1=drag.t1+dt;follow=false;clampView();drawAll();
      }
    }else if(e.touches.length===2&&pinch){
      const[a,b]=e.touches;
      const d=Math.abs(a.clientX-b.clientX);
      if(pinch.d0>0&&d>0){
        const w=(pinch.t1-pinch.t0)*pinch.d0/d;
        const anchor=xToT(cv,pinch.cx-pinch.rect.left);
        const r=(anchor-pinch.t0)/(pinch.t1-pinch.t0);
        view.t0=anchor-w*r;view.t1=view.t0+w;follow=false;clampView();drawAll();
      }
    }
  },{passive:false});
  cv.addEventListener("touchend",e=>{
    for(const t of e.changedTouches)delete touches[t.identifier];
    if(e.touches.length<2)pinch=null;
    if(e.touches.length===0)drag=null;
  });
  // 悬停十字线 + 气泡
  cv.addEventListener("mousemove",e=>{if(!drag||!drag.moved){hover(cv,e.offsetX,e.offsetY);}});
  cv.addEventListener("mouseleave",()=>{hoverCv=null;drawAll();});
  cv.addEventListener("click",e=>{
    if(drag&&drag.moved)return;
    // 单击某图表：把它的时间游标同步到全部图表（查看同一时刻各阶段）
    hover(cv,e.offsetX,e.offsetY,true);
  });
}
let hoverCv=null,hoverT=0;
function hover(cv,x,y,stick){
  hoverCv=cv.id;hoverT=xToT(cv,x);drawAll();
}

// ---------- 渲染 ----------
function niceStep(span,target){
  const steps=[2,5,10,15,30,60,120,300,600,900,1800,3600,7200];
  for(const s of steps)if(span/s<=target)return s;
  return 14400;
}
function fmtT(t){const d=new Date(t*1000);const p=n=>(n<10?"0":"")+n;return p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds());}
function drawChart(cfg){
  const cv=cvMap[cfg.id];if(!cv)return;
  const dpr=window.devicePixelRatio||1;
  const W=cv.clientWidth,H=cv.id==="cv-total"?230:(window.innerWidth<720?200:230);
  if(cv.height!==H)cv.height=H;
  if(cv.width!==W*dpr||cv.height!==H*dpr){cv.width=W*dpr;cv.height=H*dpr;}
  const g=cv.getContext("2d");
  g.setTransform(dpr,0,0,dpr,0,0);
  g.clearRect(0,0,W,H);
  const cw=W-PADL-PADR,ch=H-PADT-PADB;
  const X=t=>PADL+(t-view.t0)/(view.t1-view.t0)*cw;

  // 可视数据 + Y 范围
  let series;
  if(cfg.type==="stack"){series=[[cfg.src,D[cfg.src]]];}
  else{series=[["pri",D.pri]];if(hasFbk)series.push(["fbk",D.fbk]);}
  let yMax=10;
  const vis=series.map(([k,arr])=>arr.filter(p=>p.t>=view.t0&&p.t<=view.t1));
  vis.forEach((arr,i)=>{
    arr.forEach(p=>{
      const v=cfg.type==="stack"?p.ms:valOf(p,cfg.field);
      if(v>yMax)yMax=v;
    });
  });
  yMax=Math.ceil(yMax*1.15/5)*5;
  const Y=v=>PADT+ch-(v/yMax)*ch;

  // 网格与轴
  g.strokeStyle="#eef0f5";g.fillStyle="#9aa0ae";g.lineWidth=1;
  g.font="10.5px system-ui";g.textAlign="right";
  for(let i=0;i<=4;i++){
    const v=yMax*i/4,y=Y(v);
    g.beginPath();g.moveTo(PADL,y);g.lineTo(W-PADR,y);g.stroke();
    g.fillText(Math.round(v)+" ms",PADL-6,y+3);
  }
  const step=niceStep(view.t1-view.t0,6);
  g.textAlign="center";
  const tStart=Math.ceil(view.t0/step)*step;
  for(let t=tStart;t<=view.t1;t+=step){
    const x=X(t);
    if(x<PADL+4||x>W-PADR-4)continue;
    g.strokeStyle="#f4f5f9";g.beginPath();g.moveTo(x,PADT);g.lineTo(x,PADT+ch);g.stroke();
    g.fillStyle="#9aa0ae";g.fillText(fmtT(t),x,PADT+ch+14);
  }

  if(cfg.type==="stack"){
    const arr=vis[0]||[];
    // 自下而上堆叠分层面积
    const acc=arr.map(()=>0);
    PH.forEach((ph,pi)=>{
      g.beginPath();
      let started=false;
      arr.forEach((p,i)=>{
        acc[i]+=phases(p)[pi];
        const x=X(p.t),y=Y(acc[i]);
        if(!started){g.moveTo(x,y);started=true;}else g.lineTo(x,y);
      });
      for(let i=arr.length-1;i>=0;i--){ // 下沿 = 上一层顶
        const base=acc[i]-phases(arr[i])[pi];
        g.lineTo(X(arr[i].t),Y(base));
      }
      g.closePath();
      g.fillStyle=ph[2]+"cc";g.fill();
    });
    if(arr.length){
      g.strokeStyle="#546e7a";g.lineWidth=1.2;g.beginPath();
      arr.forEach((p,i)=>{const x=X(p.t),y=Y(p.ms);i?g.lineTo(x,y):g.moveTo(x,y);});
      g.stroke();
    }
    document.getElementById("hint-"+cfg.id).textContent=arr.length?("可视 "+arr.length+" 点 · 顶线=总耗时"):"暂无数据";
  }else{
    const colors={pri:C1,fbk:C2};
    vis.forEach((arr,i)=>{
      const k=series[i][0],col=colors[k];
      if(!arr.length)return;
      // 面积渐变
      const grad=g.createLinearGradient(0,PADT,0,PADT+ch);
      grad.addColorStop(0,col+"33");grad.addColorStop(1,col+"05");
      g.beginPath();
      arr.forEach((p,j)=>{const x=X(p.t),y=Y(valOf(p,cfg.field));j?g.lineTo(x,y):g.moveTo(x,y);});
      g.lineTo(X(arr[arr.length-1].t),PADT+ch);g.lineTo(X(arr[0].t),PADT+ch);g.closePath();
      g.fillStyle=grad;g.fill();
      // 平滑折线
      g.strokeStyle=col;g.lineWidth=2;g.beginPath();
      arr.forEach((p,j)=>{
        const x=X(p.t),y=Y(valOf(p,cfg.field));
        if(!j)g.moveTo(x,y);
        else{
          const q=arr[j-1],qx=X(q.t),qy=Y(valOf(q,cfg.field)),mx=(qx+x)/2;
          g.bezierCurveTo(mx,qy,mx,y,x,y);
        }
      });
      g.stroke();
      // 数据点：空心=探测，实心=真实
      arr.forEach(p=>{
        const x=X(p.t),y=Y(valOf(p,cfg.field));
        g.beginPath();g.arc(x,y,3,0,7);
        if(p.p){g.strokeStyle=col;g.lineWidth=1.5;g.stroke();}
        else{g.fillStyle=col;g.fill();}
      });
    });
    const n=vis.reduce((a,b)=>a+b.length,0);
    document.getElementById("hint-"+cfg.id).textContent=n?("可视 "+n+" 点"):"暂无数据";
  }

  // 十字线游标（悬停/点击同步到所有图表）
  if(hoverCv&&hoverT>=view.t0&&hoverT<=view.t1){
    const x=X(hoverT);
    g.strokeStyle="#5f6368";g.setLineDash([4,3]);g.lineWidth=1;
    g.beginPath();g.moveTo(x,PADT);g.lineTo(x,PADT+ch);g.stroke();g.setLineDash([]);
    if(hoverCv===cv.id){
      // 气泡：最近点详情
      let best=null,bd=1e18,bk="";
      series.forEach(([k,arr],i)=>vis[i].forEach(p=>{
        const d=Math.abs(p.t-hoverT);if(d<bd){bd=d;best=p;bk=k;}
      }));
      if(best){
        const col=bk==="fbk"?C2:C1;
        const ph=phases(best);
        const lines=[(bk==="fbk"?names.fbk:names.pri)+" · "+fmtT(best.t),
          "总耗时 "+best.ms+" ms"+(best.p?"（探测）":"")+(best.r?"（连接复用）":"")];
        if(cfg.type==="stack"||best.dns||best.tcp||best.tls)
          lines.push("DNS "+ph[0]+" / TCP "+ph[1]+" / TLS "+ph[2]+" / 等待 "+ph[3]+" / 传输 "+ph[4]+" ms");
        else lines.push("本阶段 "+valOf(best,cfg.field)+" ms");
        g.font="11px system-ui";
        const tw=Math.max(...lines.map(l=>g.measureText(l).width))+16;
        const th=lines.length*16+10;
        let bx=x+10;if(bx+tw>W-PADR)bx=x-tw-10;
        let by=PADT+6;
        g.fillStyle="rgba(255,255,255,.96)";g.strokeStyle=col;
        roundRect(g,bx,by,tw,th,6);g.fill();g.stroke();
        g.fillStyle="#1a1a2e";g.textAlign="left";
        lines.forEach((l,i)=>g.fillText(l,bx+8,by+18+i*16));
      }
    }
  }
}
function roundRect(g,x,y,w,h,r){
  g.beginPath();
  g.moveTo(x+r,y);g.arcTo(x+w,y,x+w,y+h,r);g.arcTo(x+w,y+h,x,y+h,r);
  g.arcTo(x,y+h,x,y,r);g.arcTo(x,y,x+w,y,r);g.closePath();
}
function drawAll(){CHARTS.forEach(drawChart);}

// ---------- 汇总卡片 ----------
function stats(arr,field){
  const vs=arr.map(p=>field==="ms"?p.ms:valOf(p,field));
  if(!vs.length)return null;
  const sum=vs.reduce((a,b)=>a+b,0);
  const reuse=arr.filter(p=>p.r).length;
  return{n:vs.length,last:vs[vs.length-1],avg:Math.round(sum/vs.length),
    min:Math.min(...vs),max:Math.max(...vs),reuse:Math.round(reuse/arr.length*100)};
}
function renderSum(){
  const rows=(arr,col,name)=>{
    const st=stats(arr,"ms");
    if(!st)return '<div class="sumc"><h3><span class="sw" style="background:'+col+'"></span>'+esc(name)+'</h3><table><tr><td>暂无数据</td><td>-</td></tr></table></div>';
    const dnsSt=stats(arr.filter(p=>p.dns),"dns"),tlsSt=stats(arr.filter(p=>p.tls),"tls");
    return '<div class="sumc"><h3><span class="sw" style="background:'+col+'"></span>'+esc(name)+'</h3><table>'+
      "<tr><td>最新 / 均值</td><td>"+st.last+" / "+st.avg+" ms</td></tr>"+
      "<tr><td>最低 / 最高</td><td>"+st.min+" / "+st.max+" ms</td></tr>"+
      "<tr><td>DNS 均值 / TLS 均值</td><td>"+(dnsSt?dnsSt.avg:"-")+" / "+(tlsSt?tlsSt.avg:"-")+" ms</td></tr>"+
      "<tr><td>连接复用率</td><td>"+st.reuse+"%</td></tr>"+
      "<tr><td>数据点</td><td>"+st.n+"</td></tr></table></div>";
  };
  document.getElementById("sum").innerHTML=rows(D.pri,C1,names.pri)+(hasFbk?rows(D.fbk,C2,names.fbk):"");
}

// ---------- 数据轮询 ----------
let built=false;
async function pull(){
  try{
    const r=await fetch("/latency.json",{cache:"no-store"});
    const j=await r.json();
    names.pri="主上游 "+(j.primaryName||"");
    names.fbk="后备上游 "+(j.fallbackName||"");
    hasFbk=!!j.fallbackName;
    D.pri=j.primary||[];D.fbk=j.fallback||[];
    if(!built){built=true;buildDOM();resetView();}
    else if(follow){const[f0,f1]=fullRange();view={t0:Math.max(f0,f1-winW),t1:f1};clampView();}
    renderSum();drawAll();
  }catch(e){}
}
window.addEventListener("resize",()=>drawAll());
pull();setInterval(pull,2000);
</script></body></html>`)
}
