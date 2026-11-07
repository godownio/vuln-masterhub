/* The taxonomy is the tree. Only a card directly owned by a directory is a leaf. */
(() => {
  'use strict';
  const app = document.getElementById('knowledge-tree-app');
  if (!app) return;
  const $ = id => document.getElementById(id), NS = 'http://www.w3.org/2000/svg';
  const viewport = $('kt-viewport'), world = $('kt-world'), detail = $('kt-detail');
  const scene=document.createElement('div');scene.id='kt-scene';viewport.insertBefore(scene,$('kt-svg'));scene.append($('kt-svg'));
  const raster=document.createElement('canvas');raster.id='kt-raster';raster.setAttribute('aria-hidden','true');scene.prepend(raster);
  let rasterReady=false,rasterVersion=0,interactionTimer,hudTime=0;
  const limits = new Map(), dirs = new Map(), cardsByPath = new Map(), cache = new Map();
  const pointers = new Map();
  const expanded = new Set(['']), INITIAL_BUDGET = 400;
  const gardenFrame=document.querySelector('.kt-cat-garden');gardenFrame.hidden=true;scene.prepend(gardenFrame);
  gardenFrame.replaceChildren();
  const sceneAssets=window.KnowledgeSceneAssets||{cats:[],flora:[]};
  for(const [i,asset] of sceneAssets.flora.entries()){const image=document.createElement('img');image.className='kt-floor-cluster'+(i%4===0?' is-breezy':'');image.src=new URL(asset.file,document.baseURI);image.dataset.asset=asset.key;image.loading='lazy';image.decoding='async';image.alt='';image.setAttribute('aria-hidden','true');gardenFrame.append(image);}
  for(const [i,asset] of sceneAssets.cats.entries()){
    const cat=document.createElement('button');cat.type='button';cat.className='kt-cat kt-cat-unique';cat.dataset.cat=asset.name;cat.dataset.asset=asset.key;cat.setAttribute('aria-label',`点击猫${asset.name}，领取一片知识叶子`);
    const image=document.createElement('img');image.src=new URL(asset.file,document.baseURI);image.alt='手绘猫'+asset.name;image.loading=i===0?'eager':'lazy';image.decoding='async';
    const label=document.createElement('span');label.textContent=asset.name;cat.append(image,label);gardenFrame.append(cat);
  }
  const revealed = new Set(), bookmarks = new Set();
  let toastTimer;
  const randomFor = key => {let h=2166136261;for(const ch of key){h^=ch.charCodeAt(0);h=Math.imul(h,16777619);}return (h>>>0)/4294967295;};
  let data, root, entities = [], bounds, mini, selected = '', scope = '', query = '', requestId = 0;
  let tx = 0, ty = 0, scale = 1, dragMoved = false, pinch = null, resizeTimer, framePending = false;
  let woodEdges=[];
  let miniVersion=0;
  const normalize = s => String(s || '').normalize('NFKC').toLocaleLowerCase().replace(/[\s_\-/]+/g, '');
  const under = (path, parent) => !parent || path === parent || path.startsWith(parent + '/');
  const textEl = (tag, text, cls) => { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; return n; };
  const svg = (tag, attrs = {}, parent) => { const n = document.createElementNS(NS, tag); for (const [k,v] of Object.entries(attrs)) n.setAttribute(k,v); if(parent) parent.append(n); return n; };
  const matches = item => !query || item.search.includes(normalize(query));
  const urlFor = path => new URL(path.replace(/^\//,''), document.baseURI).href;
  function button(label, action, cls) {const b=textEl('button',label,cls);b.type='button';b.addEventListener('click',action);return b;}
  function setup() {
    for (const card of data.cards) {
      card.search=normalize([card.title,card.path,card.breadcrumb,...(card.tags||[]),...(card.aliases||[]),...(card.cve||[])].join(' '));
      if(!cardsByPath.has(card.path)) cardsByPath.set(card.path,[]);
      cardsByPath.get(card.path).push(card);
    }
    function directory(node,parent,depth) {
      const n={...node,kind:'directory',parent,depth,key:node.path,search:normalize(node.path+' '+node.title+' '+node.description),cards:cardsByPath.get(node.path)||[]};
      dirs.set(n.path,n); n.children=(node.children||[]).map(c=>directory(c,n,depth+1));return n;
    }
    root={kind:'directory',title:'安全知识库',path:'',key:'',depth:0,count:data.cards.length,cards:[],search:normalize('安全知识库'),description:'沿枝干浏览全部知识分类，点击叶子读取场景。'};
    dirs.set('',root);root.children=data.tree.map(n=>directory(n,root,1));
    function minimumCost(n){if(expanded.has(n.path))return 1+n.children.reduce((s,c)=>s+minimumCost(c),0)+Math.min(3,n.cards.length)+(n.cards.length>3?1:0);if(n.cards.length)return 2;const child=n.children.find(c=>c.count>0);return 1+(child?minimumCost(child):0);}
    const queue=[...root.children];while(queue.length){const n=queue.shift();expanded.add(n.path);if(minimumCost(root)<=INITIAL_BUDGET)queue.push(...n.children);else expanded.delete(n.path);}
    rebuild(); renderGlobalDirectory(); openDirectory(root,false); homeView(); renderBookmarks(); $('kt-loading').hidden=true;
    $('kt-stats').textContent=`${dirs.size-1} 个目录 · ${data.cards.length.toLocaleString()} 张场景卡片`;
    app.dataset.ready='true';
  }
  function rebuild() {
    entities=[];
    const searchCards=query?data.cards.filter(c=>under(c.path,scope)&&matches(c)).slice(0,50):[];
    const searchPaths=new Set(['']);
    if(query)for(const path of [...searchCards.map(c=>c.path),...Array.from(dirs.values()).filter(n=>under(n.path,scope)&&matches(n)).map(n=>n.path)]){const parts=path.split('/');for(let i=1;i<=parts.length;i++)searchPaths.add(parts.slice(0,i).join('/'));}
    function build(n) {
      let shown=n.cards.slice(0,limits.get(n.path) ?? 3);
      for(const card of n.cards)if(revealed.has(card.url)&&!shown.includes(card))shown.push(card);
      // Search surfaces matching leaves even when they are outside the initial three.
      if(query) shown=searchCards.filter(c=>c.path===n.path);
      n.collapsed=!query&&!expanded.has(n.path)&&(n.cards.length>0||n.children.length>0);
      if(n.collapsed){
        if(n.cards.length){const c=n.cards.find(card=>revealed.has(card.url))||n.cards[0];n.items=[{kind:'card',card:c,title:c.title,path:c.path,key:c.url,parent:n,depth:n.depth+1,weight:1}];}
        else{const child=n.children.find(c=>c.count>0);n.items=child?[child]:[];if(child)build(child);}
        n.weight=Math.max(1,n.items.reduce((s,c)=>s+c.weight,0));return;
      }
      const leaves=shown.map(c=>({kind:'card',card:c,title:c.title,path:c.path,key:c.url,parent:n,depth:n.depth+1,weight:1}));
      const children=query?n.children.filter(c=>searchPaths.has(c.path)):n.children;
      n.items=[...children,...leaves];
      for(const child of children) build(child);
      if(!query && shown.length<n.cards.length) n.items.push({kind:'more',title:`＋ ${n.cards.length-shown.length}`,path:n.path,key:'more:'+n.path,parent:n,depth:n.depth+1,weight:.8});
      n.weight=Math.max(1,n.items.reduce((s,c)=>s+c.weight,0));
    }
    build(root);
    function collect(n){entities.push(n);if(n.kind==='directory')for(const c of n.items)collect(c);}
    collect(root);
    layout();
    bounds=getBounds(entities);
    const sceneWidth=bounds.right-bounds.x,sceneHeight=bounds.bottom-bounds.y;
    scene.style.width=sceneWidth+'px';scene.style.height=sceneHeight+'px';
    $('kt-svg').setAttribute('viewBox',`${bounds.x} ${bounds.y} ${sceneWidth} ${sceneHeight}`);
    placeGarden();gardenFrame.hidden=false;
    draw();
    $('kt-visible-count').textContent=`${entities.length} 个节点 · ${entities.filter(n=>n.kind==='directory').length-1}/${dirs.size-1} 个目录 · ${entities.filter(n=>n.kind==='card').length} 片叶子`;
  }
  function layout(){
    woodEdges=[];
    // Invisible binary fork points let sibling subtrees use disjoint rectangles.
    // Only real directories and cards become clickable nodes.
    function fork(items,key){
      if(items.length===1)return items[0];
      const total=items.reduce((sum,n)=>sum+n.weight,0);let sum=0,cut=1;
      for(let i=0;i<items.length-1;i++){sum+=items[i].weight;cut=i+1;if(sum>=total/2)break;}
      const n={kind:'fork',key:'@fork:'+key,w:0,h:0,weight:total};
      n.routes=[fork(items.slice(0,cut),key+'a'),fork(items.slice(cut),key+'b')];return n;
    }
    function prepare(n){
      n.w=n.kind==='card'?160:n.kind==='more'?64:Math.max(96,Math.min(188,n.title.length*15+40));
      n.h=n===root?38:36;n.gap=3+3*randomFor(n.key+'spacing');
      if(n.kind==='directory'){
        for(const c of n.items)prepare(c);
        n.routes=n.items.length>2?[fork(n.items,n.key)]:n.items;
      }else n.routes=[];
    }
    prepare(root);
    function measure(n,target=1){
      const children=n.routes||[];for(const c of children)measure(c,target);
      if(!children.length){n.bw=n.w;n.bh=n.h;return;}
      const factor=n.gap||3+3*randomFor(n.key),isFork=n.kind==='fork',gap=isFork?24+12*randomFor(n.key+'gap'):13*factor;
      n.channel=isFork?20+8*randomFor(n.key+'channel'):45+8*factor;
      const rowW=Math.max(n.w,children.reduce((s,c)=>s+c.bw,0)+gap*(children.length-1));
      const rowH=n.h+n.channel+Math.max(...children.map(c=>c.bh));
      const colW=n.w+n.channel+Math.max(...children.map(c=>c.bw));
      const colH=Math.max(n.h,children.reduce((s,c)=>s+c.bh,0)+gap*(children.length-1));
      const score=(w,h)=>Math.max(w/target,h)/Math.min(w/target,h)+w*h/3000000;
      n.direction=score(rowW,rowH)<=score(colW,colH)?'up':'right';
      n.bw=n.direction==='up'?rowW:colW;n.bh=n.direction==='up'?rowH:colH;n.routeGap=gap;
    }
    // Evaluate several local aspect preferences against the whole tree, so
    // hundreds of nodes do not accumulate into an unnecessarily narrow strip.
    let bestTarget=1,bestScore=Infinity;
    for(const target of [.55,.7,.85,1,1.2,1.4,1.7,2,2.4]){
      measure(root,target);
      const score=Math.max(root.bw,root.bh)/Math.min(root.bw,root.bh)+root.bw*root.bh/60000000;
      if(score<bestScore){bestScore=score;bestTarget=target;}
    }
    measure(root,bestTarget);
    function place(n,x,y){
      n.x=x+n.w/2;n.y=y+n.bh-n.h/2;n.angle=0;n.radius=0;
      let cursor=n.direction==='up'?x:y+n.bh;
      for(const child of n.routes||[]){
        if(n.direction==='up'){
          place(child,cursor,y+n.bh-n.h-n.channel-child.bh);cursor+=child.bw+n.routeGap;
        }else{
          cursor-=child.bh;place(child,x+n.w+n.channel,cursor);cursor-=n.routeGap;
        }
        woodEdges.push({parent:n,child,direction:n.direction,key:child.key,weight:child.weight});
      }
    }
    place(root,0,0);
    app.dataset.spacingMin=Math.min(...entities.map(n=>n.gap)).toFixed(2);app.dataset.spacingMax=Math.max(...entities.map(n=>n.gap)).toFixed(2);
  }
  function getBounds(nodes) {
    return {x:Math.min(...nodes.map(n=>n.x-(n.w||140)/2))-25,y:Math.min(...nodes.map(n=>n.y))-35,
      right:Math.max(...nodes.map(n=>n.x+(n.w||140)/2))+100,bottom:Math.max(...nodes.map(n=>n.y))+220};
  }
  function branchPath(edge) {
    const p=edge.parent,n=edge.child;
    // Fan out inside the parent's empty corridor before entering a child's
    // rectangle. A direct cubic can cut through a neighbouring tall subtree.
    if(edge.direction==='up'){
      const lane=p.y-p.h/2-p.channel/2;
      return `M${p.x},${p.y} C${p.x},${lane} ${n.x},${lane} ${n.x},${lane} Q${n.x},${lane} ${n.x},${n.y}`;
    }
    const lane=p.x+p.w/2+p.channel/2;
    return `M${p.x},${p.y} C${lane},${p.y} ${lane},${n.y} ${lane},${n.y} Q${lane},${n.y} ${n.x},${n.y}`;
  }
  function draw() {
    world.replaceChildren();
    const branchLayer=svg('g',{'class':'kt-branch'},world), nodeLayer=svg('g',{},world);
    const chosen=entities.find(n=>n.key===selected), selectedPaths=new Set();
    for(let n=chosen;n;n=n.parent) selectedPaths.add(n.key);
    const trunk=svg('g',{transform:`translate(${root.x} ${root.y}) scale(.48)`},branchLayer);
    svg('path',{d:'M-100,135 Q-28,80 -22,10 Q-20,-35 30,-90 Q13,-25 25,20 Q35,80 100,135 Q30,108 0,115 Q-40,110 -100,135 Z',fill:'url(#kt-wood-fill)',stroke:'#776044','stroke-width':3},trunk);
    for(let i=-2;i<=2;i++) svg('path',{d:`M${i*18},112 Q${i*9},50 ${i*6+5},-40`,fill:'none',stroke:'#987d52','stroke-width':1.3,opacity:.8},trunk);
    const garden=svg('g',{transform:`translate(${root.x} ${root.y+55})`,class:'kt-garden-sketch'},branchLayer);
    for(let i=0;i<19;i++){const x=(i-9)*9,y=Math.sin(i*2.1)*5,height=12+randomFor('grass'+i)*24;svg('path',{d:`M${x},${y} q${Math.sin(i)*12},${-height*.6} ${Math.cos(i)*8},${-height} M${x},${y} q-9,-13 -16,-17`,fill:'none',stroke:i%3?'#8a9d6f':'#b3a87c','stroke-width':.9,opacity:.7},garden);}
    svg('path',{d:'M60,5 q-2,-17 2,-27 m-17,1 q18,-27 35,1 q-19,7 -35,-1 M-54,8 q3,-11 1,-19 m-14,1 q12,-20 27,0 q-12,5 -27,0',fill:'#d9be91',stroke:'#927c57','stroke-width':1,opacity:.75},garden);
    const activeWood=new Set();
    function markWood(n){for(const c of n.routes||[]){const active=markWood(c);if(active)activeWood.add(c.key);}return selectedPaths.has(n.key)||activeWood.has(n.key);}
    markWood(root);
    for(const edge of woodEdges) {
      const n=edge.child,inPath=activeWood.has(n.key)||selectedPaths.has(n.key);
      const width=n.kind==='card'||n.kind==='more'?2.2:Math.max(4,Math.min(26,Math.sqrt(edge.weight)*2.8));
      const g=svg('g',{'data-wood-key':edge.key},branchLayer);edge.element=g;const d=branchPath(edge);
      svg('path',{d,fill:'none',stroke:inPath?'#b77d32':'#746044','stroke-width':width+2,'stroke-linecap':'round'},g);
      svg('path',{d,fill:'none',stroke:inPath?'#e6bc66':'#d4b486','stroke-width':width,'stroke-linecap':'round'},g);
      if(n.kind==='directory'||n.kind==='fork'){
        svg('path',{d,fill:'none',stroke:'#8e744f','stroke-width':Math.max(.6,width*.08),'stroke-dasharray':'8 3 19 2',opacity:.7},g);
        svg('path',{d,fill:'none',stroke:'#faf0d1','stroke-width':.7,'stroke-dasharray':'2 7 1 11 4 13',opacity:.65},g);
      }
      if(n.kind!=='fork')n.edge=g;
    }
    for(const n of entities) {
      const rotation=0;
      const g=svg('g',{transform:`translate(${n.x} ${n.y}) rotate(${rotation})`,class:`kt-${n.kind==='card'?'card-leaf':n.kind}${n.key===selected?' is-selected':''}`,role:'button',tabindex:'0','aria-label':n.kind==='directory'?`目录：${n.title}，${n.count} 张卡片`:n.kind==='more'?`展开 ${n.parent.title} 的更多场景`:n.title,'data-key':n.key},nodeLayer);
      n.element=g;g.dataset.spacing=n.gap.toFixed(3);
      svg('title',{},g).textContent=n.kind==='directory'?`${n.path||'全部知识'} · 直属 ${n.cards.length} 张 / 子树 ${n.count} 张`:n.title;
      if(n.kind==='directory') {
        const w=n.w||150;
        svg('path',{d:`M${-w/2},-17 L${w/2-5},-18 L${w/2},-12 L${w/2-2},16 L${-w/2+3},18 Z`,class:'kt-sign'},g);
        svg('text',{x:0,y:6,'text-anchor':'middle'},g).textContent=n.title.length>10?n.title.slice(0,9)+'…':n.title;
        if(n.collapsed)svg('text',{x:w/2+9,y:5,class:'kt-collapse-badge'},g).textContent='⊕';
        svg('path',{d:`M${-w/2+5},-13 Q-5,-15 ${w/2-9},-13 M${-w/2+7},13 Q6,12 ${w/2-7},12`,fill:'none',stroke:'#b79c71','stroke-width':.6,'stroke-dasharray':'4 6',opacity:.7},g);
      } else if(n.kind==='card') {
        svg('path',{d:'M-79,0 Q-47,-29 4,-15 Q47,-10 80,-3 Q49,20 4,16 Q-44,28 -79,0 Z',class:'kt-leaf-shape'},g);
        svg('path',{d:'M-78,0 Q0,-2 75,-3',fill:'none',stroke:'#6c955f','stroke-width':.7,opacity:.45},g);
        for(let j=-2;j<=2;j++)svg('path',{d:`M${j*20},0 q12,-7 21,-12 M${j*20},1 q12,7 20,12`,fill:'none',stroke:'#759666','stroke-width':.55,opacity:.5},g);
        svg('text',{x:0,y:5,'text-anchor':'middle'},g).textContent=n.title.length>9?n.title.slice(0,8)+'…':n.title;
        if(bookmarks.has(n.card.url))svg('path',{d:'M59,-21 l10,1 -1,18 -5,-5 -5,5 Z',fill:'#c18b48',stroke:'#98703b','stroke-width':.8},g);
      } else {
        svg('rect',{x:-32,y:-14,width:64,height:28,rx:14},g);svg('text',{x:0,y:5,'text-anchor':'middle'},g).textContent=n.title;
      }
      const activate=()=>{if(dragMoved)return;if(n.kind==='directory')openDirectory(n,false,false);else if(n.kind==='card')openCard(n.card);else{openDirectory(n.parent,false,false);$('kt-leaf-limit')?.focus();}};
      g.addEventListener('click',activate);g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();activate();}});
      g.addEventListener('pointerenter',e=>{if(pointers.size)return;const r=viewport.getBoundingClientRect(),hint=$('kt-node-hint');hint.textContent=n.kind==='directory'?`${n.title} · ${n.count} 张场景${n.collapsed?' · 双击展开':' · 双击收拢'}`:n.kind==='more'?`设置 ${n.parent.title} 的叶子数量`:n.title;hint.style.left=Math.max(8,Math.min(r.width-260,e.clientX-r.left+18))+'px';hint.style.top=Math.max(60,Math.min(r.height-75,e.clientY-r.top+18))+'px';hint.hidden=false;});
      g.addEventListener('pointerleave',()=>{$('kt-node-hint').hidden=true;});
      if(n.kind==='directory'&&n!==root)g.addEventListener('dblclick',e=>{e.preventDefault();toggleDirectory(n);});
    }
    drawMini(); updateMatches(); transform();snapshot();
  }
  function snapshot(){
    rasterReady=false;const version=++rasterVersion,clone=$('kt-svg').cloneNode(true),style=document.createElementNS(NS,'style');
    const rules=[];for(const sheet of document.styleSheets){try{for(const rule of sheet.cssRules)if(rule.selectorText?.includes('.kt-'))rules.push(rule.cssText);}catch{}}
    style.textContent=rules.join('\n');clone.prepend(style);
    const w=bounds.right-bounds.x,h=bounds.bottom-bounds.y,dpr=Math.min(2,window.devicePixelRatio||1.5,Math.sqrt(4500000/(w*h)));
    clone.setAttribute('width',w);clone.setAttribute('height',h);
    const objectURL=URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(clone)],{type:'image/svg+xml;charset=utf-8'})),image=new Image();
    image.onload=()=>{if(version===rasterVersion){raster.width=Math.ceil(w*dpr);raster.height=Math.ceil(h*dpr);const ctx=raster.getContext('2d',{alpha:true});ctx.setTransform(dpr,0,0,dpr,0,0);ctx.drawImage(image,0,0,w,h);rasterReady=true;}URL.revokeObjectURL(objectURL);};image.onerror=()=>URL.revokeObjectURL(objectURL);image.src=objectURL;
  }
  function interaction(){$('kt-node-hint').hidden=true;if(rasterReady)scene.classList.add('kt-interacting');clearTimeout(interactionTimer);interactionTimer=setTimeout(()=>{scene.classList.remove('kt-interacting');hudTime=0;transform();},160);}
  function transform() {
    if(framePending)return;framePending=true;requestAnimationFrame(()=>{framePending=false;paintTransform();});
  }
  function paintTransform() {
    scene.style.transform=`translate3d(${tx+bounds.x*scale}px,${ty+bounds.y*scale}px,0) scale(${scale})`;
    if(performance.now()-hudTime<65)return;hudTime=performance.now();
    $('kt-zoom-label').textContent=Math.round(scale*100)+'%';
    if(mini) {const r=$('kt-mini-view');r.setAttribute('x',(-tx/scale-mini.x)*mini.s+mini.ox);r.setAttribute('y',(-ty/scale-mini.y)*mini.s+mini.oy);r.setAttribute('width',viewport.clientWidth/scale*mini.s);r.setAttribute('height',viewport.clientHeight/scale*mini.s);}
  }
  function fit(nodes) {
    if(!nodes.length)return;
    const b=getBounds(nodes),w=viewport.clientWidth,h=viewport.clientHeight;
    scale=Math.min(1.3,(w-45)/(b.right-b.x),(h-85)/(b.bottom-b.y));scale=Math.max(.006,scale);
    tx=w/2-(b.x+b.right)/2*scale;ty=h/2+10-(b.y+b.bottom)/2*scale;transform();
  }
  function homeView(){scale=Math.min(.9,Math.max(.72,viewport.clientHeight/1100));tx=Math.max(105,viewport.clientWidth*.12)-root.x*scale;ty=viewport.clientHeight-110-root.y*scale;hudTime=0;transform();}
  function zoomAt(factor,x=viewport.clientWidth/2,y=viewport.clientHeight/2) {
    interaction();
    const next=Math.max(.006,Math.min(4,scale*factor));tx=x-(x-tx)*next/scale;ty=y-(y-ty)*next/scale;scale=next;transform();
  }
  function focusNode(n) {const current=entities.find(x=>x.key===n.key);if(current)fit(entities.filter(x=>x===current||(x.kind==='directory'?under(x.path,current.path):under(x.parent.path,current.path))));}
  function drawMini() {
    const version=++miniVersion,g=$('kt-mini-world');g.replaceChildren();const b=bounds,s=Math.min(172/(b.right-b.x),97/(b.bottom-b.y));mini={...b,s,ox:4,oy:4};
    const paths=svg('g',{transform:`translate(${4-b.x*s} ${4-b.y*s}) scale(${s})`},g);
    for(const edge of woodEdges)svg('path',{d:branchPath(edge),fill:'none',stroke:edge.child.kind==='card'?'#769364':'#a58b61','stroke-width':1/s,'stroke-linecap':'round'},paths);
    // Cache the static mini-map separately: moving its viewport rectangle must
    // not repaint hundreds of branch paths on every HUD update.
    const picture=svg('svg',{xmlns:NS,viewBox:'0 0 180 105',width:180,height:105});picture.append(g.cloneNode(true));
    const url=URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(picture)],{type:'image/svg+xml'})),image=new Image();
    image.onload=()=>{if(version===miniVersion){const canvas=document.createElement('canvas');canvas.width=360;canvas.height=210;const ctx=canvas.getContext('2d');ctx.scale(2,2);ctx.drawImage(image,0,0,180,105);g.replaceChildren();svg('image',{href:canvas.toDataURL('image/png'),width:180,height:105},g);}URL.revokeObjectURL(url);};image.onerror=()=>URL.revokeObjectURL(url);image.src=url;
  }
  function syncScope() {$('kt-scope-label').textContent='范围：'+(dirs.get(scope)?.title||'全部知识');$('kt-reset-scope').hidden=!scope;for(const item of $('kt-global-directory').querySelectorAll('[data-path]'))item.classList.toggle('is-current',item.dataset.path===scope);}
  function renderGlobalDirectory(){
    const nav=$('kt-global-directory');nav.replaceChildren();
    for(const n of dirs.values()){
      const control=button('',()=>{openDirectory(n,false,false);focusNode(n);},'kt-global-directory-row');control.dataset.path=n.path;control.style.paddingLeft=(10+Math.max(0,n.depth-1)*10)+'px';control.title=n.path||'全部知识';
      control.append(textEl('span',n===root?'全部知识':n.title),textEl('small',String(n.count)));
      control.addEventListener('dblclick',()=>{if(n===root){homeView();return;}if(!entities.includes(n)){for(let p=n.parent;p;p=p.parent)expanded.add(p.path);expanded.add(n.path);rebuild();openDirectory(n,false,false);focusNode(n);}else{toggleDirectory(n);focusNode(n);}});
      nav.append(control);
    }
  }
  function select(key){
    selected=key;const active=new Set();
    function visit(n){let hit=n.key===key;for(const c of n.routes||[]){if(visit(c)){active.add(c.key);hit=true;}}return hit;}
    visit(root);for(const n of entities)n.element.classList.toggle('is-selected',n.key===key);
    for(const edge of woodEdges){const strokes=edge.element.querySelectorAll('path');strokes[0]?.setAttribute('stroke',active.has(edge.key)?'#bd8031':'#746044');strokes[1]?.setAttribute('stroke',active.has(edge.key)?'#e6bc66':'#d4b486');}snapshot();
  }
  function openDirectory(n,focus=false,expand=false) {
    if(n.collapsed&&expand){const sx=tx+n.x*scale,sy=ty+n.y*scale;expanded.add(n.path);rebuild();tx=sx-n.x*scale;ty=sy-n.y*scale;transform();}scope=n.path;syncScope();select(n.key); if(query)search();
    detail.replaceChildren(textEl('h2',n.title),textEl('div',`${n.path||'知识库根目录'} · ${n.children.length} 个子目录 · ${n.cards.length} 张直属场景 · 子树 ${n.count} 张`,'kt-detail-meta'),textEl('p',n.description));
    detail.append(button('聚焦这一枝',()=>focusNode(n),'kt-focus-button'));
    if(n!==root){const control=button(n.collapsed?'双击展开这一枝':'双击收拢这一枝',()=>{},'kt-focus-button kt-collapse-action');control.addEventListener('dblclick',()=>toggleDirectory(n));control.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();toggleDirectory(n);}});detail.append(control);}
    if(n.children.length){detail.append(textEl('h3','子目录'));const list=textEl('div',null,'kt-children-list');for(const c of n.children){const control=button(`${c.title} · ${c.count}`,()=>{openDirectory(c,false,false);focusNode(c);});control.addEventListener('dblclick',()=>toggleDirectory(c));list.append(control);}detail.append(list);}
    if(n.cards.length){
      detail.append(textEl('h3','直属场景叶子'));
      const form=textEl('form',null,'kt-count-form'),label=textEl('label','显示数量');label.htmlFor='kt-leaf-limit';
      const input=textEl('input');input.id='kt-leaf-limit';input.type='number';input.min='1';input.max=String(n.cards.length);input.value=String(Math.min(n.cards.length,limits.get(n.path)??3));
      const submit=textEl('button','应用数量');submit.type='submit';form.append(label,input,submit,button('全部',()=>{expanded.add(n.path);limits.set(n.path,n.cards.length);rebuild();openDirectory(n);focusNode(n);}));
      form.addEventListener('submit',e=>{e.preventDefault();expanded.add(n.path);limits.set(n.path,Math.max(1,Math.min(n.cards.length,Math.floor(Number(input.value)||3))));rebuild();openDirectory(n);focusNode(n);});detail.append(form);
      const list=textEl('div',null,'kt-card-list');for(const c of n.cards.slice(0,limits.get(n.path)??3))list.append(button(c.title,()=>openCard(c)));detail.append(list);
    }
    if(focus)focusNode(n);
  }
  async function openCard(card) {
    const ticket=++requestId;select(card.url);
    const reader=$('kt-card-reader'),wasHidden=reader.hidden;if(wasHidden)reader.classList.remove('is-expanded');reader.hidden=false;
    $('kt-reader-title').textContent=card.title;$('kt-reader-meta').textContent=`${card.breadcrumb} · ${card.status==='verified'?'已核对':card.status==='deprecated'?'已废弃':'草稿 / 未核对'} · ${card.updated||''}`;
    $('kt-reader-actions').replaceChildren(button(bookmarks.has(card.url)?'★ 已放入叶签':'☆ 收藏这片叶子',async e=>{const control=e.currentTarget;control.disabled=true;const saved=!bookmarks.has(card.url);try{if(await saveLeaf(card,saved))control.textContent=saved?'★ 已放入叶签':'☆ 收藏这片叶子';}finally{control.disabled=false;}},'kt-focus-button kt-bookmark-action'));
    const content=$('kt-reader-body');content.textContent='正在加载知识详情…';content.classList.add('kt-article');$('kt-reader-scroll').scrollTop=0;
    if(wasHidden||!reader.classList.contains('is-expanded'))resizeReader(true);
    try {
      const url=urlFor(card.url);
      if(!cache.has(url)) {
        const response=await fetch(url);if(!response.ok)throw Error('HTTP '+response.status);
        const parsed=new DOMParser().parseFromString(await response.text(),'text/html'),body=parsed.querySelector('article main .content')||parsed.querySelector('article main');
        if(!body)throw Error('正文不可用');
        body.querySelectorAll('script,iframe,object,embed,style,form,.heading-anchor,.hextra-heading-anchor').forEach(el=>el.remove());
        for(const el of body.querySelectorAll('*'))for(const attr of Array.from(el.attributes)){if(attr.name.startsWith('on')||attr.name==='srcdoc')el.removeAttribute(attr.name);}
        for(const el of body.querySelectorAll('[href],[src]'))for(const attr of ['href','src'])if(el.hasAttribute(attr)){const u=new URL(el.getAttribute(attr),url);if(!['http:','https:'].includes(u.protocol))el.removeAttribute(attr);else el.setAttribute(attr,u.href);}
        cache.set(url,body.innerHTML);
      }
      if(ticket!==requestId)return;content.innerHTML=cache.get(url);
      const link=textEl('a','打开完整页面 ↗');link.href=url;link.target='_blank';link.rel='noopener';content.append(link);
    }catch(e){if(ticket===requestId){content.textContent='详情加载失败，请重试。';content.append(button('重新加载',()=>openCard(card)));}}
  }
  function collapseDirectory(n){
    const sx=tx+n.x*scale,sy=ty+n.y*scale;
    for(const path of [...expanded])if(under(path,n.path))expanded.delete(path);
    query='';$('kt-query').value='';$('kt-search-results').hidden=true;rebuild();
    tx=sx-n.x*scale;ty=sy-n.y*scale;openDirectory(n,false,false);hudTime=0;transform();toast('已收拢 '+n.title+'，双击目录可重新展开。');
  }
  function toggleDirectory(n){if(n.collapsed)openDirectory(n,false,true);else collapseDirectory(n);}
  function placeGarden(){
    const width=bounds.right-bounds.x,height=bounds.bottom-bounds.y;
    function location(index,cols,rows,w,h,salt){
      const cellX=index%cols,cellY=Math.floor(index/cols)%rows;let x=0,y=0;
      for(let attempt=0;attempt<18;attempt++){
        x=bounds.x+(cellX+.15+.65*randomFor(salt+index+'x'+attempt))*width/cols;
        y=bounds.y+(cellY+.15+.65*randomFor(salt+index+'y'+attempt))*height/rows;
        x=Math.max(bounds.x+20,Math.min(bounds.right-w-20,x));y=Math.max(bounds.y+20,Math.min(bounds.bottom-h-20,y));
        if(!entities.some(n=>x<n.x+n.w/2+25&&x+w>n.x-n.w/2-25&&y<n.y+n.h/2+25&&y+h>n.y-n.h/2-25))break;
      }return{x:x-bounds.x,y:y-bounds.y};
    }
    gardenFrame.querySelectorAll('[data-cat]').forEach((cat,i)=>{const point=i===0?{x:Math.max(20,root.x-bounds.x-120),y:Math.max(20,root.y-bounds.y-140)}:location((i*3)%8,2,4,150,155,'cat');cat.style.left=point.x+'px';cat.style.top=point.y+'px';cat.style.right='auto';cat.style.bottom='auto';});
    gardenFrame.querySelectorAll('.kt-floor-cluster').forEach((image,i)=>{const point=location(i,3,4,520,310,'meadow');image.style.left=point.x+'px';image.style.top=point.y+'px';image.style.width='520px';image.style.setProperty('--kt-sprig-angle','0deg');});
  }
  $('kt-reader-close').addEventListener('click',()=>{++requestId;$('kt-card-reader').hidden=true;});
  function resizeReader(expand){
    const reader=$('kt-card-reader'),before=reader.getBoundingClientRect();reader.getAnimations().forEach(animation=>animation.cancel());reader.classList.toggle('is-expanded',expand);
    const after=reader.getBoundingClientRect();$('kt-reader-expand').textContent=expand?'还原 ↙':'放大 ↗';$('kt-reader-expand').setAttribute('aria-label',expand?'还原知识卡片':'放大知识卡片');
    if(!matchMedia('(prefers-reduced-motion: reduce)').matches)reader.animate([{transform:`translate(${before.left-after.left}px,${before.top-after.top}px) scale(${before.width/after.width},${before.height/after.height})`},{transform:'none'}],{duration:340,easing:'cubic-bezier(.22,.7,.18,1)'});
  }
  $('kt-reader-expand').addEventListener('click',()=>resizeReader(!$('kt-card-reader').classList.contains('is-expanded')));
  function toast(message){const node=$('kt-toast');node.textContent=message;node.hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>{node.hidden=true;},3000);}
  function revealCard(card){
    query='';$('kt-query').value='';$('kt-search-results').hidden=true;
    for(let n=dirs.get(card.path);n;n=n.parent)expanded.add(n.path);
    revealed.add(card.url);rebuild();openCard(card);const node=entities.find(n=>n.key===card.url);if(node)fit([node]);
  }
  function renderBookmarks(){
    const list=$('kt-bookmark-list');list.replaceChildren();let count=0;
    for(const key of bookmarks){const card=data.cards.find(c=>c.url===key);if(!card)continue;count++;list.append(button('♧ '+card.title,()=>revealCard(card),'kt-search-result'));}
    $('kt-bookmark-count').textContent=String(count);if(!count)list.append(textEl('p',window.KnowledgeAccount?.state.user?'在场景详情里收藏叶子，下次回来仍可找到。':'使用 GitHub 登录后，收藏会保存在你的账号中。'));
  }
  async function saveLeaf(card,saved){
    try{if(!await window.KnowledgeAccount.setBookmark(card.url,saved))return false;if(saved)bookmarks.add(card.url);else bookmarks.delete(card.url);renderBookmarks();draw();return true;}catch(error){toast(error.message);return false;}
  }
  window.KnowledgeAccount?.ready.then(async state=>{if(state.user){try{const result=await window.KnowledgeAccount.request('/api/bookmarks');bookmarks.clear();for(const key of result.bookmarks)bookmarks.add(key);}catch(error){toast(error.message);}}if(data){renderBookmarks();draw();}});
  let giftCard=null,giftCat='松果',giftTicket=0;
  async function catGift(name){
    if(!data)return;giftCat=name;const pool=data.cards.filter(card=>under(card.path,scope)&&matches(card));
    if(!pool.length){toast('这片枝干暂时没有可送出的叶子。');return;}
    giftCard=pool[Math.floor(Math.random()*pool.length)];const card=giftCard,ticket=++giftTicket,dialog=$('kt-cat-dialog');
    $('kt-cat-caption').textContent=name+'递来一片知识叶子';$('kt-gift-title').textContent=card.title;
    $('kt-gift-meta').textContent=card.breadcrumb+' · '+(card.status==='verified'?'已核对':'草稿 / 未核对');
    $('kt-gift-body').textContent='正在展开猫送来的手记…';$('kt-gift-save').textContent=bookmarks.has(card.url)?'★ 已收藏':'☆ 收藏叶子';
    if(!dialog.open)dialog.showModal();
    try{const response=await fetch(urlFor(card.url));if(!response.ok)throw Error();const parsed=new DOMParser().parseFromString(await response.text(),'text/html'),body=parsed.querySelector('article main .content');if(!body)throw Error();body.querySelectorAll('.heading-anchor,.hextra-heading-anchor').forEach(n=>n.remove());const excerpt=body.textContent.replace(/\s+/g,' ').trim();if(ticket===giftTicket)$('kt-gift-body').textContent=excerpt.slice(0,650)+(excerpt.length>650?'…':'');}catch{if(ticket===giftTicket)$('kt-gift-body').textContent='这片叶子已送到，可以点击“阅读完整知识”展开手记。';}
  }
  document.querySelectorAll('[data-cat]').forEach(cat=>cat.addEventListener('click',()=>{cat.classList.remove('is-purring');void cat.offsetWidth;cat.classList.add('is-purring');catGift(cat.dataset.cat);}));
  $('kt-cat-close').addEventListener('click',()=>$('kt-cat-dialog').close());
  $('kt-cat-dialog').addEventListener('click',event=>{if(event.target===$('kt-cat-dialog'))event.target.close();});
  $('kt-gift-next').addEventListener('click',()=>catGift(giftCat));
  $('kt-gift-open').addEventListener('click',()=>{if(giftCard){$('kt-cat-dialog').close();revealCard(giftCard);}});
  $('kt-gift-save').addEventListener('click',async()=>{if(giftCard&&await saveLeaf(giftCard,true))$('kt-gift-save').textContent='★ 已收藏';});
  function updateMatches() {
    const relevant=new Set();
    if(query)for(const n of entities){if(n.kind==='directory'&&under(n.path,scope)&&matches(n)||n.kind==='card'&&under(n.path,scope)&&matches(n.card)){for(let p=n;p;p=p.parent)relevant.add(p.key);}}
    for(const n of entities){n.element.classList.toggle('kt-dim',!!query&&!relevant.has(n.key));n.element.classList.toggle('kt-match',!!query&&(n.kind==='directory'?under(n.path,scope)&&matches(n):n.kind==='card'&&under(n.path,scope)&&matches(n.card)));if(n.edge)n.edge.classList.toggle('kt-dim',!!query&&!relevant.has(n.key));}
    function mark(n){let visible=relevant.has(n.key);for(const c of n.routes||[]){if(mark(c))visible=true;}n.routeRelevant=visible;return visible;}
    mark(root);for(const edge of woodEdges)edge.element.classList.toggle('kt-dim',!!query&&!edge.child.routeRelevant);
  }
  function search() {
    if(!data)return;query=$('kt-query').value.trim();rebuild();const result=$('kt-search-results');result.replaceChildren();result.hidden=!query;if(!query)return;
    const directoryMatches=Array.from(dirs.values()).filter(n=>under(n.path,scope)&&matches(n)),cardMatches=data.cards.filter(c=>under(c.path,scope)&&matches(c));
    result.append(textEl('p',`${directoryMatches.length} 个目录 · ${cardMatches.length} 张场景`));
    for(const n of directoryMatches.slice(0,15))result.append(button('▱ 目录 · '+n.title,()=>{openDirectory(n,false,false);focusNode(n);},'kt-search-result kt-search-directory'));
    for(const c of cardMatches.slice(0,40)){const b=button('❧ '+c.title,()=>{openCard(c);const n=entities.find(x=>x.key===c.url);if(n)fit([n]);},'kt-search-result kt-search-card');b.append(textEl('small',c.breadcrumb));result.append(b);}
    if(!directoryMatches.length&&!cardMatches.length)result.append(textEl('p','当前分支没有匹配结果。可返回全库继续搜索。'));
    else if(cardMatches.length>40)result.append(textEl('p','先展示前 40 个匹配，请缩小搜索范围。'));
  }
  $('kt-query').addEventListener('input',()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(search,160);});
  $('kt-reset-scope').addEventListener('click',()=>{scope='';syncScope();search();});
  $('kt-fit').addEventListener('click',()=>fit(entities));
  $('kt-home').addEventListener('click',()=>{query='';$('kt-query').value='';scope='';rebuild();openDirectory(root);$('kt-search-results').hidden=true;homeView();});
  $('kt-random').addEventListener('click',()=>{const pool=data?.cards.filter(c=>under(c.path,scope)&&matches(c));if(!pool?.length){toast('当前范围没有可拾取的叶子。');return;}const card=pool[Math.floor(Math.random()*pool.length)];revealCard(card);toast('拾到一叶 · '+card.title);});
  $('kt-zoom-in').addEventListener('click',()=>zoomAt(1.45));$('kt-zoom-out').addEventListener('click',()=>zoomAt(1/1.45));
  viewport.addEventListener('wheel',e=>{e.preventDefault();const r=viewport.getBoundingClientRect();zoomAt(Math.exp(-e.deltaY*.0016),e.clientX-r.left,e.clientY-r.top);},{passive:false});
  viewport.addEventListener('pointerdown',e=>{if(e.button!==0)return;dragMoved=false;pointers.set(e.pointerId,{x:e.clientX,y:e.clientY});if(!e.target.closest("button,[role=button]"))viewport.setPointerCapture(e.pointerId);viewport.classList.add('is-dragging');if(pointers.size===2){const p=Array.from(pointers.values());pinch=Math.hypot(p[0].x-p[1].x,p[0].y-p[1].y);}});
  viewport.addEventListener('pointermove',e=>{const old=pointers.get(e.pointerId);if(!old)return;const dx=e.clientX-old.x,dy=e.clientY-old.y;if(Math.abs(dx)+Math.abs(dy)>2)dragMoved=true;pointers.set(e.pointerId,{x:e.clientX,y:e.clientY});if(pointers.size===2){const p=Array.from(pointers.values()),distance=Math.hypot(p[0].x-p[1].x,p[0].y-p[1].y),r=viewport.getBoundingClientRect();if(pinch)zoomAt(distance/pinch,(p[0].x+p[1].x)/2-r.left,(p[0].y+p[1].y)/2-r.top);pinch=distance;}else{interaction();tx+=dx;ty+=dy;transform();}});
  function release(e){pointers.delete(e.pointerId);pinch=null;if(!pointers.size)viewport.classList.remove('is-dragging');}
  viewport.addEventListener('pointerup',release);viewport.addEventListener('pointercancel',release);
  $('kt-minimap').addEventListener('click',e=>{if(!mini)return;const r=e.currentTarget.getBoundingClientRect(),x=(e.clientX-r.left)*180/r.width,y=(e.clientY-r.top)*105/r.height;tx=viewport.clientWidth/2-((x-mini.ox)/mini.s+mini.x)*scale;ty=viewport.clientHeight/2-((y-mini.oy)/mini.s+mini.y)*scale;transform();});
  new ResizeObserver(()=>{if(data)transform();}).observe(viewport);
  fetch(urlFor('kb-index.json')).then(r=>{if(!r.ok)throw Error(r.status);return r.json();}).then(json=>{data=json;setup();}).catch(e=>{$('kt-loading').textContent='知识树加载失败，请刷新重试。';$('kt-loading').classList.add('kt-error');console.error(e);});
})();
