(() => {
  const treeEl = document.querySelector('#kb-tree'), cardsEl = document.querySelector('#kb-cards');
  if (!treeEl || !cardsEl) return;
  const queryEl = document.querySelector('#kb-query'), countEl = document.querySelector('#kb-count');
  let data, selected = '', query = '', limit = 36, expanded = false;
  const previewLimits = new Map(), dialog = document.querySelector('#kb-dialog');
  const norm = s => String(s || '').normalize('NFKC').toLocaleLowerCase();
  const matches = (item, q) => !q || norm([item.title, item.path, item.description, ...(item.aliases || []), ...(item.tags || []), ...(item.cve || [])].join(' ')).includes(q);
  const pathMatch = (path, chosen) => !chosen || path === chosen || path.startsWith(chosen + '/');
  const el = (tag, cls, value) => { const n = document.createElement(tag); if (cls) n.className = cls; if (value != null) n.textContent = value; return n; };
  function renderTree() {
    treeEl.replaceChildren(); const q = norm(query);
    const matchingPaths = new Set();
    for (const card of data.cards) if (pathMatch(card.path,selected) && matches(card, q)) { const parts = card.path.split('/'); for(let i=1;i<=parts.length;i++) matchingPaths.add(parts.slice(0,i).join('/')); }
    function visit(nodes, parent) {
      for (const node of nodes) {
        const inScope = !selected || pathMatch(node.path,selected) || selected.startsWith(node.path + '/');
        const ownMatch = matches(node,q), visible = inScope && (!q || ownMatch || matchingPaths.has(node.path));
        if (!visible) continue;
        const details = el('details','kb-node' + (selected === node.path ? ' active' : ''));
        details.open = !!q || expanded || !!selected && selected.startsWith(node.path + '/');
        const summary = el('summary'); summary.append(el('span','kb-arrow','›'));
        const title = el('span','kb-node-title',node.title); title.addEventListener('click', e => { e.preventDefault(); selected = selected === node.path ? '' : node.path; limit=36; render(); });
        summary.append(title,el('span','kb-node-count',node.count)); details.append(summary);
        const children=el('div','kb-children'); visit(node.children || [],children); details.append(children);
        const nodeCards=data.cards.filter(c => pathMatch(c.path,node.path) && matches(c,q));
        if(nodeCards.length) {
          const preview=el('div','kb-node-preview'), list=el('div','kb-node-preview-list'), controls=el('div','kb-node-controls');
          const countInput=el('input'); countInput.type='number'; countInput.min='1'; countInput.max=String(nodeCards.length);
          countInput.setAttribute('aria-label',`显示 ${node.title} 的卡片数`);
          const expand=el('button',null,'展开'); expand.type='button';
          function updatePreview(){
            const n=Math.min(nodeCards.length,Math.max(1,previewLimits.get(node.path) || 3));
            list.replaceChildren();
            for(const card of nodeCards.slice(0,n)) list.append(cardButton(card,'kb-preview-card'));
            countInput.value=String(n); expand.hidden=n>=nodeCards.length;
            controls.hidden=nodeCards.length<=3;
          }
          expand.addEventListener('click',()=>{previewLimits.set(node.path,Math.min(nodeCards.length,Math.max(1,Number(countInput.value)||3)));updatePreview();});
          countInput.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();expand.click();}});
          controls.append(el('span',null,`共 ${nodeCards.length} 张 · 显示`),countInput,expand);
          preview.append(list,controls); details.append(preview); updatePreview();
        }
        parent.append(details);
      }
    }
    visit(data.tree,treeEl);
  }
  function cardButton(card, cls){const button=el('button',cls,card.title);button.type='button';button.addEventListener('click',()=>openCard(card));return button;}
  async function openCard(card){
    const body=document.querySelector('#kb-dialog-body'), url=new URL(card.url.replace(/^\//,''),document.baseURI);
    document.querySelector('#kb-dialog-title').textContent=card.title;
    document.querySelector('#kb-dialog-link').href=url.href;
    body.replaceChildren(el('p',null,'正在加载详情…'));dialog.showModal();
    try{
      const response=await fetch(url);if(!response.ok)throw Error(response.status);
      const parsed=new DOMParser().parseFromString(await response.text(),'text/html');
      const content=parsed.querySelector('article main .content') || parsed.querySelector('article main');
      if(!content)throw Error('找不到正文');
      for(const item of content.querySelectorAll('[href],[src]')) for(const attr of ['href','src']) if(item.hasAttribute(attr)) item.setAttribute(attr,new URL(item.getAttribute(attr),url).href);
      body.replaceChildren(...Array.from(content.childNodes).map(n=>document.importNode(n,true)));
    }catch{body.replaceChildren(el('p',null,'详情加载失败，请使用下方链接打开完整页面。'));}
  }
  function renderCards() {
    const q=norm(query), cards=data.cards.filter(c => pathMatch(c.path,selected) && matches(c,q));
    document.querySelector('#kb-heading').textContent=selected ? (data.nodes[selected]?.title || selected) : '全部场景';
    document.querySelector('#kb-clear').hidden=!selected && !query;
    countEl.textContent=`${cards.length} 张卡片`;
    cardsEl.replaceChildren();
    for(const card of cards.slice(0,limit)) {
      cardsEl.append(cardButton(card,'kb-card'));
    }
    if(!cards.length) cardsEl.append(el('p',null,'没有匹配的目录或卡片。'));
    document.querySelector('#kb-more').hidden=cards.length<=limit;
  }
  function render(){renderTree();renderCards();}
  queryEl.addEventListener('input',()=>{query=queryEl.value.trim();limit=36;render();});
  document.querySelector('#kb-clear').addEventListener('click',()=>{selected='';query='';queryEl.value='';render();});
  document.querySelector('#kb-expand').addEventListener('click',()=>{expanded=!expanded;document.querySelector('#kb-expand').textContent=expanded?'全部收起':'全部展开';renderTree();});
  document.querySelector('#kb-more').addEventListener('click',()=>{limit+=36;renderCards();});
  document.querySelector('#kb-dialog-close').addEventListener('click',()=>dialog.close());
  dialog.addEventListener('click',e=>{if(e.target===dialog)dialog.close();});
  fetch(new URL('kb-index.json',document.baseURI)).then(r=>{if(!r.ok)throw Error(r.status);return r.json();}).then(json=>{data=json;document.querySelector('#card-total').textContent=data.cards.length.toLocaleString();render();}).catch(()=>{countEl.textContent='索引加载失败，请先运行导出脚本。';});
})();
