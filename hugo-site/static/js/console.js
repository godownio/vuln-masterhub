(async()=>{
  const account=window.KnowledgeAccount,$=id=>document.getElementById(id),state=await account.ready;
  const message=text=>{$('console-message').textContent=text;};
  const reasons={'not-configured':'GitHub 登录暂未配置完成。','invalid-state':'登录状态已失效。请在同一个浏览器内，从知识库的登录按钮重新完成授权。','cancelled':'登录已取消。','provider-error':'GitHub 暂时未能完成验证，请重试。'};
  message(reasons[new URL(location.href).searchParams.get('login')]||'');
  $('console-login-button').onclick=()=>account.login();
  $('mcp-endpoint').textContent=state.mcp_url||location.origin+'/mcp';
  $('mcp-config').textContent=JSON.stringify({mcpServers:{'godown-knowledge':{url:state.mcp_url||location.origin+'/mcp',headers:{Authorization:'Bearer YOUR_API_KEY'}}}},null,2);
  fetch('/api/search/status').then(r=>r.json()).then(index=>{$('vector-status').textContent=index.ready?`向量索引：${index.cards} 张卡片 / ${index.chunks} 个分块，模型 ${index.model}`:'向量索引尚未就绪，当前会回退到关键词检索。';}).catch(()=>{$('vector-status').textContent='暂时无法读取索引状态。';});
  if(!state.user)return;
  $('console-login').hidden=true;$('console-authenticated').hidden=false;
  const date=seconds=>seconds?new Date(seconds*1000).toLocaleString():'—';
  async function refresh(){
    const {keys}=await account.request('/api/keys'),list=$('key-list');list.replaceChildren();
    for(const key of keys){const tr=document.createElement('tr'),expired=key.expires_at&&key.expires_at*1000<=Date.now();for(const text of [key.name,key.prefix+'…',key.expires_at?date(key.expires_at):'永不过期',date(key.last_used_at),key.revoked_at?'已撤销':expired?'已过期':'有效']){const td=document.createElement('td');td.textContent=text;tr.append(td);}const td=document.createElement('td');if(!key.revoked_at){const button=document.createElement('button');button.type='button';button.textContent='撤销';button.onclick=async()=>{button.disabled=true;try{await account.request('/api/keys/'+key.id,{method:'DELETE'});message('密钥已撤销，不能再用于 MCP。');await refresh();}catch(error){message(error.message);button.disabled=false;}};td.append(button);}tr.append(td);list.append(tr);}
    if(!keys.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=6;td.textContent='还没有密钥，创建一把开始检索。';tr.append(td);list.append(tr);}
  }
  const form=$('key-form');form.elements.lifetime.onchange=()=>{$('key-custom-label').hidden=form.elements.lifetime.value!=='custom';form.elements.expires.required=form.elements.lifetime.value==='custom';};
  form.onsubmit=async event=>{event.preventDefault();const submit=form.querySelector('[type=submit]');submit.disabled=true;try{let lifetime=form.elements.lifetime.value;if(lifetime==='custom'){lifetime=Math.floor((new Date(form.elements.expires.value).getTime()-Date.now())/1000);if(!Number.isFinite(lifetime)||lifetime<60)throw Error('请选择至少一分钟以后的到期时间。');}else lifetime=lifetime===''?null:Number(lifetime);const result=await account.request('/api/keys',{method:'POST',body:JSON.stringify({name:form.elements.name.value,lifetime_seconds:lifetime})});$('key-secret').value=result.token;$('key-created').hidden=false;message('新密钥已创建。');await refresh();}catch(error){message(error.message);}finally{submit.disabled=false;}};
  $('key-copy').onclick=async()=>{try{await navigator.clipboard.writeText($('key-secret').value);message('密钥已复制。');}catch{ $('key-secret').select();message('请手动复制选中的密钥。');}};
  $('key-dismiss').onclick=()=>{$('key-secret').value='';$('key-created').hidden=true;};
  try{await refresh();}catch(error){message(error.message);}
})();
