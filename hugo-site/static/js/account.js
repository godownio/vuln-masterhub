(() => {
  const state={user:null,csrf:'',oauth_ready:false,mcp_url:''};
  const remote=window.KnowledgePortal&&new URL(window.KnowledgePortal).origin!==location.origin;
  const portal=remote?window.KnowledgePortal.replace(/\/$/,''):'';
  if(remote){state.oauth_ready=true;for(const link of document.querySelectorAll('a[href$="/console/"]'))link.href=portal+'/console/';}
  const ready=remote?Promise.resolve(state):fetch('/api/session',{credentials:'same-origin',cache:'no-store'}).then(async response=>{if(!response.ok)throw Error('账号服务尚未就绪');Object.assign(state,await response.json());return state;}).catch(error=>{state.error=error.message;return state;});
  async function request(path,options={}){
    await ready;const headers={...(options.headers||{})};
    if(options.method&&options.method!=='GET'){headers['X-CSRF-Token']=state.csrf;headers['Content-Type']='application/json';}
    const response=await fetch(path,{...options,headers,credentials:'same-origin',cache:'no-store'}),data=await response.json();
    if(!response.ok)throw Error(data.error||'请求失败');return data;
  }
  function login(message='使用 GitHub 登录后，可以收藏知识叶子并管理 API Key。'){
    let dialog=document.getElementById('kt-login-dialog');
    if(!dialog){dialog=document.createElement('dialog');dialog.id='kt-login-dialog';dialog.className='kt-paper-dialog';dialog.innerHTML='<div class="kt-paper-dialog-head"><span>知识树 · 登录</span><button type="button" aria-label="关闭">×</button></div><h2>让叶子留在你的书页里</h2><p class="kt-login-message"></p><a class="kt-github-login" href="/auth/github/login">使用 GitHub 继续 ↗</a>';document.body.append(dialog);dialog.querySelector('button').onclick=()=>dialog.close();dialog.addEventListener('click',event=>{if(event.target===dialog)dialog.close();});}
    dialog.querySelector('.kt-login-message').textContent=remote?'前往在线知识树登录，收藏和 API Key 将保存在你的账号中。':state.error||(!state.oauth_ready?'GitHub 登录暂未配置完成，请稍后再试。':message);
    const link=dialog.querySelector('a');link.hidden=!state.oauth_ready;link.href=portal+'/auth/github/login'+(location.pathname.startsWith('/console')?'?next=/console/':'');dialog.showModal();
  }
  async function setBookmark(url,saved){await ready;if(!state.user){login();return false;}await request('/api/bookmarks',{method:saved?'POST':'DELETE',body:JSON.stringify({url})});return true;}
  window.KnowledgeAccount={state,ready,request,login,setBookmark};
  ready.then(()=>{
    const button=document.getElementById('kt-account-button');if(!button)return;
    button.textContent=state.user?state.user.login+' · 退出':'GitHub 登录';
    button.onclick=async()=>{if(!state.user){login();return;}try{await request('/api/logout',{method:'POST',body:'{}'});location.reload();}catch(error){login(error.message);}};
  });
})();
