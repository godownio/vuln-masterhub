"""Hugging Face Gradio SDK entry point; no credentials belong in this file."""
import os
import sqlite3
import gzip
import hashlib
import json
import tempfile
import zipfile
import shutil
from pathlib import Path

os.environ.setdefault('PORTAL_REQUIRE_DATABASE','1')
os.environ.setdefault('VULN_MASTERHUB_EMBED_MODEL','moka-ai/m3e-base')
os.environ.setdefault('VULN_MASTERHUB_EMBED_DEVICE','cpu')
os.environ.setdefault('HF_ENDPOINT','https://huggingface.co')
os.environ.setdefault('OMP_NUM_THREADS','2')
os.environ.setdefault('MKL_NUM_THREADS','2')
os.environ.setdefault('TOKENIZERS_PARALLELISM','false')
if os.environ.get('SPACE_HOST'):
    os.environ.setdefault('PORTAL_BASE_URL','https://'+os.environ['SPACE_HOST'])
if os.environ.get('SPACE_SIGNING_SECRET'):
    os.environ.setdefault('PORTAL_SESSION_SECRET',os.environ['SPACE_SIGNING_SECRET'])

def load_release_bundle(root):
    pointer=root/'cloud-release.json'
    if not pointer.exists():
        return
    import requests
    release=json.loads(pointer.read_text())
    prefix='https://github.com/godownio/vuln-masterhub/releases/download/'
    if not release['url'].startswith(prefix) or not release['url'].endswith('/space-runtime.zip'):
        raise RuntimeError('Unexpected release origin')
    with tempfile.TemporaryDirectory() as directory:
        archive=Path(directory)/'release.zip';digest=hashlib.sha256()
        with requests.get(release['url'],stream=True,timeout=(30,180)) as response:
            response.raise_for_status()
            with archive.open('wb') as output:
                for chunk in response.iter_content(1024*1024):
                    digest.update(chunk);output.write(chunk)
        if digest.hexdigest()!=release['sha256']:
            raise RuntimeError('Release archive checksum mismatch')
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                name=member.filename
                if not (name.startswith(('knowledge/','hugo-site/public/')) or name in ('data/kb.sqlite','data/portal-vectors.sqlite','release-manifest.json')):
                    continue
                target=(root/name).resolve()
                if not target.is_relative_to(root.resolve()):
                    raise RuntimeError('Invalid release path')
                if member.is_dir():target.mkdir(parents=True,exist_ok=True)
                else:
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with bundle.open(member) as source,target.open('wb') as output:
                        shutil.copyfileobj(source,output)
    # A previous compressed deployment must not overwrite this verified bundle.
    for name in ('kb.sqlite.gz','portal-vectors.sqlite.gz'):
        (root/'data'/name).unlink(missing_ok=True)


def restore_release_databases(root):
    # Compressed release databases avoid storing a second large raw revision.
    manifest_path=root/'release-manifest.json'
    manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    for name in ('kb.sqlite','portal-vectors.sqlite'):
        packed=root/'data'/(name+'.gz')
        if packed.exists():
            target=root/'data'/name;temporary=target.with_suffix('.unpacking')
            digest=hashlib.sha256()
            with gzip.open(packed,'rb') as source,temporary.open('wb') as output:
                while chunk:=source.read(1024*1024):
                    digest.update(chunk);output.write(chunk)
            expected=manifest.get('files',{}).get('data/'+name)
            if not expected or digest.hexdigest()!=expected:
                temporary.unlink()
                raise RuntimeError('Release database checksum mismatch: '+name)
            temporary.replace(target)

if __name__=='__main__':
    if not os.environ.get('PORTAL_SESSION_SECRET'):
        raise RuntimeError('Configure a persistent PORTAL_SESSION_SECRET in Space Secrets')
    root=Path(__file__).resolve().parent
    load_release_bundle(root)
    restore_release_databases(root)
    with sqlite3.connect(root/'data/kb.sqlite') as db:
        for cid,path,filename in db.execute('SELECT id,path,filename FROM cards').fetchall():
            db.execute('UPDATE cards SET file_path=? WHERE id=?',(str(root/'knowledge'/path/filename),cid))
    import uvicorn
    from web.portal_gradio import create_app
    search=None
    if os.environ.get('SPACES_ZERO_GPU','').lower() in ('1','t','true'):
        # This is real query inference, reached only through authenticated MCP.
        # Keep CUDA placement at startup as required by ZeroGPU's emulation.
        import spaces
        from tools.kb_lib.config import load
        from tools.kb_lib.embedder import Embedder
        from tools.kb_lib.portal_search import KnowledgeSearch
        cfg=load(root)
        gpu_embedder=Embedder(cache_dir=cfg.data/'models')
        gpu_embedder.load().to('cuda')

        @spaces.GPU(duration=10)
        def encode_query(text):
            return gpu_embedder.encode_one(text)

        class CloudQueryEmbedder:
            model_name=gpu_embedder.model_name

            def encode_one(self,text):
                return encode_query(text)

        search=KnowledgeSearch(cfg,CloudQueryEmbedder())
        # Gradio's mount API does not call Blocks.launch, where spaces normally
        # packs CUDA tensors and registers its decorated functions on startup.
        from spaces.zero import startup as start_zero_gpu
        start_zero_gpu()
    uvicorn.run(create_app(search=search),host='0.0.0.0',port=7860,access_log=False,proxy_headers=False)
