"""Hugging Face Gradio SDK entry point; no credentials belong in this file."""
import os
import sqlite3
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

if __name__=='__main__':
    if not os.environ.get('PORTAL_SESSION_SECRET'):
        raise RuntimeError('Configure a persistent PORTAL_SESSION_SECRET in Space Secrets')
    root=Path(__file__).resolve().parent
    with sqlite3.connect(root/'data/kb.sqlite') as db:
        for cid,path,filename in db.execute('SELECT id,path,filename FROM cards').fetchall():
            db.execute('UPDATE cards SET file_path=? WHERE id=?',(str(root/'knowledge'/path/filename),cid))
    import uvicorn
    from web.portal_gradio import create_app
    search=None
    if os.environ.get('SPACES_ZERO_GPU') == 'true':
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
    uvicorn.run(create_app(search=search),host='0.0.0.0',port=7860,access_log=False,proxy_headers=False)
