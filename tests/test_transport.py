import json
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import pytest
from vulinstruct.llm import LLMClient

@pytest.fixture
def server():
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));seen.append(body)
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
            content={'choices':[{'message':{'content':'<match_result>MATCH</match_result>'},'finish_reason':'stop'}],'usage':{'total_tokens':10}}
            self.wfile.write(json.dumps(content).encode())
    http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
    yield 'http://127.0.0.1:'+str(http.server_port)+'/v1',seen
    http.shutdown();thread.join();http.server_close()

def test_http_roundtrip_cache_budget_and_reasoning_payload(tmp_path,server):
    url,seen=server;c=LLMClient(url,cache_dir=tmp_path,max_calls=2)
    assert c.ask('judge evidence','gpt-5','judge')=='<match_result>MATCH</match_result>'
    c.ask('judge evidence','gpt-5','judge');assert len(seen)==1 and c.cache_hits==1
    assert 'temperature' not in seen[0] and 'max_completion_tokens' in seen[0]
    c.ask('other input','deepseek-v3','detect');assert len(seen)==2 and seen[1]['temperature']==0
    with pytest.raises(RuntimeError,match='budget'):c.ask('third input','deepseek-v3','detect')
    for p in tmp_path.glob('*.json'):assert 'Authorization' not in p.read_text()

def test_explicit_cache_refresh_replaces_cached_bad_output(tmp_path,server):
    url,seen=server;c=LLMClient(url,cache_dir=tmp_path,max_calls=3)
    c.ask('same','fixture','judge');c.ask('same','fixture','judge');assert len(seen)==1
    fresh=LLMClient(url,cache_dir=tmp_path,max_calls=1,refresh_cache=True)
    fresh.ask('same','fixture','judge');assert len(seen)==2

def test_thinking_option_is_sent_and_changes_cache_identity(tmp_path,server):
    url,seen=server
    a=LLMClient(url,cache_dir=tmp_path,max_calls=1)
    a.ask('prompt','deepseek-flash','judge')
    b=LLMClient(url,cache_dir=tmp_path,max_calls=1,request_options={'thinking':{'type':'disabled'}})
    b.ask('prompt','deepseek-flash','judge')
    assert len(seen)==2 and seen[1]['thinking']=={'type':'disabled'}
    assert b.stats()['successful_network_tokens']['total_tokens']==10
    with pytest.raises(ValueError):LLMClient(url,request_options={'messages':[]})

def test_stage_options_do_not_leak_into_knowledge_calls_or_share_wrong_cache(tmp_path,server):
    url,seen=server
    c=LLMClient(url,cache_dir=tmp_path,max_calls=3,max_output_tokens=4096,
        request_options={'thinking':{'type':'disabled'}},
        stage_request_options={'detect':{'thinking':{'type':'enabled'}}},
        stage_max_output_tokens={'detect':16384})
    c.ask('same','deepseek-flash','keywords');c.ask('same','deepseek-flash','detect');c.ask('same','deepseek-flash','keywords')
    assert len(seen)==2 and c.cache_hits==1
    assert seen[0]['thinking']['type']=='disabled' and seen[0]['max_tokens']==4096
    assert seen[1]['thinking']['type']=='enabled' and seen[1]['max_tokens']==16384
    with pytest.raises(ValueError):LLMClient(url,stage_request_options={'detect':{'messages':[]}})
    with pytest.raises(ValueError):LLMClient(url,stage_max_output_tokens={'detect':-1})

def test_cached_incomplete_output_is_never_accepted_or_silently_retried(tmp_path,server):
    url,seen=server;c=LLMClient(url,cache_dir=tmp_path,max_calls=1)
    c.ask('same','deepseek-flash','detect')
    path=next(tmp_path.glob('*.json'));data=json.loads(path.read_text())
    data.update(response='',finish_reason='length',validation_error='Model output truncated; increase max_output_tokens')
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='truncated'):c.ask('same','deepseek-flash','detect')
    assert len(seen)==1

def test_concurrent_identical_requests_share_one_response_and_cache_entry(tmp_path,server):
    from concurrent.futures import ThreadPoolExecutor
    url,seen=server;c=LLMClient(url,cache_dir=tmp_path,max_calls=8)
    start=threading.Barrier(8)
    def same_request(_):
        start.wait()
        return c.ask('same evidence','deepseek-flash','domain-specifications')
    with ThreadPoolExecutor(max_workers=8) as pool:answers=list(pool.map(same_request,range(8)))
    assert len(seen)==1 and c.cache_hits==7 and len(set(answers))==1
    assert len(list(tmp_path.glob('*.json')))==1
