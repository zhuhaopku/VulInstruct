import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from vulinstruct.llm import LLMClient
from vulinstruct.io import write_json, digest
from vulinstruct.cli import main
from vulinstruct.datasets import normalize_corpus
from test_pipeline import Pipeline, Client, Dense, NVD, sample


@pytest.mark.parametrize('url', ['http://localhost:80@external.invalid/v1', 'https://user:pass@example.invalid/v1', 'https://example.invalid/v1?token=value', 'https://example.invalid/v1#fragment', 'https:///v1'])
def test_endpoint_rejects_embedded_credentials_and_loopback_spoof(url):
    with pytest.raises(ValueError):LLMClient(url)


def test_authorization_is_never_forwarded_by_redirect(tmp_path, monkeypatch):
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            seen.append(self.path);self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(302);self.send_header('Location','/collector');self.end_headers()
        def do_GET(self):
            seen.append(self.path);self.send_response(200);self.end_headers()
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
    monkeypatch.setenv('FIXTURE_TOKEN','dummy-test-value')
    try:
        c=LLMClient('http://127.0.0.1:'+str(server.server_port)+'/v1',key_env='FIXTURE_TOKEN',cache_dir=tmp_path)
        with pytest.raises(RuntimeError,match='HTTP 302'):c.ask('example','fixture','detect')
        assert seen==['/v1/chat/completions']
    finally:server.shutdown();t.join();server.server_close()


def test_failed_rerun_removes_stale_metrics(tmp_path):
    write_json(tmp_path/'metrics.json',{'f1':1});write_json(tmp_path/'results.json',[{'status':'ok'}])
    p=Pipeline(Client(),Dense(),NVD(),{'models':dict(knowledge='fixture',detector='fixture',judge='fixture')})
    s=sample();s['ground_truth_status']='requires_review'
    assert p.run([s],tmp_path)[0]['status']=='error'
    assert not (tmp_path/'metrics.json').exists()
    assert json.loads((tmp_path/'results.json').read_text())[0]['status']=='error'


def test_cli_invalid_inputs_remove_old_run_summary(tmp_path):
    write_json(tmp_path/'metrics.json',{'f1':1})
    assert main(['run','--benchmark','missing','--config',str(tmp_path/'missing.json'),'--output',str(tmp_path)])==2
    assert not (tmp_path/'metrics.json').exists()


def test_cli_detects_changed_benchmark_content_and_stale_output(tmp_path):
    a=sample();b=dict(a,sample_id='b',code_type='after',true_label=0)
    results=[dict(x,prediction=0,status='ok',sample_hash=digest(x)) for x in [a,b]]
    a['code']='changed input';write_json(tmp_path/'b.json',[a,b]);write_json(tmp_path/'r.json',results)
    write_json(tmp_path/'metrics.json',{'f1':1})
    assert main(['evaluate','--benchmark',str(tmp_path/'b.json'),'--results',str(tmp_path/'r.json'),'--output',str(tmp_path/'metrics.json')])==2
    assert not (tmp_path/'metrics.json').exists()


def test_versioned_result_cannot_disagree_with_its_answer(tmp_path):
    a=sample();b=dict(a,sample_id='b',code_type='after',true_label=0)
    answer='<has_vulnerability>no</has_vulnerability><suspected_root_cause>Checked.</suspected_root_cause>'
    r=[dict(x,prediction=1,status='ok',judge='MATCH',protocol='domain-cascade-v4',raw_response=answer) for x in [a,b]]
    write_json(tmp_path/'b.json',[a,b]);write_json(tmp_path/'r.json',r)
    assert main(['evaluate','--benchmark',str(tmp_path/'b.json'),'--results',str(tmp_path/'r.json')])==2


def test_normalize_wrapped_list_and_invalid_spec_schema(tmp_path):
    case=dict(case_id='one',cve_id='CVE-2000-1',understand='Parser',specifications=['Check bounds'])
    write_json(tmp_path/'c.json',{'cases':[case]});assert len(normalize_corpus(tmp_path/'c.json'))==1
    case['specifications']='not a list';write_json(tmp_path/'c.json',[case])
    with pytest.raises(ValueError):normalize_corpus(tmp_path/'c.json')


def test_evaluation_cannot_delete_its_input(tmp_path):
    file = tmp_path / 'input.json'
    file.write_text('[]')
    assert main(['evaluate', '--benchmark', str(file), '--results', str(file), '--output', str(file)]) == 2
    assert file.read_text() == '[]'
