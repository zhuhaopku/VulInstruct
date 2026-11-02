from conftest import research_root
import json
from pathlib import Path
import pytest
from vulinstruct.pipeline import Pipeline, validate_domain_specs, selected_items
from vulinstruct.prompts import target_text
from vulinstruct.knowledge import build_knowledge
from vulinstruct.io import write_json,rows

class Dense:
    manifest={'fixture':'dense'}
    def search(self,*args,**kwargs):
        return [dict(case_id='historical',cve_id='CVE-2018-1',specifications=['HS-BOUNDS-001: Validate buffer sizes.'],understand='parser',vulnerability_analysis='copy overflow')]

class NVD:
    manifest={'fixture':'nvd'}
    def get(self,cid):return {'published':'2020-01-01'}
    def search(self,*args,**kwargs):return {'results':[],'audit':{'fixture':True}}
    def search_domain(self,*args,**kwargs):return self.search(*args,**kwargs)

class Client:
    def __init__(self):self.calls=[]
    def ask(self,prompt,model,stage):
        self.calls.append((stage,prompt))
        if stage=='understand':return '<understand>network parser</understand>'
        if stage=='keywords':return '{"identifiers":["widget"],"domain_terms":["protocol"]}'
        if stage.startswith('score-'):
            items=json.loads(prompt.split('CANDIDATES:\n')[1]);return json.dumps({'scores':[dict(id=r['id'],score=8 if stage=='score-specifications' else 1) for r in items]})
        if stage in ('detect','detect-review'):return '<has_vulnerability>yes</has_vulnerability><suspected_root_cause>Unbounded copy.</suspected_root_cause>'
        if stage=='judge':return 'Final judgment: FALSE_ALARM' if 'based on the patched version' in prompt else 'Final judgment: MATCH'
        raise AssertionError(stage)

def sample():
    return dict(sample_id='a',pair_id='p',code_type='before',true_label=1,cve_id='CVE-2020-1',repository='widget',filename='parser.c',code='copy(buf,input);',context='',ground_truth={'cve_description':'SECRET_GOLD','commit_message':'FIX_SECRET','code_diff':'PATCH_SECRET'},ground_truth_status='source_pair')

def test_specs_only_and_gold_isolation_and_resume(tmp_path):
    client=Client();p=Pipeline(client,Dense(),NVD(),{'models':dict(knowledge='fixture',detector='fixture',judge='fixture')})
    s=sample();result=p.run([s],tmp_path)
    assert result[0]['knowledge']['specifications'] and not result[0]['knowledge']['cases']
    assert result[0]['judge']=='MATCH'
    for stage,prompt in client.calls:
        if stage!='judge':
            for secret in ['SECRET_GOLD','PATCH_SECRET','FIX_SECRET','CVE-2020-1']:assert secret not in prompt
    calls=len(client.calls);assert p.run([s],tmp_path)==result;assert len(client.calls)==calls
    s['code']='copy(buf,input,n);';p.run([s],tmp_path);assert len(client.calls)>calls

def test_failed_metadata_never_runs_or_scores(tmp_path):
    client=Client();p=Pipeline(client,Dense(),NVD(),{'models':dict(knowledge='fixture',detector='fixture',judge='fixture')})
    s=sample();s['ground_truth_status']='requires_review';result=p.run([s],tmp_path)
    assert result[0]['status']=='error' and not client.calls

@pytest.mark.parametrize('refs',[['CVE-2018-1'],['CVE-2018-1','CVE-2018-1'],['CVE-2018-1','CVE-2099-2']])
def test_domain_specs_require_real_recurring_support(refs):
    with pytest.raises(ValueError):validate_domain_specs({'specifications':[dict(id='AS-PARSE-001',statement='Validate lengths',attack_pattern='overflow',supporting_cves=refs)]},[{'cve_id':'CVE-2018-1'},{'cve_id':'CVE-2018-2'}])

def test_knowledge_score_coverage():
    class Bad:
        def ask(self,*args):return '{"scores":[]}'
    with pytest.raises(ValueError,match='omitted'):selected_items(Bad(),'m',sample(),[{'id':'a'}],'cases',6)

def test_original_extraction_prompts_and_all_methods(tmp_path):
    class Extraction:
        def __init__(self):self.calls=[]
        def ask(self,prompt,model,stage):
            self.calls.append(prompt)
            if len(self.calls)==1:return '<understand>Parser</understand><spec>HS-BOUNDS-001: Validate lengths.</spec>'
            return '<model>untrusted input</model><vuln>unbounded read</vuln><solution>length check</solution>'
    item=dict(cve_id='CVE-2020-1',commit_hash='abcdef123456789',repository='widget',commit_msg='Check lengths',cve_desc='Out of bounds read',cwe_list=['CWE-125'],vulnerableMethods_before=[{'raw_code':'first()'},{'raw_code':'second()'}],vulnerableMethods_after=[{'raw_code':'fixed()'}])
    path=tmp_path/'source.json';write_json(path,[item]);client=Extraction()
    report=build_knowledge(path,tmp_path/'out.json',client,'fixture')
    assert report=={'successful':1,'failed':[]}
    assert 'first()' in client.calls[0] and 'second()' in client.calls[0]

@pytest.mark.research
def test_primevul_benchmark_identity_and_evidence_are_preserved():
    root=research_root()
    samples=list(rows(root/'data/benchmarks/primevul.jsonl.gz'))
    assert len(samples)==838 and len({s['sample_id'] for s in samples})==838
    assert len({s['pair_id'] for s in samples})==419
    assert not any(s['ground_truth_status']=='requires_review' for s in samples)

def test_parallel_run_preserves_manifest_order_and_resume(tmp_path):
    client=Client();p=Pipeline(client,Dense(),NVD(),{'sample_workers':4,'models':dict(knowledge='fixture',detector='fixture',judge='fixture')})
    samples=[dict(sample(),sample_id=str(i),pair_id=str(i//2),code_type='before' if i%2==0 else 'after') for i in range(8)]
    result=p.run(samples,tmp_path)
    assert [r['sample_id'] for r in result]==[str(i) for i in range(8)]
    assert all(r['status']=='ok' for r in result)
    calls=len(client.calls);assert p.run(samples,tmp_path)==result and len(client.calls)==calls
    from vulinstruct.io import read_json
    assert read_json(tmp_path/'progress.json')['reused']==8

@pytest.mark.parametrize('reported',['CVE-2015-7511_88e13529','CVE-2015-7511_88e135899','CVE-2015-7511_88e1389'])
def test_unique_hash_typo_repair_preserves_score_reason_and_reported_id(reported):
    class Typo:
        def ask(self,*args):return json.dumps({'scores':[{'id':reported,'score':7,'reason':'same mechanism'}]})
    kept,scores=selected_items(Typo(),'m',sample(),[{'id':'CVE-2015-7511_88e13589'}],'cases',6)
    assert kept==[{'id':'CVE-2015-7511_88e13589'}]
    assert scores==[{'id':'CVE-2015-7511_88e13589','reported_id':reported,'score':7,'reason':'same mechanism'}]

@pytest.mark.parametrize('ids',[['CVE-2015-7512_88e13529'],['CVE-2015-7511_88e13589','CVE-2015-7511_88e13599']])
def test_hash_repair_rejects_changed_cve_or_ambiguous_mapping(ids):
    class Bad:
        def ask(self,*args):
            entries=[{'id':'CVE-2015-7511_88e13529','score':7}]
            if len(ids)==2:entries.append({'id':'CVE-2015-7511_88e13519','score':8})
            return json.dumps({'scores':entries})
    with pytest.raises(ValueError,match='omitted'):
        selected_items(Bad(),'m',sample(),[{'id':i} for i in ids],'cases',6)

@pytest.mark.parametrize('repair_succeeds',[True,False])
def test_domain_format_repair_is_bounded_and_never_accepts_unsupported_refs(tmp_path,repair_succeeds):
    class TwoNVD(NVD):
        def search(self,*args,**kwargs):return {'results':[{'cve_id':'CVE-2018-1'},{'cve_id':'CVE-2018-2'}]}
    class Repair(Client):
        def ask(self,prompt,model,stage):
            if stage=='score-nvd':return '{"scores":[{"id":"CVE-2018-1","score":8},{"id":"CVE-2018-2","score":8}]}'
            if stage.startswith('domain-specifications'):
                self.calls.append((stage,prompt))
                if stage.endswith('format-repair') and repair_succeeds:return '{"specifications":[]}'
                return json.dumps({'specifications':[dict(id='AS-TEST-001',statement='Check lengths',attack_pattern='overflow',supporting_cves=['CVE-2099-1'])]})
            return super().ask(prompt,model,stage)
    client=Repair();p=Pipeline(client,Dense(),TwoNVD(),{'models':dict(knowledge='fixture',detector='fixture',judge='fixture')})
    r=p.run([sample()],tmp_path)[0]
    assert r['status']==('ok' if repair_succeeds else 'error')
    assert sum(stage.endswith('format-repair') for stage,_ in client.calls)==(1 if repair_succeeds else 2)
    if repair_succeeds:
        assert not r['knowledge']['domain_specifications']
        assert r['domain_format_repairs'][0]['error'].startswith('Recurring')

def test_judge_receives_root_cause_and_analysis_process(tmp_path):
    class LongAnalysis(Client):
        def ask(self,prompt,model,stage):
            if stage in ('detect','detect-review'):
                self.calls.append((stage,prompt))
                return 'Analysis Process:\nDetailed trigger: integer wraps BEFORE the guard.\nFinal Conclusion:\n<vulnerability_assessment><has_vulnerability>yes</has_vulnerability><suspected_root_cause>Overflow.</suspected_root_cause></vulnerability_assessment>'
            return super().ask(prompt,model,stage)
    client=LongAnalysis();p=Pipeline(client,Dense(),NVD(),{'models':dict(knowledge='m',detector='m',judge='m')})
    result=p.run([sample()],tmp_path)[0]
    assert result['status']=='ok' and result['judge_input_scope']=='stage1_reasoning'
    judge=next(prompt for stage,prompt in client.calls if stage=='judge')
    assert 'integer wraps BEFORE the guard' in judge
    assert 'Suspected Root Cause: Overflow.' in judge
    assert '<has_vulnerability>' not in result['judge_input']


def test_cli_evaluation_rejects_result_labels_that_disagree_with_manifest(tmp_path):
    from vulinstruct.cli import main
    s=sample();fixed=dict(s,sample_id='b',code_type='after',true_label=0)
    benchmark=tmp_path/'benchmark.json';result=tmp_path/'result.json'
    write_json(benchmark,[s,fixed]);write_json(result,[dict(s,true_label=0,status='ok',prediction=0),dict(fixed,status='ok',prediction=0)])
    assert main(['evaluate','--results',str(result),'--benchmark',str(benchmark),'--binary-only'])==2

def test_score_format_repairs_only_invalid_schema_and_preserves_valid_low_scores():
    class Missing:
        def __init__(self):self.calls=[]
        def ask(self,prompt,model,stage):
            self.calls.append(stage)
            if stage.endswith('format-repair'):
                return '{"scores":[{"id":"a","score":1,"reason":"unrelated"},{"id":"b","score":8,"reason":"applicable"}]}'
            return '{"scores":[{"id":"a","score":1,"reason":"unrelated"}]}'
    c=Missing();repairs=[]
    keep,scores=selected_items(c,'m',sample(),[{'id':'a'},{'id':'b'}],'cases',6,repairs=repairs)
    assert keep==[{'id':'b'}] and scores[0]['score']==1 and len(repairs)==1
    assert c.calls==['score-cases','score-cases-format-repair']
    class Valid(Missing):
        def ask(self,*args):self.calls.append(args[-1]);return '{"scores":[{"id":"a","score":1}]}'
    c=Valid();keep,_=selected_items(c,'m',sample(),[{'id':'a'}],'cases',6)
    assert not keep and c.calls==['score-cases']

@pytest.mark.parametrize('prediction',['yes','no'])
def test_every_v3_sample_gets_one_review_without_ground_truth(prediction,tmp_path):
    class Review(Client):
        def ask(self,prompt,model,stage):
            if stage in ('detect','detect-review'):
                self.calls.append((stage,prompt))
                return f'<has_vulnerability>{prediction}</has_vulnerability><suspected_root_cause>Concrete evidence.</suspected_root_cause>'
            return super().ask(prompt,model,stage)
    c=Review();p=Pipeline(c,Dense(),NVD(),{'prompt_protocol':'domain-cascade-v3','models':dict(knowledge='m',detector='m',judge='m')})
    result=p.run([sample()],tmp_path)[0]
    assert result['status']=='ok' and result['detection_draft']
    review=[prompt for stage,prompt in c.calls if stage=='detect-review']
    assert len(review)==1
    for secret in ['SECRET_GOLD','PATCH_SECRET','FIX_SECRET','CVE-2020-1']:assert secret not in review[0]

def test_output_budget_retry_is_bounded_declared_and_not_label_based():
    class Exhausted:
        def __init__(self):self.calls=[]
        def ask(self,prompt,model,stage):
            self.calls.append((prompt,stage))
            if stage=='detect':raise ValueError('Model output truncated; increase max_output_tokens')
            return '<has_vulnerability>no</has_vulnerability><suspected_root_cause>Checks hold.</suspected_root_cause>'
    c=Exhausted();p=Pipeline(c,Dense(),NVD(),{'models':dict(knowledge='m',detector='m',judge='m'),
       'stage_max_output_tokens':{'detect':10,'detect-output-retry':20}})
    text,meta=p.ask_final('fixed prompt','detector','detect')
    assert meta['retry_max_output_tokens']==20 and '<has_vulnerability>no' in text
    assert c.calls==[('fixed prompt','detect'),('fixed prompt','detect-output-retry')]
    c=Exhausted();p=Pipeline(c,Dense(),NVD(),{'models':dict(knowledge='m',detector='m',judge='m')})
    with pytest.raises(ValueError,match='truncated'):p.ask_final('fixed prompt','detector','detect')
    assert len(c.calls)==1

def test_saved_results_invalidate_when_prompt_source_changes_without_version_bump(tmp_path,monkeypatch):
    from vulinstruct import prompts
    source=tmp_path/'prompts.py';source.write_text('first implementation')
    monkeypatch.setattr(prompts,'__file__',str(source))
    c=Client();cfg={'models':dict(knowledge='m',detector='m',judge='m')};out=tmp_path/'results'
    first=Pipeline(c,Dense(),NVD(),cfg);first.run([sample()],out);count=len(c.calls)
    source.write_text('changed prompt, same declared version')
    second=Pipeline(c,Dense(),NVD(),cfg);second.run([sample()],out)
    assert first.fingerprint!=second.fingerprint and len(c.calls)>count

def test_lower_effort_fallback_requires_two_output_failures_and_preserves_prompt():
    class Long:
        def __init__(self):self.calls=[]
        def ask(self,prompt,model,stage):
            self.calls.append((prompt,stage))
            if stage!='detect-output-fallback':raise ValueError('Model output truncated; increase max_output_tokens')
            return '<has_vulnerability>yes</has_vulnerability><suspected_root_cause>Concrete finding.</suspected_root_cause>'
    c=Long();p=Pipeline(c,Dense(),NVD(),{'models':dict(knowledge='m',detector='m',judge='m'),
        'stage_max_output_tokens':{'detect':10,'detect-output-retry':20,'detect-output-fallback':10},
        'stage_request_options':{'detect-output-fallback':{'reasoning_effort':'low'}}})
    _,meta=p.ask_final('same evidence','detector','detect')
    assert [s for _,s in c.calls]==['detect','detect-output-retry','detect-output-fallback']
    assert all(t=='same evidence' for t,_ in c.calls) and meta['fallback_reasoning_effort']=='low'

@pytest.mark.parametrize('direct_error',[False,True])
def test_last_direct_output_recovery_is_bounded_and_preserves_prompt(direct_error):
    class Incomplete:
        def __init__(self): self.calls=[]
        def ask(self,prompt,model,stage):
            self.calls.append((prompt,stage))
            if stage!='detect-output-direct' or direct_error:
                raise ValueError('Model output truncated; increase max_output_tokens')
            return '<has_vulnerability>no</has_vulnerability>'
    c=Incomplete()
    p=Pipeline(c,Dense(),NVD(),{'models':{'detector':'flash'},
        'stage_max_output_tokens':{'detect':10,'detect-output-retry':20,'detect-output-fallback':10,'detect-output-direct':10},
        'stage_request_options':{'detect-output-fallback':{'reasoning_effort':'low'},'detect-output-direct':{'thinking':{'type':'disabled'}}}})
    if direct_error:
        with pytest.raises(ValueError,match='truncated'):p.ask_final('identical evidence','detector','detect')
    else:
        text,meta=p.ask_final('identical evidence','detector','detect')
        assert meta['direct_thinking']=='disabled' and '>no<' in text
    assert [s for _,s in c.calls]==['detect','detect-output-retry','detect-output-fallback','detect-output-direct']
    assert {p for p,_ in c.calls}=={'identical evidence'}

@pytest.mark.parametrize('succeeds',[True,False])
def test_direct_review_length_retry_requires_larger_declared_budget(succeeds):
    class LongReview:
        def __init__(self):self.calls=[]
        def ask(self,prompt,model,stage):
            self.calls.append((prompt,stage))
            if succeeds and stage=='detect-output-direct-retry':return 'complete final review'
            raise ValueError('Model output truncated; increase max_output_tokens')
    c=LongReview();p=Pipeline(c,Dense(),NVD(),{'models':{'detector':'flash'},
        'stage_max_output_tokens':{'detect':10,'detect-output-retry':20,'detect-output-fallback':10,'detect-output-direct':10,'detect-output-direct-retry':20},
        'stage_request_options':{'detect-output-fallback':{'reasoning_effort':'low'},'detect-output-direct':{'thinking':{'type':'disabled'}},'detect-output-direct-retry':{'thinking':{'type':'disabled'}}}})
    if succeeds:
        text,meta=p.ask_final('same full function','detector','detect')
        assert text=='complete final review' and meta['direct_retry_max_output_tokens']==20
    else:
        with pytest.raises(ValueError,match='truncated'):p.ask_final('same full function','detector','detect')
    assert len(c.calls)==5 and {q for q,_ in c.calls}=={'same full function'}
