import pytest

from vulinstruct.cli import main
from vulinstruct.io import write_json
from vulinstruct.judge import JUDGE_PROTOCOL, build_judge_prompt, prepare_rationale
from test_pipeline import Client, Dense, NVD, Pipeline, sample


def response(label='yes'):
    return ('**Analysis Process**:\nAn attacker-controlled length reaches the copy.\n'
            '**Key Findings**:\nThe guard fails when n equals capacity.\n'
            '**Final Conclusion**:\n<vulnerability_assessment>'
            '<has_vulnerability>'+label+'</has_vulnerability>'
            '<suspected_root_cause>n &gt; capacity permits n == capacity.</suspected_root_cause>'
            '</vulnerability_assessment>')


def test_rationale_preserves_analysis_and_unescapes_the_root_cause():
    rationale = prepare_rationale(response())
    assert 'Suspected Root Cause: n > capacity permits n == capacity.' in rationale
    assert 'An attacker-controlled length reaches the copy.' in rationale
    assert 'The guard fails when n equals capacity.' in rationale
    assert '<has_vulnerability>' not in rationale and 'Final Conclusion' not in rationale
    raw = 'Full review without an assessment wrapper.'
    assert prepare_rationale(raw).endswith(raw)
    with pytest.raises(ValueError):prepare_rationale('')
    with pytest.raises(ValueError):prepare_rationale('<vulnerability_assessment></vulnerability_assessment>')


@pytest.mark.parametrize('protocol', ['corrected-v1','domain-cascade-v2','domain-cascade-v3','domain-cascade-v4'])
@pytest.mark.parametrize('side,label,verdict', [
    ('before','yes','MATCH'), ('before','yes','MISMATCH'),
    ('after','yes','FALSE_ALARM'), ('after','yes','CORRECT'),
    ('before','no','NOT_NEEDED'), ('after','no','NOT_NEEDED'),
])
def test_all_detection_versions_use_side_specific_stage2(protocol,side,label,verdict,tmp_path):
    class JudgeClient(Client):
        def ask(self,prompt,model,stage):
            if stage in ('detect','detect-review'):
                self.calls.append((stage,prompt))
                return response(label)
            if stage=='judge':
                self.calls.append((stage,prompt))
                return '**Final Judgment**: **'+verdict+'**'
            return super().ask(prompt,model,stage)
    client=JudgeClient()
    config={'prompt_protocol':protocol,'models':dict(knowledge='k',detector='d',judge='flash')}
    target=dict(sample(),code_type=side,true_label=int(side=='before'))
    result=Pipeline(client,Dense(),NVD(),config).run([target],tmp_path)[0]
    assert result['status']=='ok' and result['judge']==verdict
    assert result['judge_protocol']==JUDGE_PROTOCOL and result['judge_model']=='flash'
    calls=[prompt for stage,prompt in client.calls if stage=='judge']
    if label=='no':
        assert not calls and 'judge_prompt' not in result
    else:
        assert len(calls)==1 and calls[0]==result['judge_prompt']
        assert result['judge_input']==prepare_rationale(response())
        if side=='before':
            assert 'based on the vulnerable version' in calls[0]
            assert 'FALSE_ALARM' not in calls[0]
        else:
            assert 'based on the patched version' in calls[0]
            assert 'newly added line in the patch problematic' in calls[0]
        for stage,prompt in client.calls:
            if stage!='judge':
                assert all(value not in prompt for value in target['ground_truth'].values())


def test_wrong_side_or_invalid_judge_output_never_becomes_a_successful_result(tmp_path):
    class WrongSide(Client):
        def ask(self,prompt,model,stage):
            if stage=='judge':return 'Final judgment: MATCH'
            return super().ask(prompt,model,stage)
    target=dict(sample(),code_type='after',true_label=0)
    cfg={'models':dict(knowledge='k',detector='d',judge='flash')}
    result=Pipeline(WrongSide(),Dense(),NVD(),cfg).run([target],tmp_path)[0]
    assert result['status']=='error' and 'code_type' in result['error']


@pytest.mark.parametrize('change',['judge','judge_input','judge_prompt','judge_rationale','judge_protocol'])
def test_offline_evaluation_checks_recorded_stage2_evidence(tmp_path,change):
    targets=[sample(),dict(sample(),sample_id='b',code_type='after',true_label=0)]
    config={'models':dict(knowledge='k',detector='d',judge='flash')}
    records=Pipeline(Client(),Dense(),NVD(),config).run(targets,tmp_path/'run')
    benchmark=tmp_path/'benchmark.json'
    results=tmp_path/'results.json'
    write_json(benchmark,targets)
    write_json(results,records)
    args=['evaluate','--benchmark',str(benchmark),'--results',str(results)]
    assert main(args)==0
    records[1][change]='changed'
    write_json(results,records)
    assert main(args)==2


def test_judge_implementation_change_invalidates_saved_samples(tmp_path,monkeypatch):
    from vulinstruct import pipeline
    original=pipeline.file_digest
    revision=['first']
    monkeypatch.setattr(pipeline,'file_digest',lambda p:revision[0] if p.name=='judge.py' else original(p))
    client=Client()
    config={'models':dict(knowledge='k',detector='d',judge='flash')}
    first=Pipeline(client,Dense(),NVD(),config)
    first.run([sample()],tmp_path)
    count=len(client.calls)
    revision[0]='second'
    second=Pipeline(client,Dense(),NVD(),config)
    second.run([sample()],tmp_path)
    assert first.fingerprint!=second.fingerprint and len(client.calls)>count


def test_judge_rejects_missing_evidence_and_unknown_code_side():
    truth=sample()['ground_truth']
    for evidence,side in [({},'before'),(truth,'unknown')]:
        with pytest.raises(ValueError):build_judge_prompt(evidence,'Detailed findings','before' if side=='before' else side)
