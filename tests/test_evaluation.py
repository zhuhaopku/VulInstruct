import pytest
from vulinstruct.evaluation import evaluate, parse_judge, parse_detection, effective_prediction, EvaluationError
from vulinstruct.judge import JUDGE_PROTOCOL


def row(i, pair, side, pred, judge=None):
    judge = judge or ('MATCH' if side == 'before' else 'FALSE_ALARM')
    return dict(sample_id=i, pair_id=pair, cve_id='CVE-2020-1000', code_type=side, prediction=pred, judge=judge, judge_protocol=JUDGE_PROTOCOL, status='ok')

def test_same_cve_different_functions_not_collapsed():
    data=[row('a','f1','before',1),row('b','f1','after',1,'CORRECT'),row('c','f2','before',0),row('d','f2','after',1)]
    metrics=evaluate(data)
    assert metrics['correct_pairs']['n_pairs']==2
    assert metrics['correct_pairs']['counts']=={'P-C':1,'P-V':0,'P-B':0,'P-R':1}
    assert metrics['correct_pairs']['VP-S']==0
    assert metrics['binary']['confusion_matrix']==dict(tp=1,fp=2,tn=0,fn=1)

@pytest.mark.parametrize('change',[{'judge':'ING'},{'status':'error'},{'prediction':None},{'true_label':1}])
def test_invalid_after_never_becomes_tn(change):
    a=row('a','p','before',1);b=row('b','p','after',1);b.update(change)
    with pytest.raises(EvaluationError): evaluate([a,b])

def test_coverage_and_pair_validation():
    a,b=row('a','p','before',1),row('b','p','after',0)
    for data,expected in [([a],None),([a,a],None),([a,b],['a','b','c'])]:
        with pytest.raises(EvaluationError): evaluate(data,expected)

@pytest.mark.parametrize('text',['MATCH appears in analysis, but no conclusion.', '<match_result>ING</match_result>', '<match_result>MATCH</match_result><match_result>MISMATCH</match_result>', '<match_result>MATCH</match_result><match_result>unknown</match_result>'])
def test_judge_requires_unambiguous_explicit_result(text):
    with pytest.raises(EvaluationError):parse_judge(text)

def test_structured_parsers():
    assert parse_judge('It is not a MATCH.\nFinal judgment: MISMATCH')=='MISMATCH'
    assert parse_judge('<match_result>MATCH</match_result>')=='MATCH'
    response='<has_vulnerability>yes</has_vulnerability><suspected_root_cause>unbounded copy</suspected_root_cause>'
    assert parse_detection(response)['prediction']==1
    with pytest.raises(EvaluationError):parse_detection(response+'<has_vulnerability>maybe</has_vulnerability>')

def test_binary_only_is_explicit_and_does_not_invent_judgments():
    data=[row('a','p','before',1,'NOT_RUN'),row('b','p','after',0,'NOT_RUN')]
    r=evaluate(data,require_judge=False)
    assert 'correct_lenient' not in r and r['binary']['f1']==1

def test_cli_rejects_duplicate_benchmark_ids_before_scoring(tmp_path):
    from vulinstruct.cli import main
    from vulinstruct.io import write_json
    a,b=row('a','p','before',1),row('b','p','after',0)
    write_json(tmp_path/'bench.json',[a,b,a]);write_json(tmp_path/'pred.json',[a,b])
    assert main(['evaluate','--benchmark',str(tmp_path/'bench.json'),'--results',str(tmp_path/'pred.json')])==2


@pytest.mark.parametrize('side,pred,judge,outcome', [
    ('before',1,'MATCH','tp'), ('before',1,'MISMATCH','fn'),
    ('before',0,'NOT_NEEDED','fn'), ('after',0,'NOT_NEEDED','tn'),
    ('after',1,'FALSE_ALARM','fp'), ('after',1,'CORRECT','tn'),
])
def test_appendix_a_lenient_outcomes(side,pred,judge,outcome):
    from vulinstruct.evaluation import confusion
    labels=[(int(side=='before'),effective_prediction(row('a','p',side,pred,judge)))]
    assert confusion(labels)['confusion_matrix']=={k:int(k==outcome) for k in ('tp','fp','tn','fn')}


@pytest.mark.parametrize('side,wrong', [('before','FALSE_ALARM'),('before','CORRECT'),
                                      ('after','MATCH'),('after','MISMATCH')])
def test_judge_labels_must_belong_to_the_sample_side(side,wrong):
    with pytest.raises(EvaluationError):parse_judge('Final judgment: '+wrong,side)
    with pytest.raises(EvaluationError):effective_prediction(row('a','p',side,1,wrong))


@pytest.mark.parametrize('side,label', [('before','MATCH'),('before','MISMATCH'),
                                      ('after','FALSE_ALARM'),('after','CORRECT')])
def test_stage2_plain_markdown_and_tagged_conclusions(side,label):
    for text in [label, 'Final judgment: '+label, '**Final Judgment**: **'+label+'**',
                 'Final answer: "'+label+'".', '<match_result>'+label+'</match_result>']:
        assert parse_judge(text,side)==label


def test_metrics_reject_mixed_judge_protocols():
    records=[row('a','p','before',1),row('b','p','after',0)]
    records[1].pop('judge_protocol')
    with pytest.raises(EvaluationError,match='protocols'):evaluate(records)


def test_explicit_judge_conclusion_can_precede_explanation_or_use_verdict_heading():
    assert parse_judge('CORRECT\n\nThe reported issue is unrelated to the fixed vulnerability.', 'after')=='CORRECT'
    assert parse_judge('The explanation describes a different mechanism.\n\n**Verdict: MISMATCH**', 'before')=='MISMATCH'


@pytest.mark.parametrize('text', [
    'MATCH\n\nFinal judgment: MISMATCH',
    '<match_result>CORRECT</match_result>\nVerdict: FALSE_ALARM',
])
def test_conflicting_explicit_judge_conclusions_are_rejected(text):
    with pytest.raises(EvaluationError,match='Conflicting'):parse_judge(text)
