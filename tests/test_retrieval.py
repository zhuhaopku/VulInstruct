import numpy as np
import pytest
from vulinstruct.io import write_json,read_json
from vulinstruct.retrieval import build_dense,DenseIndex,unit_vectors

class Encoder:
    identity={'model':'test-deterministic','revision':'1'}
    def encode(self,texts):
        return np.asarray([[len(t),sum(map(ord,t))%7+1] for t in texts],dtype=float)

def corpus():
    return [dict(case_id='a',cve_id='CVE-2019-1',understand='bounds',code='a()',published='2019-01-01'),dict(case_id='b',cve_id='CVE-2021-1',understand='memory',code='b()',published='2021-01-01')]

def test_dense_temporal_and_content_integrity(tmp_path):
    path=tmp_path/'corpus.json';write_json(path,corpus());enc=Encoder();out=tmp_path/'index'
    build_dense(path,out,enc)
    n=DenseIndex(out,enc)
    assert [r['case_id'] for r in n.search('memory','x()',before='2020-01-01')]==['a']
    changed=read_json(out/'corpus.json');changed[0]['understand']='tampered';write_json(out/'corpus.json',changed)
    with pytest.raises(ValueError,match='hash'):DenseIndex(out,enc)

def test_no_commit_message_as_code_no_zero_vectors(tmp_path):
    data=corpus();data[0]['code']='';data[0]['commit_msg']='Do not embed this fix description'
    path=tmp_path/'corpus.json';write_json(path,data)
    with pytest.raises(ValueError,match='missing code'):build_dense(path,tmp_path/'index',Encoder(),True)
    with pytest.raises(ValueError,match='Zero'):unit_vectors([[0,0]])

def test_wrong_encoder_identity_rejected(tmp_path):
    path=tmp_path/'corpus.json';write_json(path,corpus());enc=Encoder();out=tmp_path/'index';build_dense(path,out,enc)
    enc.identity={'model':'different-model','revision':'1'}
    with pytest.raises(ValueError,match='identity'):DenseIndex(out,enc)
