import pytest
from vulinstruct.nvd import normalize, NVDIndex, build_index, timestamp
from vulinstruct.io import write_rows

def record(cid, date, text='widget buffer overflow allows an attacker', cpes=None):
    return dict(cve_id=cid,published=date,modified=None,description=text,cpes=cpes or [],cwes=[],references=[])

def index(tmp_path, records):
    source=tmp_path/'nvd.jsonl';write_rows(source,records)
    path=tmp_path/'index.sqlite';build_index(source,path)
    return NVDIndex(path)

def test_both_temporal_constraints_before_ranking(tmp_path):
    n=index(tmp_path,[record('CVE-2020-9','2020-01-01'),record('CVE-2020-10','2020-03-01'),record('CVE-2020-11','2020-01-01'),record('CVE-2019-1','2020-05-01'),record('CVE-2019-2','2020-02-01')])
    found=n.search(['buffer overflow'],'CVE-2020-10',top_k=1,max_frequency=2)
    assert len(found['results'])==1
    assert found['audit']['candidates']==2
    assert not found['audit']['keywords'][0]['discarded_as_broad']
    all_found=n.search(['buffer overflow'],'CVE-2020-10')['results']
    assert {r['cve_id'] for r in all_found}=={'CVE-2020-9','CVE-2019-2'}

def test_broad_cap_exact_boundary_and_cpe_phrases(tmp_path):
    data=[record(f'CVE-2019-{i}','2019-01-01','duplicate packets allow attack', ['cpe:2.3:a:test:foo-bar:*:*:*:*:*:*:*:*']) for i in range(1,502)]
    n=index(tmp_path,data)
    q=n.search(['foo-bar'],before='2020-01-01',max_frequency=500)
    assert not q['results'] and q['audit']['keywords'][0]['discarded_as_broad']
    assert len(n.search(['foo-bar'],before='2020-01-01',max_frequency=501)['results'])==10
    # Compare actual FTS backend with exact-scan semantics, including quotes/punctuation.
    a=n.search(['duplicate packets','foo-bar','a:"test'],before='2020-01-01',max_frequency=501)
    n.manifest['backend']='scan'
    assert n.search(['duplicate packets','foo-bar','a:"test'],before='2020-01-01',max_frequency=501)==a

def test_no_year_as_publication_fallback(tmp_path):
    n=index(tmp_path,[record('CVE-2020-1','2020-01-01')])
    with pytest.raises(ValueError,match='publication'):n.search(['widget'],'CVE-2022-1')
    with pytest.raises(ValueError):timestamp(None)

def test_normalize_old_new_full_text_nested_cpe_and_reject():
    description='A duplicate packet attack ' + 'long '*200
    old={'cve':{'CVE_data_meta':{'ID':'CVE-2020-1'},'description':{'description_data':[{'lang':'en','value':description}]},'problemtype':{'problemtype_data':[{'description':[{'value':'CWE-20'}]}]}},'publishedDate':'2020-01-01T00:00Z','configurations':{'nodes':[{'children':[{'cpe_match':[{'cpe23Uri':'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*'}]}]}]}}
    normalized=normalize(old)
    assert normalized['description']==description and normalized['cpes'] and normalized['cwes']==['CWE-20']
    new={'cve':{'id':'CVE-2020-1','published':'2020-01-01T00:00:00.000','descriptions':[{'lang':'en','value':description}],'configurations':[{'nodes':[{'cpeMatch':[{'criteria':normalized['cpes'][0]}]}]}]}}
    assert normalize(new)['cpes']==normalized['cpes']
    new['cve']['vulnStatus']='Rejected';assert normalize(new) is None
    old['cve']['description']['description_data'][0]['value']='** REJECT ** duplicate reservation';assert normalize(old) is None

def test_shared_index_uses_thread_local_read_connections(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    n=index(tmp_path,[record('CVE-2019-1','2019-01-01')])
    def query(_):return n.search(['widget'],before='2020-01-01')['results'][0]['cve_id']
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(query,range(20)))==['CVE-2019-1']*20

def test_domain_cascade_preserves_specific_component_over_long_unrelated_case(tmp_path):
    n=index(tmp_path,[record('CVE-2019-1','2019-01-01','ImageMagick property.c EXIF invalid index'),
      record('CVE-2019-2','2019-12-01','MP4v2 mp4property.cpp attacker '+ 'long '*200),
      record('CVE-2019-3','2019-12-01','ImageMagick unrelated coder attacker '+ 'long '*200)])
    q={'products':[], 'identifiers':['magick/property.c'], 'domain_terms':['EXIF']}
    a=n.search_domain(q,'ImageMagick6',before='2020-01-01',top_k=1)
    assert a['results'][0]['cve_id']=='CVE-2019-1'
    assert a['results'][0]['retrieval_tier']=='product_component'
    assert a['audit']['candidates']==2  # no mp4property.cpp substring false match
    n.manifest['backend']='scan'
    assert n.search_domain(q,'ImageMagick6',before='2020-01-01',top_k=1)==a


def test_broad_product_is_retained_and_component_matches_rank_first(tmp_path):
    n=index(tmp_path,[record(f'CVE-2019-{i}','2019-01-01',
       'Linux '+('special_parser.c packets' if i==9 else 'packets other subsystem')) for i in range(1,10)])
    q={'products':['Linux'],'identifiers':['special_parser.c'],'domain_terms':['packets']}
    a=n.search_domain(q,'linux',before='2020-01-01',max_frequency=2)
    assert len(a['results'])==9 and a['results'][0]['cve_id']=='CVE-2019-9'
    assert all(r['matched_terms']['domain']==['packets'] for r in a['results'])
    assert a['audit']['keywords'][-1]['global_pool_suppressed']


def test_domain_cascade_never_admits_target_or_later_publications(tmp_path):
    n=index(tmp_path,[record('CVE-2019-1','2020-06-01','widget module'),
       record('CVE-2020-2','2020-01-01','widget module'),
       record('CVE-2020-3','2020-01-01','widget module'),
       record('CVE-2019-2','2019-02-01','widget module')])
    a=n.search_domain({'products':['widget'],'identifiers':['module']},target_cve='CVE-2020-2')
    assert [r['cve_id'] for r in a['results']]==['CVE-2019-2']
