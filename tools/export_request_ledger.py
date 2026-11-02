#!/usr/bin/env python3
"""Export an endpoint/credential-free ledger from exact cached v4 requests.

Run beside the completed private configuration. This never sends model requests.
It verifies prompt/request identities against the original transport cache and
exports token/option/model metadata, not private endpoints, keys or reasoning text.
"""
import argparse
import re
from pathlib import Path
from vulinstruct import prompts
from vulinstruct.evaluation import parse_judge
from vulinstruct.judge import JUDGE_PROTOCOL, build_judge_prompt, prepare_rationale
from vulinstruct.io import digest, read_json, rows, write_rows, write_json

p=argparse.ArgumentParser()
p.add_argument('--config',required=True);p.add_argument('--benchmark',required=True)
p.add_argument('--results',required=True);p.add_argument('--output',required=True)
a=p.parse_args();cfgpath=Path(a.config).resolve();cfg=read_json(cfgpath)
cache=Path(cfg['cache_dir']);cache=cache if cache.is_absolute() else cfgpath.parent/cache
samples={s['sample_id']:s for s in rows(a.benchmark)}
ledger=[]

def add(sid,stage,prompt,role):
    model=cfg['models'][role]
    body={'model':model,'messages':[{'role':'user','content':prompt}]}
    reasoning=bool(re.match(r'^(gpt-5|o[134])',model))
    body['max_completion_tokens' if reasoning else 'max_tokens']=cfg.get('stage_max_output_tokens',{}).get(stage,cfg.get('max_output_tokens',4096))
    if not reasoning:body['temperature']=0
    body.update(cfg.get('request_options',{}));body.update(cfg.get('stage_request_options',{}).get(stage,{}))
    h=digest({'endpoint':cfg['base_url'].rstrip('/'),'request':body})
    d=read_json(cache/(h+'.json'))
    if d['request_hash']!=h or d['request']!=body:raise ValueError('Cache request mismatch: '+sid+' '+stage)
    ledger.append(dict(sample_id=sid,stage=stage,request_hash=h,model=model,returned_model=d.get('returned_model'),
        prompt_sha256=digest(prompt),response_sha256=digest(d['response']),usage=d.get('usage'),
        thinking=body.get('thinking'),reasoning_effort=body.get('reasoning_effort'),max_output_tokens=body.get('max_tokens',body.get('max_completion_tokens')),
        finish_reason=d.get('finish_reason'),validation_error=d.get('validation_error'),
        reasoning_present=bool(d.get('reasoning_present') or d.get('reasoning_content')),response_elapsed_seconds=d.get('elapsed_seconds')))
    return d['response']

for r in rows(a.results):
    if r['status']!='ok' or r['protocol']!='domain-cascade-v4':raise ValueError('Expected complete successful v4 results')
    if r.get('judge_protocol')!=JUDGE_PROTOCOL:raise ValueError('Expected the Stage 2 judge protocol')
    sid=r['sample_id'];s=samples[sid]
    add(sid,'understand',prompts.understanding(s),'knowledge')
    add(sid,'keywords',prompts.keywords(s,r['understand']),'knowledge')
    cases=[{'id':c['case_id'],**c} for c in r['retrieval']['general']]
    specs=[];seen=set()
    for c in cases:
        for text in c['specifications']:
            h=digest(text)
            if h not in seen:seen.add(h);specs.append({'id':'spec-'+h[:20],'statement':text,'source_cve':c['cve_id']})
    groups={'cases':cases,'specifications':specs,'nvd':[{'id':c['cve_id'],**c} for c in r['retrieval']['nvd']['results']]}
    for kind,items in groups.items():
        if not items or cfg.get('thresholds',{}).get(kind,6)>10:continue
        prompt=prompts.score(s,items,kind);add(sid,'score-'+kind,prompt,'knowledge')
        for repair in r.get('score_format_repairs',{}).get(kind,[]):
            correction=(prompt+'\nPREVIOUS INVALID RESPONSE:\n'+repair['response']+'\nVALIDATION ERROR: '+repair['error']
                +'\nReturn valid JSON with each exact supplied ID once and integer scores in [1,10]. '
                 'Preserve valid relevance judgments. Correct only schema, transcription and missing entries; '
                 'do not change judgments to retain more or fewer candidates.')
            add(sid,'score-'+kind+'-format-repair',correction,'knowledge')
    if len(r['knowledge']['nvd'])>=2:
        prompt=prompts.domain_specifications(r['knowledge']['nvd']);add(sid,'domain-specifications',prompt,'knowledge')
        for repair in r.get('domain_format_repairs',[]):
            correction=(prompt+'\nPREVIOUS INVALID RESPONSE:\n'+repair['response']+'\nVALIDATION ERROR: '+repair['error']
                +'\nReturn corrected JSON. Do not invent supporting evidence. Omit unsupported specifications; an empty specifications array is valid when no recurring mechanism has two supporting retrieved CVEs.')
            add(sid,'domain-specifications-format-repair',correction,'knowledge')
    text=add(sid,'detect',prompts.detection(s,r['knowledge']),'detector')
    if r.get('detection_output_retry'):
        text=add(sid,r['detection_output_retry']['retry_stage'],prompts.detection(s,r['knowledge']),'detector')
    if r.get('detection_output_retry',{}).get('fallback_stage'):
        text=add(sid,r['detection_output_retry']['fallback_stage'],prompts.detection(s,r['knowledge']),'detector')
    if r.get('detection_output_retry',{}).get('direct_stage'):
        text=add(sid,r['detection_output_retry']['direct_stage'],prompts.detection(s,r['knowledge']),'detector')
    if r.get('detection_output_retry',{}).get('direct_retry_stage'):
        text=add(sid,r['detection_output_retry']['direct_retry_stage'],prompts.detection(s,r['knowledge']),'detector')
    if text!=r['raw_response']:raise ValueError('Detector response mismatch: '+sid)
    if r['prediction']:
        judge_input=prepare_rationale(r['raw_response'])
        judge_prompt=build_judge_prompt(s['ground_truth'],judge_input,s['code_type'])
        if r.get('judge_input')!=judge_input or r.get('judge_prompt')!=judge_prompt:
            raise ValueError('Judge input mismatch: '+sid)
        text=add(sid,'judge',judge_prompt,'judge')
        if r.get('judge_output_retry'):
            text=add(sid,r['judge_output_retry']['retry_stage'],judge_prompt,'judge')
        if r.get('judge_output_retry',{}).get('fallback_stage'):
            text=add(sid,r['judge_output_retry']['fallback_stage'],judge_prompt,'judge')
        if r.get('judge_output_retry',{}).get('direct_stage'):
            text=add(sid,r['judge_output_retry']['direct_stage'],judge_prompt,'judge')
        if r.get('judge_output_retry',{}).get('direct_retry_stage'):
            text=add(sid,r['judge_output_retry']['direct_retry_stage'],judge_prompt,'judge')
        if text!=r['judge_rationale']:raise ValueError('Judge response mismatch: '+sid)
        if parse_judge(text,s['code_type'])!=r['judge']:raise ValueError('Judge label mismatch: '+sid)
write_rows(a.output,ledger)
write_json(a.output+'.manifest.json',dict(rows=len(ledger),unique_request_hashes=len({x['request_hash'] for x in ledger}),
    detector_reasoning_count=sum(x['stage'].startswith('detect') and x['reasoning_present'] and not x['validation_error'] for x in ledger),
    judge_reasoning_count=sum(x['stage'].startswith('judge') and x['reasoning_present'] and not x['validation_error'] for x in ledger),
    returned_models=sorted({x['returned_model'] for x in ledger}),
    note='Counts include exact cache reuse. Unique request token totals are not provider-billed usage. No key, endpoint or reasoning text is exported.'))
print('Verified and exported',len(ledger),'requests')
