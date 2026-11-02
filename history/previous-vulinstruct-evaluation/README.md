# Previous VulInstruct evaluation

These previously published experimental outputs were moved from `exp/`. For the current implementation and evaluation workflow, see the [main README](../../README.md).

This directory contains the experimental outputs from our evaluation.
 
## Files
 
- **`deepseek-v3_vulinstruct_gpt_5_evaluation.json`** — Evaluation results on the PrimeVul dataset.
- **`sven.json`** — Evaluation results on the SVEN dataset.
 
## Notes
 
### PrimeVul
 
In the latest version of PrimeVul, we noticed that 32 out of 870 samples originate from different functions associated with the same CVE. During our conversion to the CORRECT data format, we did not apply any special handling for these cases. 
 
### SVEN
 
SVEN was a more recent addition to our experiments. It is another relatively well-recognized vulnerability dataset. However, since SVEN only provides code diffs and CWE labels (without richer contextual information), the CORRECT-style evaluation setup may further amplify the inherent LLM-as-a-judge risk to some extent.