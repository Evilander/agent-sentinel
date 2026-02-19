# Responsible Open Source Plan

## Recommendation

Yes, open source this project with a staged release model.

## Why

- Defensive value increases with community review and reproducible benchmarks.
- Transparent red-team artifacts improve trust in reported resilience claims.
- Shared seed families create a common language for prompt-injection evaluation.

## Guardrails

- Keep all payloads synthetic and non-deployable.
- Prohibit publishing real target details, unauthorized exploit chains, or live-abuse automation.
- Require attribution of seed hypotheses and references in every run artifact.
- Maintain a code-of-conduct section that scopes usage to defensive testing.

## Release Phases

1. Private validation:
   - Run tournaments on internal policy variants.
   - Verify that artifact files are complete and auditable.
2. Limited beta:
   - Invite security researchers and model safety teams.
   - Collect false-positive/false-negative reports and refine metrics.
3. Public release:
   - Publish with baseline + top seed profiles, transparency manifest, and reproducibility scripts.
   - Include issue templates for new defensive seed proposals.

## Required Transparency Artifacts

- `summary.json`
- `developer_outputs.jsonl`
- `red_hat_wins.jsonl`
- `llm_review_packet.json`
- `paper_writeup.md`
- `transparency_manifest.json`

## Governance

- Changes to `top` seeds require rationale + source links.
- Policy regressions must include new regression tests before merge.
- Security disclosures should follow coordinated disclosure timelines.

