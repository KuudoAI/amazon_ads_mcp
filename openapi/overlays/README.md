# Transform Overlays — hand-authored rules that survive regeneration

## Why this directory exists

The private `.build/` pipeline regenerates `openapi/resources/*.transform.json`
from scratch. Any hand-authored `input_transform` / `arg_aliases` rules placed
in those files get wiped on the next regen — that's the root cause of the
reportId alias regression (bug.md Issue 6) shipping twice.

Overlays in this directory are:

* **Source-controlled** — checked into git and travel with every deploy.
* **Untouched by `.build/` regenerators** — they live outside `openapi/resources/`.
* **Merged at startup** by `SidecarTransformMiddleware` on top of whatever the
  regenerated transform files provide.

## File format

One overlay per OpenAPI namespace. Filename must match the spec stem:
`openapi/overlays/<Namespace>.json`.

```json
{
  "namespace": "AdsAPIv1All",
  "tool_overlays": [
    {
      "match": {"operationId": "AdsApiv1RetrieveReport"},
      "input_transform": {
        "arg_aliases": [
          {"from": "reportId", "to": "reportIds", "wrap": "list"}
        ]
      }
    }
  ]
}
```

Only the keys you want to override need to appear. The overlay merger treats
each entry as an additive `input_transform` rule for the matched operation.

## When to add an overlay

* **Singular ↔ plural aliases** for endpoints whose request body is a single-item
  array (LLMs naturally reach for the singular form). Grep the spec for
  `minItems: 1, maxItems: 1` to find candidates.
* **Default argument injection** (e.g., inferring a minCreationTime).
* **Declarative coercions** that the transform executor supports.

## When **not** to add an overlay

* Behavior better expressed in Python (complex conditionals, stateful logic).
* Anything that would run *after* the tool dispatch — `output_transform` lives
  on a different path and is tracked separately.
