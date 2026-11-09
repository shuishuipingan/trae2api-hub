# Locale packs

One JSON file per language. **Dropping a file in this folder adds a language to the panel's
language button** — no code change, no rebuild, no gateway restart. The folder listing *is*
the registry; `GET /i18n/manifest` scans it on every request.

File name is the language code: `en.json` → `en`, `id.json` → `id`. Only
`^[A-Za-z0-9][A-Za-z0-9._-]{1,31}\.json$` is accepted; anything else is ignored.

## The contract

Keys are **the Chinese source text, verbatim**. There is no key namespace to invent and no
registry to update. A string with no entry renders as its original Chinese — never blank,
never a raw key. That fallback is the whole point: an incomplete pack is a working pack.

```json
{
  "@locale": { "code": "en", "name": "English", "dir": "ltr", "order": 10, "version": 1 },

  "messages":  { "数据指标看板": "Analytics" },
  "patterns":  { "最近一次对话（{0}）走了 {1}：未换区": "Last call ({0}) used {1}: no switch" },
  "fragments": { " 个 Key 生效": " keys active" }
}
```

### `@locale`

| Field | Meaning |
|---|---|
| `code` | Informational — **the filename wins.** A `de.json` claiming `"code": "en"` is served and listed as `de`. |
| `name` | What the dropdown shows. Use the language's own name (`English`, `Bahasa Indonesia`), not an English translation of it: when the UI is in a language you cannot read, the native name is the only thing still findable. |
| `order` | Sort weight, ascending. Lower appears first. Missing or non-numeric → 100. |
| `dir` | `ltr` / `rtl`. |
| `version` | Integer. **The panel caches the pack in `localStorage` and this number is the only thing that invalidates it** — edit the pack without raising `version` and everyone who has already opened the panel keeps seeing the old one. Raise it on every content change. |

`zh` needs no file — it is the source language and is always listed first.

### The three tiers, and which one you want

Looked up in this order, cheapest and most reliable first:

1. **`messages`** — exact match on the whole string. Use this for anything that
   appears on its own: nav items, headings, buttons, table headers, tooltips, placeholders.
   This should be 90%+ of your file. The string on the page is tried as written, then trimmed,
   then with runs of whitespace collapsed to single spaces — so a key copied out of the HTML
   with its indentation squashed into one line still matches, and you never have to reproduce
   the source's line breaks.
2. **`fragments`** — also exact match, but for short pieces that get concatenated onto
   runtime values (`" 个 Key 生效"` → `" keys active"`). Keep leading/trailing spaces
   deliberate: they are part of the key, and the untrimmed attempt is why they can match at all.
3. **`patterns`** — for sentences built at runtime from several parts. `{0}`, `{1}` are
   capture slots matched left to right against the non-literal pieces, and **may appear in
   any order in the translation**, which is how you get correct English word order out of
   Chinese word order.

Patterns are tried in the order they appear in the file and the **first match wins**, so put
the specific source before the general one. A source that is nothing but slots (`{0}`) compiles
to "match any text" and is rejected by the suite.

A leading slot is the usual way to write an over-broad pattern by accident: `{0} 天` matches
anything ending in ` 天`, including the range label `近 7 天`, which then renders as
`近 7 days`. Put `近 {0} 天` (and any other longer shape) **above** `{0} 天` in the file.

Slot values are looked up themselves, up to two levels deep. In
`最近一次对话（{0}）走了 {1}：未换区`, `{1}` captures `国内版` and renders as `China` because
`国内版` is a key somewhere in your file — you do not have to spell every sentence out twice,
but the piece inside the slot does need an entry of its own if you want it translated.

If a sentence reads wrong, it is usually because it is built from fragments and belongs in
`patterns`, not because the lookup is broken.

### Rules the loader enforces

A pack is applied **whole or not at all** — a half-translated UI is harder to debug than an
untranslated one. The file is rejected if:

- it is not a JSON object, or a top-level tier is not an object of `string → string`;
- it is not valid UTF-8.

Rejected packs are skipped by the manifest and logged (`i18n: skipping <file> (<reason>)`),
so the panel keeps working in Chinese.

`{n}` slots must appear on both sides of a pattern entry. `{2}` in a target with no `{2}` in
its source renders as nothing.

## What is deliberately not translated

- **The log stream.** It is freeform developer prose from the backend, and it re-renders
  every 5 seconds — the highest cost, the lowest value.
- Anything inside `<code>` and `<pre>` — commands and config samples must stay copy-pasteable.
- Anything marked `class="no-i18n"` (the language dropdown itself).
- **Text the panel only displays, never owns** — model descriptions from `/v1/models`, hardware
  fingerprint lines from `/health`, agent-setup blurbs from `qoder_agents.py`. Those strings
  are not in `dashboard.html`, so a file in this folder cannot key them; they need backend-side
  work. See `docs/i18n.md` §9 for the list.

## Adding a language

1. Copy `en.json`, keep the Chinese keys untouched, translate the values.
2. Set `@locale.name` to the native name, pick an `order`, start `version` at 1.
3. Save it as `<code>.json` here. Reload the panel — it appears in the dropdown.

After that, every later edit needs a `version` bump to reach anyone who already loaded the page
once. Translate `messages` first. It is the only tier that covers the whole chrome of the app, and
a pack consisting of nothing but `messages` is already a usable UI.

`python tests/_test_i18n_packs.py` checks every pack in this folder, including the one rule that
is invisible when you get it wrong: **each `messages` key must actually occur in
`dashboard.html`**. A key that is mistranscribed by one character never matches, and the UI just
looks "not translated yet" — which is indistinguishable from an unfinished pack.
