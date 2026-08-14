# PII Redaction Tool

## Overview

A Python script that reads a DOCX document (Red Herring Prospectus) and produces a redacted version, replacing all personally identifiable information (PII) with realistic fake alternatives.

## Approach

**Hybrid 3-Layer Detection** — combines three complementary strategies for maximum recall:

| Layer | Method | Detects | Why |
|-------|--------|---------|-----|
| **1. Regex** | Pattern matching | Emails, phones, SSNs, credit cards, IP addresses, CIN numbers | High precision for structured PII with known formats |
| **2. spaCy NER** | `en_core_web_lg` neural model | Person names, organizations, locations/addresses | Catches names and entities in natural language context |
| **3. Curated Dictionary** | Exact string matching | Known names, companies, addresses from document analysis | Safety net for entities the NER model may miss |

**Fake Replacement via Faker** — each detected PII entity is replaced with a realistic fake alternative (not just `[REDACTED]`). The mapping is deterministic: the same entity always maps to the same fake value throughout the document, preserving readability.



## PII Types Detected

- ✅ **Full names** — via spaCy NER + curated dictionary
- ✅ **Email addresses** — via regex
- ✅ **Phone numbers** — via regex (Indian format: +91 XX XXXX XXXX)
- ✅ **Company/organization names** — via spaCy NER + curated dictionary
- ✅ **Physical/mailing addresses** — via spaCy NER + curated dictionary
- ✅ **SSNs** — via regex (XXX-XX-XXXX format)
- ✅ **Credit card numbers** — via regex
- ✅ **Dates of birth** — via context-aware pattern matching
- ✅ **IP addresses** — via regex
- ✅ **Corporate Identity Numbers (CIN)** — via regex (India-specific)

## Design Decisions & Tradeoffs

1. **Dates**: Legal/filing dates (incorporation, resolution dates) are NOT redacted since they are integral to the document's meaning. Only dates explicitly tied to individuals' DOBs would be redacted.

2. **Regulatory Bodies**: Government entities (SEBI, RBI, BSE, NSE, etc.) are NOT treated as PII since they are public institutions.

3. **Family Trusts**: Trust names ARE redacted because they are directly associated with promoter families.

4. **False Positives**: The NER model may occasionally flag generic terms ("Board", "Company") as organizations. These are filtered via an exclusion list. Some over-detection of location entities is possible.

5. **False Negatives**: The curated dictionary layer mitigates this — known person names from document analysis are always caught, even if NER misses them.

6. **Extending to new PII types**: Add a new regex pattern to `RegexDetector.PATTERNS`, a new handler in `PIIReplacer._generate_replacement()`, and optionally a new dictionary list in `DictionaryDetector`.

## Usage

```bash
# Install dependencies
pip install spacy faker python-docx
python -m spacy download en_core_web_lg

# Run the redaction
python pii_redactor.py "Red Herring Prospectus.docx"
```

## Output Files

| File | Description |
|------|-------------|
| `Red Herring Prospectus_redacted.docx` | Redacted document with all PII replaced |
| `evaluation_report.md` | Precision/recall/F1 metrics per PII type |
| `ground_truth.json` | Manually curated ground truth used for evaluation |

## Requirements

- Python 3.8+
- `python-docx` — DOCX file reading/writing
- `spacy` + `en_core_web_lg` model — Named Entity Recognition
- `faker` — Generating realistic fake PII
