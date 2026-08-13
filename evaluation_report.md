# PII Redaction — Evaluation Report

## Summary

This report evaluates the PII redaction tool against a manually curated ground truth
derived from the Red Herring Prospectus of KSH International Limited.

## Evaluation Methodology

1. **Ground Truth Creation**: Manually analyzed the document to identify all PII instances,
   categorized by type (PERSON, EMAIL, PHONE, ORGANIZATION, ADDRESS, CORPORATE_ID).
2. **Detection**: Ran the hybrid detection pipeline (regex + spaCy NER + curated dictionary).
3. **Matching**: For each ground truth entity, checked if any detected entity matched
   (using exact match or substring containment for flexibility).
4. **Metrics**: Computed precision, recall, and F1 for each PII type and overall.

## Results by PII Type

| PII Type | Precision | Recall | F1 Score | TP | FP | FN |
|----------|-----------|--------|----------|----|----|----|
| PERSON | 0.5902 | 1.0000 | 0.7423 | 36 | 25 | 0 |
| EMAIL | 1.0000 | 1.0000 | 1.0000 | 26 | 0 | 0 |
| PHONE | 0.9524 | 0.9091 | 0.9302 | 20 | 1 | 2 |
| ORGANIZATION | 0.2718 | 0.9032 | 0.4179 | 28 | 75 | 3 |
| ADDRESS | 0.1282 | 1.0000 | 0.2273 | 5 | 34 | 0 |
| CORPORATE_ID | 1.0000 | 1.0000 | 1.0000 | 4 | 0 | 0 |
| **OVERALL** | **0.4685** | **0.9597** | **0.6296** | 119 | 135 | 5 |

## Detailed Breakdown

### PERSON

**False Positives (over-detected) — sample:**
- `Appasaheb Marathe Marg`
- `Rajesh Branch`
- `Ganesh Prasad`
- `Supa Facility`
- `Karunakar N. Bhandary`
- `PAT CAGR`
- `Salil Ajay Bhargava`
- `Tara Chambers`
- `Vijay Hegde`
- `Gopal BO`

### EMAIL

*Perfect detection — no false positives or false negatives.*

### PHONE

**False Negatives (missed):**
- `+91 22 6680 5218`
- `+91 20 6680 5218`

**False Positives (over-detected) — sample:**
- `+91 22 4009 4400`

### ORGANIZATION

**False Negatives (missed):**
- `MUFG Bank Limited`
- `Bajaj Finserv Limited`
- `Kirtane Pandit & Co`

**False Positives (over-detected) — sample:**
- `the Securities and Exchange Board of India (Issue of Capital and Disclosure Requirements) Regulations`
- `the Life Insurance Companies and Pension Funds`
- `Kirtane & Pandit LLP`
- `BSE Limited`
- `Mutual Funds`
- `the Designated Stock Exchange`
- `the Foreign Exchange Management (Deposit) Regulations`
- `Business - Quality Control, Services`
- `the Securities and Exchange Board of India`
- `CG Power and Industrial Solutions Limited`

### ADDRESS

**False Positives (over-detected) — sample:**
- `WATERLOO INDUSTRIAL PARK VI PRIVATE LIMITED`
- `Lalit Muljibhai Sarvaiya`
- `Pushpakamal Apartment, Flat`
- `United States Dollars`
- `Waterloo Industrial Park V Private Limited`
- `the United States`
- `Near Akurdi Railway Station Akurdi`
- `Kanjurmarg Railway Station`
- `11/3, 11/4 and 11/5 Village Birdewadi Chakan Taluka - Khed`
- `Waterloo Industrial Park III Private Limited`

### CORPORATE_ID

*Perfect detection — no false positives or false negatives.*

## Replacement Mapping (Sample)

| Original PII | Redacted Value | Type |
|-------------|----------------|------|
| `cs.connect@kshinternational.com` | `james.anderson@example.com` | EMAIL |
| `Sarthak.malvadkar@kshinterantional.com` | `emma.thompson@example.com` | EMAIL |
| `ksh.ipo@nuvama.com` | `oliver.mitchell@example.com` | EMAIL |
| `customerservice.mb@nuvama.com` | `sophia.campbell@example.com` | EMAIL |
| `ksh@icicisecurities.com` | `william.roberts@example.com` | EMAIL |
| `customercare@icicisecurities.com` | `isabella.phillips@example.com` | EMAIL |
| `prakash.boricha@nuvama.com` | `benjamin.edwards@example.com` | EMAIL |
| `sheetal.parab@nuvama.com` | `mia.collins@example.com` | EMAIL |
| `ipo@trilegal.com` | `lucas.stewart@example.com` | EMAIL |
| `kshinternational.ipo@in.mpms.mufg.com` | `charlotte.morris@example.com` | EMAIL |
| `siddharth.jadhav@hdfcbank.com` | `henry.rogers@example.com` | EMAIL |
| `sachin.gawade@hdfcbank.com` | `amelia.reed@example.com` | EMAIL |
| `eric.bacha@hdfcbank.com` | `alexander.cooper@example.com` | EMAIL |
| `tushar.gavankar@hdfcbank.com` | `harper.morgan@example.com` | EMAIL |
| `pravin.teli2@hdfcbank.com` | `daniel.bennett@example.com` | EMAIL |
| `Ipocmg@icicibank.com` | `evelyn.brooks@example.com` | EMAIL |
| `parag.pansare@kirtanepandit.com` | `michael.watson@example.com` | EMAIL |
| `hitesh.ramani@citi.com` | `abigail.foster@example.com` | EMAIL |
| `pro@eximbankindia.in` | `david.graham@example.com` | EMAIL |
| `sharmila.joshi@indusind.com` | `emily.sullivan@example.com` | EMAIL |
| `cherag.gyara@icicibank.com` | `thomas.harrison@example.com` | EMAIL |
| `manisha.shukla@hdfcbank.com` | `sarah.russell@example.com` | EMAIL |
| `rm6.ifbpune@sbi.co.in` | `robert.palmer@example.com` | EMAIL |
| `ashishmp@federalbank.co.in` | `victoria.hayes@example.com` | EMAIL |
| `anand.soni@bajajfinserv.in` | `richard.perry@example.com` | EMAIL |
| `hingnetare@gmail.com` | `grace.richardson@example.com` | EMAIL |
| `U28129PN1979PLC141032` | `U07629GL0225RBF517675` | CORPORATE_ID |
| `U67190MH1999PTC118368` | `L61384UU4144USW521118` | CORPORATE_ID |
| `L65920MH1994PLC080618` | `U53036MD2405FJJ457830` | CORPORATE_ID |
| `L65190GJ1994PLC021012` | `U66740VT3470HXH802359` | CORPORATE_ID |
| ... | ... | ... |

## Tradeoffs and Design Decisions

1. **Dates**: Filing/incorporation dates are NOT redacted since they are integral
   to the legal document. Only dates tied to individual DOBs would be redacted.
2. **Regulatory Bodies**: Government bodies (SEBI, RBI, BSE, NSE, etc.) are NOT
   treated as PII since they are public institutions.
3. **Family Trusts**: Trust names are redacted since they are associated with
   specific promoter families and can be used for identification.
4. **CIN Numbers**: Corporate Identity Numbers are redacted as they uniquely
   identify the company (similar to SSN for organizations).
5. **Standalone Location Names**: City/state names (e.g., 'Pune', 'Mumbai') in
   isolation are NOT redacted — only full mailing addresses are redacted.
