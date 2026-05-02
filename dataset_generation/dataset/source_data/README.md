# Source Data for Dataset Generation

Input reference files used to generate BGP-Sentry evaluation datasets.
Files are prefixed with `downloaded_` (fetched from external source) or `computed_` (derived from downloaded data).

## Files

### `downloaded_caida_as_relationships_20260401.txt` (13 MB)
- **Downloaded from:** http://data.caida.org/datasets/as-relationships/serial-2/
- **Date:** April 1, 2026
- **Contents:** 79,327 unique ASes, 163,285 CP links, 564,868 peer links
- **Format:** `provider|customer|-1|source` (CP) or `peer_a|peer_b|0|source` (peering)

### `downloaded_rpki_vrps_20260418.json` (84 MB)
- **Downloaded from:** https://console.rpki-client.org/vrps.json
- **Date:** April 18, 2026
- **Contents:** 840,328 VRP entries, 58,729 unique ASes, 730,808 unique prefixes
- **Format:** Full ROA details: `{"asn", "prefix", "maxLength", "ta", "expires"}`

### `computed_rpki_unique_asns_20260417.json` (664 KB)
- **Computed from:** `downloaded_rpki_vrps_20260418.json` (deduplicated ASN extraction)
- **Date:** April 17, 2026
- **Contents:** 58,721 unique ASes with at least one validated ROA
- **Format:** JSON with `rpki_asns` list

## How to update

1. **CAIDA:** `curl -O http://data.caida.org/datasets/as-relationships/serial-2/YYYYMMDD.as-rel2.txt.bz2 && bunzip2 -k *.bz2`
2. **VRPs:** `curl -o downloaded_rpki_vrps_YYYYMMDD.json https://console.rpki-client.org/vrps.json`
3. **Unique ASNs:** Extract from VRPs:
   ```python
   import json
   d = json.load(open("downloaded_rpki_vrps_YYYYMMDD.json"))
   asns = sorted(set(r["asn"] for r in d["roas"]))
   json.dump({"rpki_asns": asns, "rpki_asn_count": len(asns),
              "source": "rpki-client.org/vrps.json", "date": "YYYY-MM-DD",
              "total_roas": len(d["roas"])}, open("computed_rpki_unique_asns_YYYYMMDD.json", "w"), indent=2)
   ```
