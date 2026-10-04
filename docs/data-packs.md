# Offline data packs

ObscuraLens answers a surprising number of analyst questions without ever
touching the network: "which vendor owns this MAC prefix?", "is `.dev` a
real TLD?", "what runs on port 3389?", "which currency does Vietnam use?".
The answers come from **data packs** -- plain-text registries shipped inside
the Python package under `obscuralens/data`, one file per registry, parsed
into typed objects on first use.

Because the packs are files inside the package they are **versioned with
the code** -- every release tag pins an exact snapshot of every registry,
and a pack fix is just a normal pull request -- and they work fully
**offline** (no database, no HTTP, no dependencies). They are also
**bundled into the desktop executable**: the PyInstaller spec collects
every `obscuralens/data/*.txt` file into the exe, so the downloadable beta
ships the same catalog as the `pip` install (see
[desktop-beta.md](desktop-beta.md)).

Related: [v5.1 release notes](v5.1.md) for the release that introduced
the catalog, [rules.md](rules.md) for the `known_pack` rule operator that
consumes these packs, and the [README](../README.md) for the general
tour.

## Contents

- [The shipped packs](#the-shipped-packs)
- [The data_catalog API](#the-data_catalog-api)
- [Usage recipes](#usage-recipes)
- [CLI recipes](#cli-recipes)
- [File formats](#file-formats)
- [Loading semantics](#loading-semantics)

## The shipped packs

Twenty packs ship today: seven that predate v5.1 and feed the email,
MAC, IMEI, IBAN and coordinates trackers, ten added in v5.1 through
the typed catalog in `obscuralens/utils/data_catalog.py`, and three v6.0
sensor packs feeding the VIN, flight and MMSI trackers. Line counts are
`wc -l` on the shipped files (comment headers and blank lines included);
the entry counts are what the catalog actually parses out of them.

### The original seven (v4/v5 era)

| Pack | Lines | Format | Consumed by |
|---|---|---|---|
| `disposable_email_domains` | 3,057 | one domain per line | `utils/data_packs.py` -> `is_disposable_email()` |
| `popular_domains` | 337 | one domain per line | `utils/data_packs.py` -> `get_popular_domains()` |
| `phishing_keywords` | 631 | one keyword per line | `utils/data_packs.py` -> `get_phishing_keywords()` |
| `oui` | 796 | `AABBCC\|Vendor` (766 vendors) | `trackers/mac_sources.py` |
| `tac` | 174 | `TAC8\|Manufacturer\|Model` (139 entries) | `trackers/imei_sources.py` |
| `iban_structures` | 159 | `CC\|length\|bank\|account\|Name` (124 countries) | `trackers/iban_sources.py` |
| `country_centroids` | 128 | `CC\|lat\|lon\|Name` (115 countries) | `trackers/coords_sources.py` |

These keep their original loaders: `utils/data_packs.py` provides the
generic `load_data_pack(name)` plus accessors for the three
keyword/domain lists, while the four structured packs are parsed by their
own tracker modules because their fields are case-sensitive or numeric.
All follow the same rules as the catalog: lazy, cached, never raise.

### The ten new packs (v5.1)

All ten are loaded through `obscuralens/utils/data_catalog.py`:

| Pack | Lines | Entries | Origin |
|---|---|---|---|
| `ports_services` | 2,684 | 2,667 | IANA port/service registry |
| `countries_iso3166` | 263 | 249 | ISO 3166-1 country codes |
| `languages_iso639` | 493 | 474 | ISO 639 language codes |
| `currencies_iso4217` | 193 | 178 | ISO 4217 currencies |
| `http_status_codes` | 83 | 63 | RFC 9110 status phrases |
| `cwe_catalog` | 175 | 161 | MITRE CWE weakness list |
| `iana_tlds` | 1,451 | 1,437 | IANA root-zone TLD list |
| `file_extensions` | 418 | 403 | curated extension registry |
| `mime_types` | 923 | 914 | curated MIME registry |
| `user_agents` | 333 | 321 | curated UA string pool |

Entry counts are the values reported by `catalog_stats()` with the shipped
files; 6,867 catalog entries in total. They are honest curation sizes,
not full upstream registries: `cwe_catalog` carries the frequently-cited
subset of MITRE's list, `iana_tlds` covers nearly the entire delegated
root zone (a few newly delegated strings may lag), and `user_agents` is a
pool of realistic modern strings rather than an exhaustive matrix.

### The four sensor packs (v6.0)

| Pack | Lines | Entries | Format | Consumed by |
|---|---|---|---|---|
| `vin_wmi` | 190 | 166 | `WMI\|Manufacturer\|Country` | `trackers/vin_sources.py` (`vin_math`), `utils/data_catalog.py` -> `wmi()` |
| `airlines_iata` | 154 | 134 | `IATA\|ICAO\|Name\|Country\|Callsign` | `trackers/flight_sources.py` (`airline_pack`), entity extraction, `utils/data_catalog.py` -> `airline()` |
| `mid_codes` | 116 | 97 | `MID\|Country` | `trackers/mmsi_sources.py` (`mid_pack`), `utils/data_catalog.py` -> `mid()` |
| `plate_formats` | 106 | 79 | `Country\|Region\|Pattern-note\|Example\|Notes` | `trackers/plate_sources.py` (`plate_pack`), `utils/data_catalog.py` -> `plate_formats()` |

The four v6.0 packs follow the original-seven pattern (own tracker-side
loader, case-sensitive fields preserved, missing file = empty, never
raise) *and* are mirrored into the typed catalog, so both the trackers and
`obscuralens data` / the rules engine's `known_pack` operator see the same
registries. Curated from the public ISO 3780 WMI allocations, the IATA
coding directory + ICAO Doc 8585 designators, the ITU-R M.1085
Annex I MID assignments and public vehicle-registration format
descriptions respectively — honest curation sizes, not the
full registries (several thousand WMIs and designators exist; the ITU MID
table runs to several hundred and is revised between WRCs).

## The data_catalog API

```python
from obscuralens.utils import data_catalog
```

Every function is module-level and **never raises** -- unknown keys return
`None`, junk input returns `None` / `[]` / `False` / `''`, and a missing
pack behaves like an empty one. Results are dataclass instances or lists
of them:

| Type | Fields |
|---|---|
| `Country` | `code`, `code3`, `numeric`, `name`, `capital` |
| `PortEntry` | `port`, `protocol`, `service`, `description` |
| `Language` | `code`, `name` |
| `Currency` | `code`, `numeric`, `minor_units`, `name` |
| `HttpStatus` | `code`, `phrase`, `category` |
| `Cwe` | `cwe_id`, `name` |
| `FileExtension` | `ext`, `category`, `description` |
| `MimeType` | `mime`, `extension`, `description` |
| `UserAgent` | `family`, `platform`, `string` |
| `WmiEntry` | `wmi`, `manufacturer`, `country` |
| `Airline` | `iata`, `icao`, `name`, `country`, `callsign` |
| `MidEntry` | `mid`, `country` |
| `CatalogStats` | `name`, `entries`, `loaded` |

### Countries, languages and currencies (ISO registries)

| Function | Description |
|---|---|
| `country(code)` | Look up a country by alpha-2 or alpha-3 code, case-insensitive; `None` when unknown. |
| `search_countries(query)` | Countries whose name contains the query (case-insensitive substring); empty query matches all. |
| `countries_count()` | Number of parsed country entries (0 when the pack is missing). |
| `language(code)` | Look up a language by its two- or three-letter code, case-insensitive. |
| `search_languages(query)` | Languages whose name **or** code contains the query. |
| `languages_count()` | Number of parsed language entries. |
| `currency(code)` | Look up a currency by its three-letter code, case-insensitive. |
| `search_currencies(query)` | Currencies whose name or code contains the query. |
| `currencies_for_country(alpha2)` | Primary currency codes for a country from the built-in map of ~80 major countries; `[]` when unmapped. |

### Ports and services (IANA)

| Function | Description |
|---|---|
| `port_service(port, protocol='tcp')` | Port registration by number and protocol (`tcp`/`udp`/`sctp`/`dccp`); `None` when unassigned. |
| `ports_for_service(name)` | Every registration using a service name, case-insensitive. |
| `service_names()` | Sorted list of the distinct service names in the pack. |
| `well_known_tcp()` | TCP registrations below 1024, in pack order. |
| `notable_registered()` | Curated registrations at or above 1024 (databases, proxies, remote access, ...). |
| `port_category(port)` | IANA range label: `well_known` (<1024), `registered` (1024-49151) or `dynamic` (>=49152); `''` for junk input. |

### HTTP statuses, CWEs and TLDs

| Function | Description |
|---|---|
| `http_status(code)` | Status entry (phrase + category) for a numeric code. |
| `http_statuses_for_category(category)` | All shipped entries for one of `informational`, `success`, `redirection`, `client_error`, `server_error`. |
| `http_status_category(code)` | Category derived purely from the hundreds digit -- needs no data pack; `None` outside 100-599. |
| `cwe(cwe_id)` | CWE entry by id, accepting `CWE-79`, `cwe-79` and `79` spellings. |
| `search_cwes(query)` | CWE entries whose id or name contains the query. |
| `cwes_count()` | Number of parsed CWE entries. |
| `is_iana_tld(tld)` | Exact membership test against the root-zone list; accepts a leading dot and any casing. |
| `iana_tlds()` | The sorted, deduplicated list of every TLD in the pack. |
| `tld_count()` | Number of TLDs in the pack. |

### Extensions, MIME types, user agents and stats

| Function | Description |
|---|---|
| `file_extension(ext)` | Extension entry (category + description); leading dot and casing are normalised away. |
| `extensions_for_category(category)` | Extension entries for one category slug (`archive`, `executable`, ...). |
| `search_extensions(query)` | Extensions whose ext, category or description contains the query. |
| `extension_category(ext)` | Just the category of an extension, or `None`. |
| `mime_for_extension(ext)` | MIME entry registered for an extension (first one seen in the pack). |
| `extension_for_mime(mime)` | Extension entry registered for a MIME type (first one seen in the pack). |
| `search_mimes(query)` | MIME entries whose mime, extension or description contains the query. |
| `mimes_count()` | Number of parsed MIME entries. |
| `random_user_agent(family=None, platform=None, seed=None)` | Draw a UA string from the pool, optionally filtered by family/platform substring; `seed` makes the draw deterministic. |
| `catalog_stats()` | One `CatalogStats` per pack (thirteen entries): name, entry count, load state. |
| `catalog_summary()` | The same data rendered as a fixed-width plain-text table. |

### v6.0 sensor registries (WMI / airlines / MID)

| Function | Description |
|---|---|
| `wmi(prefix)` | WMI entry by its 2-3 character VIN prefix, case-insensitive; `None` when the curated pack misses it. |
| `search_wmis(query)` | WMI entries whose manufacturer or country contains the query (case-insensitive). |
| `wmis_count()` | Number of parsed WMI entries. |
| `airline(code)` | Airline entry by its two-letter IATA **or** three-letter ICAO designator, case-insensitive; `None` when unknown. |
| `search_airlines(query)` | Airline entries whose name, country or callsign contains the query. |
| `airlines_count()` | Number of parsed airline entries. |
| `mid(value)` | MID entry by its three-digit code (int or str); `None` when the pack misses it. |
| `search_mids(query)` | MID entries whose country name contains the query. |
| `mids_count()` | Number of parsed MID entries. |

## Usage recipes

### Country and currency enrichment for an IP report

Attach registry context to a geolocated IP without another network call:

```python
from obscuralens.utils import data_catalog

def enrich_ip_report(country_code: str) -> dict:
    """Registry context for a geolocated IP (fully offline)."""
    country = data_catalog.country(country_code)
    if country is None:
        return {}
    currencies = data_catalog.currencies_for_country(country.code)
    money = data_catalog.currency(currencies[0]) if currencies else None
    return {
        'country': country.name,
        'country_code3': country.code3,
        'capital': country.capital,
        'currency': money.name if money else None,
    }

print(enrich_ip_report('VN'))
# {'country': 'Socialist Republic of Vietnam', 'country_code3': 'VNM',
#  'capital': 'Hanoi', 'currency': 'Vietnamese Đồng'}
```

### `is_iana_tld` as a negative-space abuse signal

A hostname whose TLD is not in the IANA root zone cannot be a normally
delegated domain -- cheap, offline and decisive:

```python
from obscuralens.utils import data_catalog

def tld_flags(hostname: str) -> list:
    tld = hostname.rsplit('.', 1)[-1] if '.' in hostname else hostname
    flags = []
    if not data_catalog.is_iana_tld(tld):
        flags.append('tld_not_in_iana_root_zone')
    elif tld in ('zip', 'mov', 'top', 'xyz'):
        flags.append('tld_commonly_abused')
    return flags

print(tld_flags('secure-login.exampletld123'))
# ['tld_not_in_iana_root_zone']
```

The test is exact membership, not a syntax check: a well-formed but
non-existent TLD fails, and punycode labels such as `xn--p1ai` pass because
they are genuinely delegated.

### Port triage with `port_category`

Classify an exposed-port list into IANA ranges and annotate the notable
ones:

```python
from obscuralens.utils import data_catalog

def triage_ports(open_ports):
    rows = []
    for number in open_ports:
        entry = data_catalog.port_service(number)
        rows.append({
            'port': number,
            'range': data_catalog.port_category(number),
            'service': entry.service if entry else None,
            'description': entry.description if entry else None,
        })
    return rows

for row in triage_ports([22, 80, 3389, 5985, 65534]):
    print(row)
# {'port': 22, 'range': 'well_known', 'service': 'ssh', ...}
# {'port': 3389, 'range': 'registered', 'service': 'rdp', ...}
# {'port': 65534, 'range': 'dynamic', 'service': None, ...}
```

A high port with a known service (5985 above is WinRM) reads very differently
from a bare number in a report, and a dynamic-range hit with no
registration deserves a note of its own.

### UA rotation for crawlers

`random_user_agent` accepts `family` and `platform` substring filters plus
a `seed` for deterministic draws -- useful both for polite rotation and for
reproducible tests:

```python
from obscuralens.utils import data_catalog

def polite_headers(session_id: int) -> dict:
    ua = data_catalog.random_user_agent(family='Chrome', seed=session_id)
    return {'User-Agent': ua}

# deterministic: the same seed always yields the same string
assert data_catalog.random_user_agent(seed=42) == \
    data_catalog.random_user_agent(seed=42)
```

When the filters match nothing the draw falls back to the unfiltered pool;
when the pack itself is missing, a safe Chrome-on-Windows constant is
returned -- callers always get a usable string.

### CWE enrichment for CVE reports

Expand the CWE references a CVE carries into human-readable names:

```python
from obscuralens.utils import data_catalog

def cwe_names(references) -> list:
    names = []
    for ref in references:
        entry = data_catalog.cwe(ref)          # accepts 'CWE-79' or '79'
        if entry is not None:
            names.append((entry.cwe_id, entry.name))
    return names

print(cwe_names(['CWE-79', 'CWE-352']))
# [('CWE-79', "Improper Neutralization of Input During Web Page Generation
#   ('Cross-site Scripting')"), ('CWE-352', 'Cross-Site Request Forgery (CSRF)')]
```

## CLI recipes

The `obscuralens data` family wraps the catalog for shell use; every query
prints a table and exits 0 on a hit:

```text
obscuralens data country US          # ISO 3166 lookup; non-code input searches names
obscuralens data port 22              # IANA registration; --protocol udp switches transport
obscuralens data tld com              # root-zone membership check (abuse signal on miss)
obscuralens data cwe CWE-79           # CWE name lookup; bare '79' also accepted
obscuralens data status 429           # RFC 9110 phrase + category
obscuralens data ua --family Chrome --seed 3   # deterministic UA draw; --platform filters too
obscuralens data mime json            # MIME mapping for an extension
obscuralens data stats                # per-pack entry counts and load states
```

A miss is honest: `data tld notarealtld` prints that the TLD is **not** in
the IANA list (flagging it as a possible abuse signal) and exits 1, and
`data port` on an unassigned port reports the IANA range it falls in.
`data stats` prints exactly what `catalog_summary()` renders -- the table
above, plus a totals row (6,867 entries, 10/10 packs loaded).

## File formats

Every pack is UTF-8 plain text, one entry per line, `|`-separated; `#`
lines are comments and blank lines are ignored in every pack. There is no
quoting or escaping -- a literal `|` inside a description is not
representable, which the curated descriptions avoid.

| Pack | Line format | Example line |
|---|---|---|
| `disposable_email_domains` | `domain` | `mailinator.com` |
| `popular_domains` | `domain` | `gmail.com` |
| `phishing_keywords` | `keyword` | `verify-account` |
| `oui` | `prefix\|vendor` | `000001\|Xerox Corporation` |
| `tac` | `tac\|manufacturer\|model` | `33002236\|Apple\|IPHONE 5 (2012)` |
| `iban_structures` | `cc\|length\|bank_len\|account_len\|name` | `DE\|22\|8\|10\|Germany` |
| `country_centroids` | `cc\|lat\|lon\|name` | `US\|39.8\|-98.6\|United States` |
| `ports_services` | `port/protocol\|service\|description` | `22/tcp\|ssh\|Secure Shell remote login` |
| `countries_iso3166` | `alpha2\|alpha3\|numeric\|name\|capital` | `US\|USA\|840\|United States of America\|Washington D.C.` |
| `languages_iso639` | `code\|name` | `en\|English` |
| `currencies_iso4217` | `code\|numeric\|minor_units\|name` | `USD\|840\|2\|United States Dollar` |
| `http_status_codes` | `code\|phrase\|category` | `404\|Not Found\|client_error` |
| `cwe_catalog` | `cwe-id\|name` | `CWE-79\|Improper Neutralization ...` |
| `iana_tlds` | `tld` | `dev` |
| `file_extensions` | `ext\|category\|description` | `zip\|archive\|ZIP compressed archive` |
| `mime_types` | `mime\|ext\|description` | `application/json\|json\|JSON data` |
| `user_agents` | `family\|platform\|ua-string` | `Chrome\|Windows 11\|Mozilla/5.0 ...` |
| `vin_wmi` | `wmi\|manufacturer\|country` | `1FA\|Ford\|United States` |
| `airlines_iata` | `iata\|icao\|name\|country\|callsign` | `BA\|BAW\|British Airways\|United Kingdom\|SPEEDBIRD` |
| `mid_codes` | `mid\|country` | `366\|United States` |

Two structural notes. `languages_iso639` holds two blocks -- ISO 639-1
two-letter codes first, then 639-2/639-3 three-letter codes -- separated by
comment lines; parsing is uniform across both. `user_agents` ships full UA
strings rather than templates, so a draw needs no string assembly and can
never emit a mismatched version pair.

## Loading semantics

The catalog follows the same contract as the original
`utils/data_packs.py` loader, and every point matters for the desktop exe:

- **Lazy.** Nothing is read from disk until the first query that needs a
  pack; importing `data_catalog` costs only the module import itself.
- **Memoized.** Each pack is parsed once and stored in the module-level
  `_CACHE` dict; repeated calls are dictionary lookups returning identical
  objects. Missing packs are *not* cached, so a file that appears later is
  picked up without a restart.
- **Never raises.** Missing, empty or half-corrupt packs yield empty
  results; malformed lines are skipped; missed lookups return `None` /
  `[]` / `False` / `''`; `random_user_agent()` falls back to a safe constant.
- **First occurrence wins.** When a pack contains duplicate keys (two
  registrations for one port/protocol pair, two entries mapping one
  extension), the first entry in file order is what every lookup returns.
  Curated packs are deduplicated upstream; the rule keeps a hand-edited
  pack from becoming non-deterministic.
- **Stdlib only.** `pathlib`, `typing`, `random` and `re` -- nothing else --
  so the catalog imports before any configuration exists and bundles
  cleanly into PyInstaller builds.

To add entries or fix a bad one, edit the pack file and open a pull request:
the packs are versioned artifacts, and a merged change ships with the next
release. There is deliberately no runtime override mechanism -- a report's
offline answers must be reproducible from the version tag alone.
