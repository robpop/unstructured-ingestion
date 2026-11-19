# apache-syslog-custom — Wazuh Decoder for Apache Access Logs over Syslog

A custom Wazuh decoder that parses Apache-style HTTP access log entries forwarded through syslog under the program name `root`. It extracts the client IP, request timestamp, HTTP method, URL, HTTP version, status code, and response size so the events can be matched by Wazuh's built-in web rules and by your own custom rules.

## Why this decoder exists

Wazuh's stock `web-accesslog` decoder expects raw Apache/Nginx access log lines read directly from a file. When access logs are instead shipped through syslog (for example, piped through `logger` by a root-owned process), each line arrives wrapped in a syslog header such as `root[1838503]:`. The stock decoder does not account for that program name, so the events go undecoded. This decoder keys on the `root` program name and then parses the Apache access log body that follows it.

## Example input

```
Nov 19 10:15:32 webhost01 root[1838503]: 203.0.113.45 - - [19/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 5123 "-" "Mozilla/5.0"
```

## Decoder

```xml
<decoder name="apache-syslog-custom">

  <!-- Identify this as an HTTP access log -->
  <type>web-log</type>

  <!-- Match the syslog program name: root[1838503] -->
  <program_name type="pcre2">^root$</program_name>

  <!-- Confirm the message body resembles an Apache access log -->
  <prematch type="pcre2">^\S+ - - \[</prematch>

  <!-- Extract IP, timestamp, method, URL, HTTP version, status, and bytes -->
  <regex type="pcre2">^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)\s+(HTTP/\d+(?:\.\d+)?)"\s+(\d{3})\s+(\d+|-)(?:\s|$)</regex>

  <!-- Map the seven capture groups to Wazuh fields -->
  <order>srcip,apache.access_time,http.method,url,http.version,id,http.bytes</order>

</decoder>
```

## How it works

Matching happens in three stages. First, the predecoder parses the syslog header and the `<program_name>` element requires the program to be exactly `root`; the PID in brackets is stripped by the predecoder and does not affect the match. Second, the `<prematch>` element performs a cheap check that the message body starts with a non-space token followed by ` - - [`, which is the signature of an Apache common/combined log line with empty ident and user fields. Only messages passing both checks are handed to the full `<regex>`, which captures seven fields. The `<type>web-log</type>` setting tags decoded events with the `web-log` category, which is what Wazuh's built-in web attack and error rules (the `31100` series in `0245-web_rules.xml`) key on.

## Syntax explained

All three patterns use `type="pcre2"`, which tells Wazuh to use Perl-compatible regular expressions instead of its own simpler OS_Regex syntax.

### `<program_name type="pcre2">^root$</program_name>`

`^` anchors the match to the start of the program name and `$` anchors it to the end, so the name must be exactly `root`. Without the anchors, names like `rootkit` or `chroot` would also match.

### `<prematch type="pcre2">^\S+ - - \[</prematch>`

| Token | Meaning |
|---|---|
| `^` | Start of the message body (after the syslog header). |
| `\S+` | One or more non-whitespace characters: the client IP. |
| ` - - ` | Literal space, dash, space, dash, space: the empty ident and user fields. |
| `\[` | A literal `[`, escaped because `[` normally opens a character class. It marks the start of the timestamp. |

This is a quick filter so the full regex only runs on lines that look like access logs.

### `<regex type="pcre2">`

Each pair of parentheses `( )` is a capture group. The groups are assigned, in order, to the fields listed in `<order>`.

| Token | Meaning | Captures |
|---|---|---|
| `^` | Start of the message body. | |
| `(\S+)` | Non-whitespace characters. | 1 → `srcip` |
| `\s+-\s+-\s+` | Whitespace, a dash, whitespace, a dash, whitespace. | |
| `\[([^\]]+)\]` | A literal `[`, then one or more characters that are not `]`, then a literal `]`. | 2 → `apache.access_time` |
| `\s+"` | Whitespace, then the opening quote of the request line. | |
| `([A-Z]+)` | One or more uppercase letters. | 3 → `http.method` |
| `\s+(\S+)` | Whitespace, then non-whitespace characters. | 4 → `url` |
| `\s+(HTTP/\d+(?:\.\d+)?)"` | `HTTP/`, one or more digits, optionally a dot and more digits, then the closing quote. `(?: )` groups without capturing, and `?` makes it optional, so both `HTTP/1.1` and `HTTP/2` match. | 5 → `http.version` |
| `\s+(\d{3})` | Whitespace, then exactly three digits. | 6 → `id` (status code) |
| `\s+(\d+\|-)` | Whitespace, then either one or more digits or a single `-`. The `\|` means "or". | 7 → `http.bytes` |
| `(?:\s\|$)` | Followed by whitespace or the end of the line, so the byte count is not cut short. Anything after it, like the referer and user-agent, is ignored. | |

Quick reference for the shorthand used above: `\S` is any non-whitespace character, `\s` is any whitespace character, `\d` is a digit, `+` means one or more, `{3}` means exactly three, and `[^ ]` matches any character *not* listed inside the brackets.

## Extracted fields

| Order | Field | Example | Notes |
|---|---|---|---|
| 1 | `srcip` | `203.0.113.45` | Static field; usable in active response and GeoIP enrichment. IPv4 or IPv6. |
| 2 | `apache.access_time` | `19/Nov/2026:10:15:32 +0000` | Dynamic field; the raw Apache timestamp string. |
| 3 | `http.method` | `GET` | Dynamic field; uppercase letters only. |
| 4 | `url` | `/index.html` | Static field; the full request target including any query string. |
| 5 | `http.version` | `HTTP/1.1` | Dynamic field; matches `HTTP/1.0`, `HTTP/1.1`, `HTTP/2`, `HTTP/2.0`, etc. |
| 6 | `id` | `200` | Static field holding the HTTP status code; this is the field the built-in web rules inspect (e.g. `<id>^4</id>` for 4xx). |
| 7 | `http.bytes` | `5123` | Dynamic field; response size in bytes, or the literal `-` when no body was sent. |

The referer and user-agent of the combined log format are tolerated (the regex allows trailing content after the byte count) but are not extracted.

## Installation

1. Save the decoder to a custom decoder file on the Wazuh manager, for example `/var/ossec/etc/decoders/apache_syslog_custom_decoders.xml`. Files in `etc/decoders` are loaded by the default `<decoder_dir>` setting in `ossec.conf`.

2. Set ownership and permissions to match the other ruleset files:

   ```bash
   chown wazuh:wazuh /var/ossec/etc/decoders/apache_syslog_custom_decoders.xml
   chmod 660 /var/ossec/etc/decoders/apache_syslog_custom_decoders.xml
   ```

   On Wazuh versions before 4.3 the group is `ossec` rather than `wazuh`.

3. Validate the decoder with `wazuh-logtest` (see below) before restarting.

4. Restart the manager to load it:

   ```bash
   systemctl restart wazuh-manager
   ```

In a multi-node cluster, deploy the file on the master node; custom decoders in `etc/decoders` are synchronised to workers.

## Testing

Run the log tester on the manager and paste the example line:

```bash
/var/ossec/bin/wazuh-logtest
```

Expected decoding phase output (abbreviated):

```
**Phase 1: Completed pre-decoding.
        full event: 'Nov 19 10:15:32 webhost01 root[1838503]: 203.0.113.45 - - [19/Nov/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 5123 "-" "Mozilla/5.0"'
        timestamp: 'Nov 19 10:15:32'
        hostname: 'webhost01'
        program_name: 'root'

**Phase 2: Completed decoding.
        name: 'apache-syslog-custom'
        apache.access_time: '19/Nov/2026:10:15:32 +0000'
        http.bytes: '5123'
        http.method: 'GET'
        http.version: 'HTTP/1.1'
        id: '200'
        srcip: '203.0.113.45'
        url: '/index.html'
```

Phase 3 should show a match against a built-in web rule (for example rule `31108` for a successful request, or a `31101`-range rule for a 4xx status). Test a few edge cases as well: a `404`, a response with `-` bytes, an IPv6 client, and a request with a query string.

## Writing rules against it

Use `<decoded_as>` to scope rules to this decoder and reference the dynamic fields with `<field>`:

```xml
<group name="web,accesslog,apache_syslog_custom,">

  <rule id="100200" level="0">
    <decoded_as>apache-syslog-custom</decoded_as>
    <description>Apache access log received via syslog.</description>
  </rule>

  <rule id="100201" level="6">
    <if_sid>100200</if_sid>
    <field name="http.method" type="pcre2">^(PUT|DELETE|TRACE|CONNECT)$</field>
    <description>Uncommon HTTP method $(http.method) from $(srcip) to $(url).</description>
  </rule>

</group>
```

Place custom rules in `/var/ossec/etc/rules/local_rules.xml` or a new file in that directory, using rule IDs in the 100000–120000 range.

## Limitations

The decoder only matches when the ident and authenticated-user fields are both `-`. Requests made with HTTP authentication (for example `203.0.113.45 - alice [...]`) fail the prematch and are not decoded; widening the second `-` to `\S+` and adding a capture would cover them.

Malformed or non-HTTP request lines, such as a bare `"-"` from a dropped connection or a request missing the protocol version, do not match the regex and are skipped.

Only events whose syslog program name is exactly `root` are considered. If the forwarding process is ever renamed or tagged differently (for example `logger -t apache`), `<program_name>` must be updated to match.

`apache.access_time` is stored as text. Wazuh uses the syslog header timestamp, not this field, as the event time.

## Compatibility

Requires Wazuh 4.3 or later for `type="pcre2"` support on `<program_name>`, `<prematch>`, and `<regex>`.
