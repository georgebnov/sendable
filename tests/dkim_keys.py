"""Real DKIM public keys, as a DNS record publishes them.

Every value below is the `p=` tag of a key generated with openssl, so the tests
read bytes a sender really publishes rather than bytes someone wrote by hand.

`spki_*` is a SubjectPublicKeyInfo, which is what `openssl rsa -pubout` writes
and what most senders publish. `bare_*` is the bare RSAPublicKey that strict
RFC 6376 asks for. A verifier accepts both, so the audit reads both.

These are fixed constants rather than keys built at test time, so the suite
needs no cryptography library to run.
"""

from __future__ import annotations

# Real keys, generated with openssl. Each one is a p= tag value as a
# DNS record publishes it.
KEYS = {
    "spki_1024": (
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1n3ojQZYKcNLolDrJcgElO9mGRUGgZ+6l"
        "Fueon7GFcr2PEuWsZKysE+Atc8amJKf1n5GOBSkT9Ch6lvQ1RlS9R2O6FLujkrTrEzv8IT7E"
        "e58EFCZR3ielosjek0hJLP/NbcTvreYqM7rGnU/XaH7C50zm15rkd0YTugTWMn+0lwIDAQAB"
    ),
    "spki_2048": (
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAto/8VIsrjnuapb1IauI/Eyau4JO7"
        "vYXMjXm6hzpEc8Wdfn/NuHsRZIoiOYWkAWp2BXmDMbnPD0ApDsPtuKlL2jRqClWirOcNcQuN"
        "dA/ZP1LLhClolc7NImgp6WTpt01VjN4+J6/QBH7ITIrxVUfJV2S01JhyIjnXCErpHVTzFkVn"
        "Ab/94m1tGUfYMFrtPr0DxGMIiDMGL/1kB9wBtbElcL/U8pEdANMNqJYr9jVYRniuFz6md9oT"
        "h0m7gqMgDZORWlmwy/3SYytvjHU2fpCm4M/TGOlrwE3qd+D9qwwhtbRcEsJMfosgwj45WyWa"
        "sQTH0FBQhGUSRM5c8ilfBZVzYQIDAQAB"
    ),
    "spki_4096": (
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuFfFjPKuVK6p8OkLnuWmG63fN0t3"
        "DTY2tACDNyELm/rYWlysoKJM13osnaOujpBg2vLGi44ycnqKCl9XqNipkjUl+cBUprP5ojBq"
        "w/Z3Hzg9uA41zaJeLryqZp6jPMUab19gBKePwIYwo+CaudkwJIRRUrA6SOifz6GtXK64UFFF"
        "LvXST3btDg316pl27QzWcMFoonwXFmuWSPWMP4zcIuKif+2WiqX5PTDJYFabCOvuK14eKC+5"
        "N3BU7doB7Ll3Uqox7AgRXr2mMIxCv4ccoCWiC67h1iyT3I9Pc/8XHwah2UZrSWoZQOBR19Mq"
        "QMSPaDTqWY0icq/RsvcE6EEiNqsGkjIpnDHItrHZjjQHsgru1Qi8iDwSRMU/kKXyzdhJpokO"
        "9cZLO24uqvzY/rJIM1XCxVoO5cTMo0skkqQmYiQV9beUUIGiyA+B4xxSPgDRl9pNWNP1Xc+7"
        "XimGx12/I5+mmCco+BXAtbg2bmWAQm8ND0GN21jwvSepuRuKzLtgm+r6CdI1Q4/CXj0HFFJ9"
        "RBuP7abk/a9PXLmZBnqowNI1lPWBikEkB8nyPmJkO91czDtkS+eI/YCHc6VBRag6eDrNS4EN"
        "Z/I7mtopsvg6UOKFbs7i5DcHVzBdkDnLr6K7gIeOJWnu4A5RQxD7UIl7flTIZsEbS9J6O9h+"
        "xVRpJ00CAwEAAQ=="
    ),
    "bare_1024": (
        "MIGJAoGBALWfeiNBlgpw0uiUOslyASU72YZFQaBn7qUW56ifsYVyvY8S5axkrKwT4C1zxqYk"
        "p/WfkY4FKRP0KHqW9DVGVL1HY7oUu6OStOsTO/whPsR7nwQUJlHeJ6WiyN6TSEks/81txO+t"
        "5iozusadT9dofsLnTObXmuR3RhO6BNYyf7SXAgMBAAE="
    ),
    "bare_2048": (
        "MIIBCgKCAQEAto/8VIsrjnuapb1IauI/Eyau4JO7vYXMjXm6hzpEc8Wdfn/NuHsRZIoiOYWk"
        "AWp2BXmDMbnPD0ApDsPtuKlL2jRqClWirOcNcQuNdA/ZP1LLhClolc7NImgp6WTpt01VjN4+"
        "J6/QBH7ITIrxVUfJV2S01JhyIjnXCErpHVTzFkVnAb/94m1tGUfYMFrtPr0DxGMIiDMGL/1k"
        "B9wBtbElcL/U8pEdANMNqJYr9jVYRniuFz6md9oTh0m7gqMgDZORWlmwy/3SYytvjHU2fpCm"
        "4M/TGOlrwE3qd+D9qwwhtbRcEsJMfosgwj45WyWasQTH0FBQhGUSRM5c8ilfBZVzYQIDAQAB"
    ),
    "bare_4096": (
        "MIICCgKCAgEAuFfFjPKuVK6p8OkLnuWmG63fN0t3DTY2tACDNyELm/rYWlysoKJM13osnaOu"
        "jpBg2vLGi44ycnqKCl9XqNipkjUl+cBUprP5ojBqw/Z3Hzg9uA41zaJeLryqZp6jPMUab19g"
        "BKePwIYwo+CaudkwJIRRUrA6SOifz6GtXK64UFFFLvXST3btDg316pl27QzWcMFoonwXFmuW"
        "SPWMP4zcIuKif+2WiqX5PTDJYFabCOvuK14eKC+5N3BU7doB7Ll3Uqox7AgRXr2mMIxCv4cc"
        "oCWiC67h1iyT3I9Pc/8XHwah2UZrSWoZQOBR19MqQMSPaDTqWY0icq/RsvcE6EEiNqsGkjIp"
        "nDHItrHZjjQHsgru1Qi8iDwSRMU/kKXyzdhJpokO9cZLO24uqvzY/rJIM1XCxVoO5cTMo0sk"
        "kqQmYiQV9beUUIGiyA+B4xxSPgDRl9pNWNP1Xc+7XimGx12/I5+mmCco+BXAtbg2bmWAQm8N"
        "D0GN21jwvSepuRuKzLtgm+r6CdI1Q4/CXj0HFFJ9RBuP7abk/a9PXLmZBnqowNI1lPWBikEk"
        "B8nyPmJkO91czDtkS+eI/YCHc6VBRag6eDrNS4ENZ/I7mtopsvg6UOKFbs7i5DcHVzBdkDnL"
        "r6K7gIeOJWnu4A5RQxD7UIl7flTIZsEbS9J6O9h+xVRpJ00CAwEAAQ=="
    ),
    "ed25519": ("j+pJMIIpotiweRHI2eEKhTV1Wd7W6qhT5+Z+g8uazLA="),
}
