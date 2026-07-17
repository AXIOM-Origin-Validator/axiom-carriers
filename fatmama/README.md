# FATMAMA — Fast ANTIE Transport MTA/MDA Agent

`fatmama.py` is the development SMTP gateway (port 2525): route table with
hot-reload, maildir delivery, loopback simulation. It drives ANTIE's SMTP
code path end-to-end in a dev environment. Dev tool only — the production
client intake is TOT (`../tot/`). Carrier-scheme spec: YPX-019
(https://github.com/AXIOM-Origin-Validator/axiom-docs).
