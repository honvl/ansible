# ansible

## ClearPass printer ACL DNS refresh

[`clearpass_printer_acl_dns.yml`](clearpass_printer_acl_dns.yml) refreshes the
HTTPS rules for `a01.ugwdevice.net` and `b01.ugwdevice.net` in
`DPW-Wired-Printer-ACL-Combined`. It handles multiple IPv4 answers, preserves
unrelated ACL rules, and previews by default. Uses only Python's standard
library and Ansible built-ins in AAP2 or Tower.
See [setup and scheduling](docs/clearpass_printer_acl_dns.md).
