# ClearPass printer ACL DNS refresh

Use **aap2** for the existing AAP2 project. **master** serves the older Tower
project; there is no `main` branch in this repository. This uses only Python's
standard library and Ansible built-ins, so no additional EE packages or
collections are required. The same script/playbook can run from Tower.

Target: ClearPass **6.11.12**, enforcement profile
**DPW-Wired-Printer-ACL-Combined**, attribute
**Radius:Cisco / Cisco-IP-Downloadable-ACL**. Enforcement profile REST GET/PATCH
support was introduced in 6.11.0.

The script resolves all A records returned for `a01.ugwdevice.net` and
`b01.ugwdevice.net`, combines and deduplicates the addresses, and replaces the
existing adjacent block of `permit tcp any host <non-RFC1918-IP> eq 443` rules.
There are currently four rules, two per name. The number of rules can change
with DNS. Removed addresses are removed from the block. No per-address mapping,
template export, or persistent state is needed.

Selection follows the user's policy constraint: **all non-RFC1918 HTTPS host
permits in this ACL belong to these two names and are adjacent**. RFC1918 means
exactly `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. If another public
HTTPS host permit is added to the same block, it would also be managed; revise
this selector before using the ACL for other public HTTPS destinations. Missing
or nonadjacent public rules cause a failure without writing. All rule text before
and after the block, all RFC1918 rules, and all other profile attributes are
preserved. ACL separators are normalized as described below. An unchanged address set causes no PATCH, even if DNS answer order
differs. New rules retain `eq 443` and the original block position.

The API can return ACL rules separated by HTML `<br>` tags. The script recognizes
`<br>`, `<br/>`, and `<br />` (case-insensitively), ordinary line endings, and HTML
breaks followed by a physical newline. **Every outgoing ACL separator is converted
to an actual LF newline before PATCH**, including separators outside the managed
block. No `<br>` tags are sent in the downloadable ACL. JSON encodes LF characters
as `\n` on the wire; decoding produces real line breaks, not literal backslash-n
text. The preview diff shows one rule per readable line.

Read-back verification normalizes the target ACL's separators for comparison,
because a GET response may render line breaks as `<br>`. Other attributes are
compared exactly. This also avoids repeatedly PATCHing an unchanged address set
just because GET returns HTML display separators.

### Repairing an ACL written by the earlier version

The earlier HTML-separator handling incorrectly preserved `<br>` tags in the
PATCH value. To rewrite the ACL with actual newlines even if the DNS addresses
have not changed, run the corrected version once with:

```yaml
clearpass_apply: true
clearpass_inspect: false
clearpass_force_update: true
```

Keep your existing `clearpass_url` and Network credential. A backup is retained
before writing. After that one run, remove `clearpass_force_update` or set it to
`false` so normal scheduled jobs only PATCH when DNS changes. Standalone runs can
use `--apply --force --backup /secure/path/new-backup.json`. A forced preview
(`clearpass_apply: false`) reports `would_change: true`; its rule diff can be empty
when the only change is the outgoing separator format.

## Credentials and first preview

In ClearPass Guest, open **Administration > API Services > API Clients** and
create an enabled **ClearPass REST API** client with **Client credentials** grant.
Its operator profile needs permission to read and update enforcement profiles.
Use the writable **publisher's HTTPS origin**.

For AAP 2.6, use the built-in **Network** credential described below; no custom
credential type is needed. For standalone use, set `CLEARPASS_URL`,
`CLEARPASS_CLIENT_ID`, and `CLEARPASS_CLIENT_SECRET` in your shell environment.
An existing `CLEARPASS_ACCESS_TOKEN` can be used instead. Credentials are passed
by environment, never command arguments. TLS certificates are verified by default. Use
`--ca-file` / `clearpass_ca_file` for an internal CA; `--insecure` /
`clearpass_insecure` explicitly disables verification for testing.

```sh
# With the environment variables above set, preview the live profile and diff.
.venv/bin/python scripts/clearpass_acl_dns.py

# Apply; the backup path must be writable and the filename must be new.
.venv/bin/python scripts/clearpass_acl_dns.py \
  --apply --backup /secure/path/profile-before-20261029T120000.json
```

Both hostname lookups must succeed, contain A records, and return only public
unicast IPv4 destinations before a PATCH can occur. The script also checks that
exactly one target attribute exists. It fetches the profile again immediately
before writing to detect concurrent attribute edits, saves the complete original
profile (mode 0600), PATCHes only the attributes field with all other attributes
preserved, and verifies the result with a final GET.

There remains a small race between the second GET and PATCH. Disable concurrent
jobs and avoid editing the profile while the job runs. A failed or timed-out
PATCH may have taken effect; inspect the live profile and backup before retrying.
The script performs no automatic rollback or write retries.

## AAP 2.6 / Tower

1. Open **Automation Execution > Infrastructure > Credentials** and create a
   credential named **ClearPass API**, with credential type **Network**.
2. Enter the ClearPass API **Client ID** as **Username** and the **Client Secret**
   as **Password**. Leave SSH keys and privilege escalation/Authorize fields empty
   or disabled. These values are API client credentials, not an interactive
   ClearPass administrator login.
3. Attach **ClearPass API** to the job template's **Credentials** field.
4. Use playbook `clearpass_printer_acl_dns.yml` and an inventory with localhost.
   Sync project branch **aap2**, which contains the script and Network credential
   support.

The built-in Network credential injects `ANSIBLE_NET_USERNAME` and
`ANSIBLE_NET_PASSWORD`; the playbook passes them to the script as
`CLEARPASS_CLIENT_ID` and `CLEARPASS_CLIENT_SECRET`. It runs locally in the EE and
calls the ClearPass HTTPS API. No SSH connection or custom injector is needed.
It uses `ansible_playbook_python`, the job's existing interpreter, so no EE rebuild
is required.

Preview extra variables:

```yaml
clearpass_url: https://YOUR_CLEARPASS_PUBLISHER
clearpass_apply: false
# clearpass_ca_file: /path/to/internal-ca.pem
```

Use the publisher's HTTPS base URL, e.g. `https://clearpass-publisher.example.com`,
with no `/tips/`, `/guest/`, or `/api` suffix. The URL goes in Extra Variables;
the secret stays in the attached Network credential.

Existing custom credentials remain supported: `CLEARPASS_URL`,
`CLEARPASS_ACCESS_TOKEN`, `CLEARPASS_CLIENT_ID`, and `CLEARPASS_CLIENT_SECRET`
environment variables, or `clearpass_access_token`, `clearpass_client_id`, and
`clearpass_client_secret` extra variables. Explicit ClearPass client variables
take precedence over `CLEARPASS_*` environment variables, which take precedence
over the Network credential. The `clearpass_url` variable may be omitted when
`CLEARPASS_URL` is injected.

After a successful preview, set `clearpass_apply: true`. Ansible check mode still
forces a preview. Disable **Enable Concurrent Jobs**. A five-minute schedule is
a starting point; choose the interval based on DNS TTL and acceptable delay.
The EE needs working DNS, HTTPS access to the publisher, and trust for its
certificate. Use the printers' DNS infrastructure where possible: regional or
rotating DNS answers can differ between clients. The script reconciles the
A records returned by its resolver; it cannot discover every address used
globally by the vendor.

When a PATCH is attempted, the complete original profile is retained in the
`clearpass_profile_before` **AAP/Tower job artifact**, including on script failure.
Restrict artifact access as appropriate for profile contents. The temporary
backup inside the EE is removed at the end. Standalone runs retain the specified
backup file. The script's JSON output contains the resolved addresses and ACL diff.

This job updates the ClearPass profile; it does not trigger CoA or bounce printer
sessions. Validate the switch's dACL caching and reauthentication behavior before
relying on immediate changes for existing sessions.

## Inspecting an ACL formatting mismatch

If the job reports that no non-RFC1918 HTTPS rules were found, it includes
`acl_diagnostics` describing the selected ACL's line endings and public-IP
contexts. These excerpts use Python `repr` so hidden characters and literal
backslash sequences are visible. The diagnostics include only the target ACL,
not other profile attributes or authentication responses.

For a dedicated read-only inspection, use these job Extra Variables:

```yaml
clearpass_url: https://YOUR_CLEARPASS_PUBLISHER
clearpass_apply: false
clearpass_inspect: true
```

Inspection reads the profile and prints its ACL formatting. It does not resolve
DNS or write the profile, and takes precedence over `clearpass_apply`. Standalone
equivalent: `scripts/clearpass_acl_dns.py --inspect`. Remove `clearpass_inspect`
or set it to `false` to return to normal preview/apply behavior.

## References and validation

- [6.11.0 release notes: enforcement profile REST support](https://arubanetworking.hpe.com/techdocs/ClearPass/CP_ReleaseNotes_6.x.x/Content/ReleaseNotes/NewFeatures/NewFeatures-6.11.0.htm)
- [Get an enforcement profile by name](https://developer.arubanetworks.com/cppm/reference/enforcementprofilenamebynameget)
- [PATCH an enforcement profile](https://developer.arubanetworks.com/cppm/reference/enforcementprofilebyenforcement_profile_idpatch)
- [ClearPass 6.11 API clients](https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/Guest/Content/AdministrationTasks1/CreateEditAPIclient.htm)
- [AAP 2.6 built-in Network credential and injected variables](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.6/secure-ref_controller_credential_network)

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_clearpass_acl_dns.py' -v
.venv/bin/ansible-playbook -i localhost, clearpass_printer_acl_dns.yml --syntax-check
```

No live ClearPass validation has been performed. The first preview checks the
actual 6.11.12 API response and profile contents without changing policy.
