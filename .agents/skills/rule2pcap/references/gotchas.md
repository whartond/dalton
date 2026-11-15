# Engine and testing gotchas

Things that make a correct-looking pcap fail to fire, fire in the wrong
place, or fire for the wrong reason. Each one cost real debugging time.
Check this list before changing the traffic.

## How Suricata inspects

- **Server data is parsed when the client ACKs it.** In IDS mode the
  stream engine hands data to the app-layer parser and to raw-stream
  inspection only once it's acknowledged. A to_client match can land on a
  later packet than the one carrying the bytes, and nothing is inspected
  if the capture stops before that ACK. Make sure every data segment is
  ACKed.
- **The raw stream is inspected in chunks** (a few KB), and the last chunk
  at flow end. If a rule depends on state set by another rule (a flowbit),
  put the matched bytes late enough that the setter has already run on an
  earlier chunk.
- **No teardown means late inspection.** Without a FIN or RST, the end of a
  flow is inspected only at flow timeout or when the pcap ends. That
  reorders alerts against rules that ran earlier. Flowsynth 1.4 emits no
  teardown; add one with `pcapkit.teardown()`.
- **Some alerts land on pseudo-packets anyway.** Rules with no content
  (a bare `byte_test`, `dsize` only) and raw-stream matches on a flow whose
  protocol wasn't recognised can alert when the stream is flushed, even
  with a proper close. The alert then has `pcap_cnt` null and a `pkt_src`
  such as "stream (flow timeout)". That's normal, not a defect.
- **The alert packet isn't the matching packet.** Because data is
  inspected when it's ACKed, or when the stream is flushed, the alert is
  usually logged on a later packet than the one carrying the bytes (an
  ACK, or the FIN exchange). The write-up records both.
- **One raw match can alert twice.** A rule whose content is on the raw
  payload (no sticky buffer) on TCP can match on the packet and again on
  the reassembled stream, so it alerts twice per flow. The same double
  counting feeds threshold and detection_filter counts: six raw-TCP
  beacons made 12 matches. Rules on app-layer buffers (`http.*`, `dns.*`,
  `tls.*`, `file.data`...) match once per transaction, so five HTTP
  requests count five.
- **Raw content plus app-layer state on to_client may never fire in IDS
  mode.** Examples are `content` with `ssl_state` or `ssl_version`. The
  state is set when the data is parsed, which is a later packet than the
  one where the raw content matched. Test with `--set stream.inline=true`.
  If it fires only that way, say plainly that the rule only fires in IPS
  (inline) mode.
- **App-layer detection needs both directions.** Rules on `http`, `tls`,
  `dns` and the like need the protocol detected, which needs a handshake
  and traffic both ways. Check `app_proto` in the eve alert, or the
  `anomaly` counts in the test output.
- **HTTP bodies are inspected only up to a limit.** `http.request_body`
  sees the first `request-body-limit` bytes (100kb in Dalton's 7.0 config
  and Suricata's default), and `file.data` on responses stops at
  `response-body-limit`. Content past the limit never matches, and junk
  padding ahead of a payload is a known evasion. React2Shell scanners pad
  by 128 KB, which hides the payload from body rules. Keep matched bytes
  inside the limit. When attack tools pad, build a padded variant, test it
  with `--expect-absent`, and confirm the cause with
  `--set app-layer.protocols.http.libhtp.default-config.request-body-limit=256kb`;
  the write-up then says the rule misses padded requests at the default
  limit.
- **libhtp merges duplicate headers.** Two `Location:` headers become one
  value in `http.header`. Match repeats in `http.header.raw`. Expect an
  `applayer:RESPONSE_HEADER_REPETITION` anomaly; it's correct, not a defect.
- **Decoders validate before setting flags.** A malformed IP option is
  rejected before `ipopts` sees it, so real exploit bytes may not fire a
  header-field rule. Say so rather than "fixing" the bytes.
- **A drop or reject rule stops inspection of the rest of its flow, even in
  IDS mode.** Later rules on that flow won't fire. Test with `alert` when
  that matters, and say you did.

## Rule dependencies

- **`flowbits:isset` with no setter.** Look for the real setter: same
  vendor, nearby sids, same flowbit name in ET. If you can't find it, write
  a stand-in setter in test.rules that sets the flowbit the way the name
  suggests, and say it's a stand-in.
- **`flowbits:noalert` rules never alert.** To test one, check
  `metadata.flowbits` on the eve event, or test a copy with `noalert`
  removed. Add the rule that uses the flowbit (`isset`) so something fires.
- **Threshold and detection_filter** need enough matches inside the window,
  tracked by the right address. Remember the double counting above.
- **Datasets, iprep, Lua and hash lists** need files the job doesn't have.
  A Dalton job can't supply them through this skill; say the rule can't be
  tested as written, and test a copy without that keyword only if the user
  agrees.
- **The rule's direction can be wrong.** Some vendor rules have the header
  or `flow` inverted relative to real traffic. The rule is canonical: build
  traffic that fires it. Note the conflict in the write-up, and ask the user
  first if that means building traffic no real attack would produce.

## Variables and the job config

- Dalton's default config sets `HOME_NET` to the RFC1918 ranges and
  `EXTERNAL_NET` to `!$HOME_NET`. Inside hosts must be RFC1918 and outside
  hosts must not be. Use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24
  for outside hosts.
- Port variables follow Suricata's defaults, e.g. `$HTTP_PORTS` is 80.
  `rule_facts.py` lists the ones a rule uses.
- Dalton rejects rules containing non-ASCII text, and gives rules with no
  sid one from 806421601 up.

## Test-harness behaviour

- **Dalton jobs run Suricata multi-threaded** (the default autofp runmode)
  unless socket control is used. Threshold alerts then land on different
  packets from run to run. For repeatable placement, test with
  `--set runmode=single`.
- **On Suricata 8, socket-control jobs (`--socket-control`) keep per-host
  threshold counters between jobs** in the agent's long-running Suricata
  ([Suricata #8603](https://redmine.openinfosecfoundation.org/issues/8603);
  7.0.17 starts each pcap fresh). Results drift with what ran before, so
  don't use socket control for threshold rules.
- **The docker runner** starts a fresh process with `--runmode single`. Ask
  the user first, as the skill says.
- **Test every engine version that's online.** Keyword support and buffer
  behaviour differ between major versions. Report each version's result
  separately.
- **Read the anomaly counts in the test output.** Unexpected `applayer:`
  anomalies usually mean the traffic is malformed, even when the rule
  fires. `stream:` anomalies would too, but Dalton's stock configs don't
  log them, so a clean result doesn't prove the TCP is right: run
  `pcap_lint.py` as well. These are known to appear on genuine traffic and can be
  accepted without changing the build:
  - `applayer:APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION` on SMTP in
    Suricata 7, and on SSLv2 sessions;
  - `applayer:RESPONSE_HEADER_REPETITION` when the response deliberately
    repeats a header.

  Anything else: find out why before shipping.
- **`smtp.mail_from`** (Suricata 8) holds the address with its angle
  brackets and stops before ESMTP parameters: for `MAIL
  FROM:<a@b.example> SIZE=698` it's `<a@b.example>`.
- **Rules with newer keywords** (`smtp.mail_from`, `from_base64` and other
  Suricata 8 additions) fail to load on older engines. `test` lists those
  engines in `not_loaded` and judges the pass on the rest.

## Debugging a rule that won't fire

Work down this list, one change at a time:

1. Run `dalton_client.py validate`. Did every engine load the rule?
2. Check `pcap_lint.py` for errors: checksums, missing handshake, sequence
   gaps.
3. Check the eve alert or flow for `app_proto`. Was the protocol detected?
4. Split the rule into one rule per condition, each with its own sid, and
   see which conditions match and on which packet (`pcap_cnt` in the test
   output). Conditions that match on different packets point to the
   inspection-timing items above.
5. Look at what the parser extracted: the eve app-layer record
   (`http`, `dns`, `tls`, `smtp`...) for the flow shows the fields the
   buffers come from. Rerun with `--dump-buffers` to get buffer dumps on
   the job's page in Dalton's web UI. They cover HTTP, DNS and TLS only,
   and aren't in the API output.
6. Try `--set stream.inline=true`, and a teardown if there isn't one.
7. Re-read the rule's modifiers: `depth`/`offset` count from the buffer
   start, `distance`/`within` from the previous match, `nocase` is
   per-content, and `startswith`/`endswith` anchor to the buffer.
