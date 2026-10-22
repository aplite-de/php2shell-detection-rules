# Detecting php2shell from web server logs

Plain-language summary of what the lab showed and how to turn it into detection.
Reproduce it with the lab in this folder (see README). Lab versions: PHP 8.4.26
(vulnerable) vs 8.4.27 (patched), Apache and nginx.

## The short version

From web server logs you can reliably catch **two things**:

1. **The attempt** - someone is sending the oddly shaped requests the attack uses.
2. **The attack biting on a still-vulnerable server** - the server was pushed into
   the exact broken state the exploit needs, and it is not patched.

What logs **cannot** tell you on their own: whether the attacker went all the way
to running their own code (full takeover). That last step needs server/endpoint
signals, not web logs. So the honest ceiling is: "high confidence the exploit
precondition fired on an unpatched server - investigate the host," not "confirmed
breach."

## What the attack looks like in the logs

The attacker sends a request that *looks like a file upload* (a "multipart" form
post) but is built to make PHP do a huge amount of work while reading it, until
PHP runs out of its memory budget and aborts the request before the page even
starts running. Then a small follow-up request tries to take advantage of the
mess that abort left behind.

In the logs that shows up as:

- **An upload-style POST that is slow and strange.** It is a multipart POST, it
  takes far longer than a normal request (we saw ~90-130 ms vs ~1-3 ms for a real
  upload), it often declares no size (sent in "chunked" mode), and it is aimed at
  ordinary PHP pages, frequently several in a burst.
- **A tiny follow-up POST** carrying an upload-progress field and a session, with
  no actual file attached.
- **The server erroring out** at the moment of that slow request (an HTTP 500, or
  a 502 behind nginx, or an empty reply).

None of these alone is proof - real uploads and real crashes exist. The value is
in the combination and the timing.

## The key signal: did it bite?

This is the useful finding. The **same request** behaves differently depending on
whether the server is patched:

- **Vulnerable server (8.4.26):** PHP runs out of memory *before the page runs*
  and writes a specific error that effectively says "ran out of memory, location
  unknown." In the lab this appeared on every run once the request was pushed hard
  enough.
- **Patched server (8.4.27):** the exact same request is shrugged off. PHP just
  notes "too many parts, ignoring the rest," answers normally (HTTP 200), and
  never runs out of memory. We confirmed this across a wide range of request
  sizes, not a lucky single point.

So **seeing that "ran out of memory, location unknown" error right after one of
these slow upload-style requests is the strongest single signal**: it means the
server is unpatched *and* the attacker drove it into the dangerous state. On a
patched server you simply won't see it.

### Two traps to avoid (false alarms)

1. **A normal application memory crash looks almost identical** - except it names
   a real file and line (for example "...in /var/www/html/report.php on line 42").
   The attack version names **no file** ("location unknown" / "Unknown on line
   0"). Key your detection on the "no file" version, or you will drown in ordinary
   app errors.
2. **Patched servers also log a "location unknown" line** - but it is a harmless
   "too many parts" *warning*, not an out-of-memory error. If you match on
   "location unknown" alone you will flag patched, healthy servers. Match on the
   *out-of-memory* wording specifically.

## How to detect it, in layers

### Layer 0 - using default logs, nothing to change

- **Apache (mod_php):** in the error log, look for the out-of-memory error that
  names no file ("...exhausted... in Unknown on line 0"), together with the
  server-worker id and client IP that Apache already records. That is the "it bit"
  signal.
- **nginx + PHP-FPM:** two places. The nginx error log shows the request failing
  oddly (a 502 described as an unexpected/garbled reply from PHP) because the PHP
  worker died mid-answer. The PHP-FPM log shows the same out-of-memory error and,
  crucially, a worker **exiting and being restarted** - an unusual event worth
  alerting on by itself.
- **Access log (the normal request log):** a burst of upload-style POSTs to
  assorted PHP pages that return 500s or empty replies, lining up in time with the
  errors above.

Limit of Layer 0: the default request log does not record request size, whether it
was an upload, or how long it took - so you lean on the error logs and timing.

### Layer 1 - add a few fields to the access log (small config change)

Add, to the request log: the content type, the declared size, whether it was
"chunked" (no size given), how long the request took, bytes received, and the
worker id. With those, the attack request stands out on its own:

- upload-style (multipart), **slow**, often **no declared size**, ending in an
  error - versus a real upload which is fast and returns 200.
- For PHP-FPM, also log **peak memory per request**: the attack requests sit right
  at the memory ceiling (we saw them pinned at the 128 MB limit) while normal
  requests use a tiny fraction.
- The worker id lets you **tie the crash to the follow-up requests** handled by
  that same worker - the pattern the second stage of the attack relies on.

## What to alert on (priority order)

1. **Highest confidence it bit:** out-of-memory error naming no file ("location
   unknown"), on Apache; or the same error plus a PHP-FPM worker exit/restart, on
   nginx. Strongly suggests an unpatched server was pushed into the vulnerable
   state. Investigate the host.
2. **Attempt in progress:** a burst of slow, upload-style POSTs (ideally with no
   declared size) to multiple PHP pages returning 500/502/empty, especially if a
   tiny upload-progress POST follows. Worth flagging even if no memory error
   appears (could be a patched server, or reconnaissance).
3. **Context that raises or lowers confidence:** is this server known-patched?
   Patched servers produce the harmless "too many parts" warning and 200s under
   the same traffic - lower priority.

## Honest limits

- **Web logs show the trigger, not the takeover.** To move from "the exploit
  precondition fired" to "the attacker ran code," you need host signals - a new
  `.php` file appearing in the web folder, or the web server/PHP process launching
  a shell. Out of scope for log-only detection; worth a sentence in the writeup.
- **The patched-vs-vulnerable difference was clear and repeatable in the lab**,
  but it is one lab, two versions, default settings. Servers with raised limits or
  unusual configs may behave differently; say so rather than over-claiming.
