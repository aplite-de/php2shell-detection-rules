# PHP2Shell detection lab

A small, self-contained lab to reproduce the log signals the detection queries in
this repo look for. It runs four PHP setups side by side and sends the attack's
request shape at them, so you can see exactly what lands in the logs on a
vulnerable server versus a patched one.

**Detection only.** The lab drives PHP into the out-of-memory failure the attack
depends on and stops there. It does not groom memory, reuse stale state, or run any
code. It is enough to validate log-based detection, not to exploit anything. Run it
only against the containers it ships with.

See the write-up for the full analysis: https://aplite.de/research/detecting-php2shell
A plain-language summary of the results is in [`DETECTION.md`](DETECTION.md).

## What is in the box

Six containers on an isolated network with nothing exposed:

| Service | Stack | PHP |
| --- | --- | --- |
| apache-vuln | Apache + mod_php | 8.4.26 (vulnerable) |
| apache-fixed | Apache + mod_php | 8.4.27 (patched) |
| nginx-vuln + fpm-vuln | nginx + PHP-FPM | 8.4.26 (vulnerable) |
| nginx-fixed + fpm-fixed | nginx + PHP-FPM | 8.4.27 (patched) |

nginx cannot run PHP on its own, so each nginx has its own PHP-FPM container behind
it. That is why there are six containers for four setups. Edit `.env` to switch the
PHP versions (for example to the 8.5 pair).

Both log formats are set up: the stock format (Level 0) and the extended format
from this repo's `log-formats/` (Level 1). Logs are written to `logs/<service>/`.

## Requirements

Docker and Docker Compose. On macOS, Colima or Docker Desktop both work.

## Run it

```bash
./run.sh up                 # build and start the six servers
./run.sh traffic            # send every scenario at every target
./run.sh traffic --list     # list the scenarios
./run.sh clean              # wipe the logs between runs
./run.sh down               # tear everything down
```

The traffic tool sends two kinds of request: the attack shapes (a multipart POST
built to run PHP out of memory, and the upload-progress follow-up) and benign
baseline traffic (a normal browse, a real upload, and an ordinary in-script memory
crash) so you can see what separates them. Every request it sends is recorded to
`logs/markers.jsonl`.

## What to look at

After a run, compare the vulnerable and patched servers:

- `logs/apache-vuln/error.log` has the out-of-memory error that names no file
  (`... exhausted ... in Unknown on line 0`). `logs/apache-fixed/error.log` only
  has a harmless "too many parts" warning for the same request.
- `logs/nginx-vuln/error.log` has the 502 (`unexpected FastCGI record`) from the
  PHP worker dying, and `logs/fpm-vuln/fpm.log` shows the worker exiting with code
  70 and being restarted.
- The benign in-script crash names a real file (`... in /var/www/html/heavy.php on
  line 6`), which is how you tell it apart from the attack.

`DETECTION.md` walks through all of this in plain language.
