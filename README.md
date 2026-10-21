# hp_uploadprogress_guard

**v3.0.0, 21 October 2026.** A small PHP extension that closes the multipart path of
CVE-2026-109618 / CVE-2026-109619 on an unpatched PHP, built from the official fix now that it is
public, without rebuilding PHP and without changing anything for the applications on the host. Built
by [Hosted Power](https://www.hosted-power.com) for its own fleet, published for everyone. PHP 5.6
through 8.5; Sury, Remi, cPanel EA4, DirectAdmin CustomBuild, official Docker images.

**The fix is the official PHP release** (8.5.12, 8.4.27, 8.3.36, 8.2.35, plus the PHP team's minimal
backports for 7.4, 8.0 and 8.1). Install it as soon as your vendor ships packages. This module is for
the hours or days until then, and for the versions nobody will patch. Read the advisories:
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

What the advisories say, in one paragraph. CVE-2026-109619: the session upload-progress handler runs
on every multipart request before the request is initialised and can consume state a previous request
on the same worker left behind; PHP's own mitigation is `session.upload_progress.enabled=0`. Validated
RCE on mod_php and php-fpm. CVE-2026-109618: if PHP runs out of memory while the request is still
being set up, the engine `longjmp`s out and request shutdown runs on half-initialised state; the
advisory lists three multipart ways to get there (a body without a usable Content-Length, a flood of
part headers, a flood of empty file controls that each still produce `$_FILES` arrays). Validated RCE
on mod_php, where shutdown runs after a failed startup. v3.0.0 removes the handler, carries the fixed
parser, and makes it impossible for the parser to run out of memory in the first place.

**v3.0.0 also fixes v2.2.0 on PHP 7.0 to 7.4**, where the carried parser rejected every multipart
request (`Multipart body parts limit exceeded 0`) because it read an ini setting that only exists from
8.0.28. If you installed v2.2.0 on a 7.x host, update.

**v3.0.1** (same day): the v3.0.0 binaries for 8.2 to 8.5 were built on Debian 13 and required
`GLIBC_2.38`, so they did not load on Debian 12 or older (`PHP Startup: Unable to load dynamic library`;
PHP kept running without the guard). Every binary is now built on the oldest Debian that ships the
minor and `build.sh` refuses anything above `GLIBC_2.14`. Also in v3.0.1: requests on hosts with
`mbstring.encoding_translation=On` are handed to PHP's own parser (mbstring's multibyte hooks are
file-static and cannot be mirrored; the callback detach still applies), the 8.0 to 8.3 copies no longer
depend on `max_multipart_body_parts` existing (it was added mid-branch, so a stale 8.0.x/8.1.x/8.2.0-2
install hit the 7.x failure), the parser copies no longer export PHP's own symbol names, `mode` is
case-insensitive, any PHP newer than 8.6 counts as patched, and `cd src && phpize && ./configure && make`
works again (config.m4 picks the parser copy for the PHP it is built against).

### What it does, silently

Three things happen at process start. None of them is visible to an application: uploads, forms,
`$_POST` and `$_FILES` behave exactly as before. The only feature that disappears is
`session.upload_progress`, which browsers replaced with native upload progress a long time ago.

1. **The session upload-progress handler is taken out of the multipart parser.** The advisory for
   CVE-2026-109619 names this handler as a confirmed way for stale request state to be consumed, and
   gives `session.upload_progress.enabled=0` as the official partial mitigation. The module does the
   same thing one level lower, by removing the handler from the parser's callback pointer, so no
   `.user.ini`, `.htaccess` or `ini_set()` can switch it back on.
2. **The multipart parser runs with the official hardening.** The module carries a copy of
   `main/rfc1867.c` from the patched releases, one per PHP branch (8.2 to 8.5 from the release tags,
   7.4/8.0/8.1 from the PHP team's backport branches, 7.0 to 7.3 and 5.6 with the same changes applied
   by hand). It keeps only the two part headers PHP uses and ignores duplicates, which removes the
   header memory-amplification path of CVE-2026-109618, and it enforces `post_max_size` on the bytes
   actually read, which closes the no-Content-Length bypass (on every branch since v3.0.0; v2.2.0 had
   it on 8.2 and later only). In this copy the callback of point 1 is compiled out entirely.
3. **The parser cannot run out of memory.** This is what v3.0.0 adds, and it is the part of the
   official fix a module could not carry as-is. The patched engine answers a memory-limit failure with
   a delayed, graceful out-of-memory at the next safe point instead of a `longjmp`; the carried parser
   uses the same checkpoints the PHP team put into `rfc1867.c` (every `ZEND_HAS_OOM()` and fallible
   allocation of the patch), but behind them it asks a different question: *would this step cross
   `memory_limit`?* It compares the allocator's own figure (`zend_memory_usage(1)`, the number the limit
   check uses) with the size the client is about to make it allocate, before every new part, every
   growth of a form-field value and every header line, and keeps an eighth of the limit (at least
   4 MB) plus one allocator chunk free for request startup and the script. If a step would not fit,
   parsing stops at that checkpoint with everything cleanly released, what was parsed is dropped,
   `$_POST` and `$_FILES` are empty, the response code is 413 and one line goes to the error log. The
   engine is never asked for memory it does not have, so the `longjmp` of CVE-2026-109618 cannot start
   inside the parser. A single part header is additionally capped at 64 KB. A request is only ever
   stopped when, without the module, it would have ended in `Allowed memory size exhausted`; the default
   `post_max_size=8M` against `memory_limit=128M` never comes near the line.
4. **It steps aside on a patched PHP.** At startup the module reads `PHP_VERSION`; on 8.5.12, 8.4.27,
   8.3.36, 8.2.35 or later it leaves PHP's own parser in place. One deployment covers patched and
   unpatched hosts, and nothing has to be undone after the upgrade.

### What it cannot do

It covers the multipart path, which is the application-independent one in both advisories, and
nothing else. Both advisories are explicit that the patched release is the only complete mitigation.
Outside any module's reach: application code that reaches a fatal error or out-of-memory (the producer
of CVE-2026-109619 on php-fpm), ini diagnostics raised before request initialisation (mod_php
`php_value` in `.htaccess`, `PHP_VALUE` passed by nginx or `mod_proxy_fcgi` to php-fpm) that consume
stale error state, and PHP 8.5's `fatal_error_backtraces` (set it to 0). Until your packages are
patched, keep the advisory's advice next to this module: a conservative `post_max_size`, no
per-request ini overrides that emit a warning, no `RLIMIT_AS`/`RLIMIT_DATA`, and `pm.max_requests`
low if you can afford it. On `memory_limit=-1` the headroom guard has nothing to guard and is inert;
with the module loaded a finite `memory_limit` is fine on the multipart path, so you do not need the
advisory's `memory_limit=-1` workaround for that path.

Two implementation notes. The stop flag is one static per process, which is exact for NTS builds (all
prebuilt files); a ZTS build from source could, in theory, see a spurious 413 on a concurrent thread.
And php-fpm reads at most `CONTENT_LENGTH` bytes of body on its own, so the no-Content-Length strategy
never reaches the parser through FPM; that one is mod_php's (Apache hands the parser a chunked body
whole), and it is the strategy the advisory's confirmed exploit used.

### Install

```ini
extension=hp_uploadprogress_guard.so
```

That is the whole configuration; the defaults are the three behaviours above. Prebuilt NTS x86_64
binaries per PHP minor are in `dist/` with `SHA256SUMS`; `build.sh` rebuilds them from the official
Docker images; `src/` has the one C file and the per-branch parser copies. Verify with
`php --ri hp_uploadprogress_guard`: it reports whether the handler is detached, whether the carried
parser is active, and whether the running PHP already carries the official fix.

### Optional: emergency switch

`hp_uploadprogress_guard.mode = block` refuses every `multipart/form-data` request before PHP reads
the body (415, empty `$_POST`/`$_FILES`; `allow_ips` lists clients that are still parsed). It costs
all uploads and multipart forms, so it is only for an environment under active attack that cannot
patch yet. All settings are `PHP_INI_SYSTEM`.

* `src/`: one C file plus `config.m4`, and `src/rfc1867/` with the per-branch parser copies.
* `dist/`: prebuilt NTS x86_64 `.so` per PHP minor with `SHA256SUMS`.
* `build.sh`: rebuilds `dist/` from the official `php:<X.Y>-cli` images.
* `test/`: `oom-test.sh` + `oomclient.php` + `mem-probe.php` (the three OOM strategies of the advisory,
  without and with the module: `docker run --rm -v $PWD/dist:/out:ro -v $PWD/test:/t:ro php:8.4-cli bash /t/oom-test.sh`),
  `test-modes.sh` (parse vs block, detach), `run-builtin-server.sh`, `fcgi-probe.py`, `fcgi-lie.py`, `probe.php`.
* `ansible/`: the task files and ini templates Hosted Power deploys (Debian/Sury, cPanel EA4, DirectAdmin).

Tests, v3.0.0, 21 October 2026, official `php:<X.Y>-cli` images, built-in server with
`memory_limit=32M post_max_size=64M`. Each of the advisory's strategies reproduces the out-of-memory
bailout without the module and ends in a 413 drop with it, after which the same server serves a normal
upload: a 40 MB form field, 20 MB of continuation lines in one part header, and 150 000 empty file
controls with nested names (`Allowed memory size exhausted` without; `413 post=0 files=0` and one
`hp_uploadprogress_guard: multipart body dropped` log line with), on 8.4, 8.1, 7.4 and 5.6 in full and
on 7.0 to 7.3, 8.0, 8.2, 8.3 and 8.5 for the field and header cases. No false positives: an 8 MB field
on `memory_limit=128M` is a normal `200 post=1`, and so is a 40 MB field on `memory_limit=-1`. Normal
uploads (two fields and a 100 KB file) parse identically with and without the module on all twelve
versions. mod_php, `php:8.4-apache` (prefork, the SAPI the advisory validated its exploit on): a
chunked 40 MB body without Content-Length against `post_max_size=1M memory_limit=32M` is a startup
out-of-memory fatal (HTTP 500) without the module and a `200` with the body cut at 1 MB and the
`Actual POST length does not match Content-Length` warning with it. php-fpm, `php:8.4-fpm` with a
FastCGI client declaring `CONTENT_LENGTH=1000` and streaming 40 MB: FPM stops reading at 1000 bytes
with or without the module.

Tests, v2, 21 October 2026: parse mode behaves identically to PHP's parser on 8.4 (nested fields,
unicode, awkward filenames, file arrays, checksum of the uploaded file, malformed body); block mode
gives 415 with empty `$_POST`/`$_FILES`, urlencoded 200, GET 200, `ini_set` cannot override; builds
and loads on 5.6 to 8.5; live on cPanel EA4 (8.1 to 8.4) and DirectAdmin CustomBuild (8.2 to 8.4)
staging hosts, block mode exercised end to end on DirectAdmin (multipart 415, urlencoded 200, GET 200,
then back to parse: 200).

---

The sections below describe v1 (the detach alone) and why it was built. They are kept for the
record; read the table above for what applies now.

## Why we built it

**Timeline.** On 20 October 2026 the PHP security team pre-announced two critical vulnerabilities
(CVSS v4.0 9.2 each) with a fix release scheduled for 21 October 14:00 UTC, details withheld. During
the night technical details leaked, and a researcher who reproduced both placed them in the
session extension's upload-progress handler, the code that runs on every `multipart/form-data`
request before any application code. Reports put the affected range at every PHP release since 5.4.

**Our situation.** A managed hosting fleet with roughly 640 hosts declaring PHP, 14 distinct minor
versions from 5.4 to 8.5 side by side, about 200 hosts carrying at least one branch that is end of
life. Three platforms: Debian/Ubuntu with Sury packages, cPanel EA4, DirectAdmin CustomBuild. Several
hundred customer applications we do not control.

**Why the usual advice was not enough for us.**

* *Wait for the packages.* Supported branches would get them within hours (Sury even backports to
  7.4/8.0/8.1), but 5.6 to 7.3 never will, and panel vendors lag by days.
* *Block multipart at the web server.* Breaks every upload form, every media library, Contact Form 7
  submissions. Not an option on shared infrastructure.
* *Set `session.upload_progress.enabled = Off`.* Correct target, wrong lever: it is a per-directory
  ini setting any customer can flip back from `.user.ini`, `.htaccess` or `ini_set()`, and the
  check lives inside the vulnerable function rather than in front of it. See
  [Why this beats the ini setting](#why-this-beats-the-ini-setting).

We wanted something that makes the affected code **unreachable**, on every SAPI, for every
installed version, that customers cannot undo, that keeps uploads working, and that can be
verified per process rather than per config file. The extension does that.

## How it works

Everything below refers to the `PHP-8.3` branch of php-src; the same structure exists from 5.4 to
master.

1. The multipart parser (`main/rfc1867.c`) talks to interested extensions through one global
   function pointer, declared `NULL`:

   ```c
   PHPAPI zend_result (*php_rfc1867_callback)(unsigned int event, void *event_data, void **extra) = NULL;   /* rfc1867.c:52 */
   ```

   Every one of its seven call sites is guarded: `if (php_rfc1867_callback != NULL) { ... }`
   (rfc1867.c:759, 861, 883, 957, 1007, 1076, 1259). A `NULL` pointer means "nobody is listening",
   and the parser just parses.

2. The session extension installs its handler into that pointer at module init
   (`PHP_MINIT_FUNCTION(session)`, session.c:2901-2902):

   ```c
   php_session_rfc1867_orig_callback = php_rfc1867_callback;
   php_rfc1867_callback = php_session_rfc1867_callback;
   ```

   and takes it out again at module shutdown (session.c:2928-2932).

3. `hp_uploadprogress_guard` declares an optional module dependency on `session`
   (`ZEND_MOD_OPTIONAL("session")`), so the engine starts it *after* session. Its `MINIT` then does:

   ```c
   if (php_rfc1867_callback != NULL) {
       php_rfc1867_callback = NULL;
       hp_upg_detached = 1;
   }
   ```

   From that moment the parser's `NULL` checks skip the session extension on every multipart
   event. `php_session_rfc1867_callback` is never entered again in that process.

4. `MINFO` reports what happened, so `php --ri hp_uploadprogress_guard` (or `phpinfo()`) shows
   `rfc1867 (session.upload_progress) callback detached => yes` in the running build.

That is the whole extension. No hooks into the engine, no opcode changes, no runtime cost: the
pointer write happens once per process start.

## Effect

| | Before | After |
|---|---|---|
| File uploads, `$_FILES`, `$_POST`, multipart forms | work | work, unchanged |
| Sessions, `session_start()`, save handlers | work | work, unchanged |
| `session.upload_progress` feature (`$_SESSION["upload_progress_<name>"]` filled while a file is uploading) | works | **off**, nothing is written |
| `ini_get('session.upload_progress.enabled')`, `phpinfo()` | `1` | still `1` (the ini is untouched; see Verify) |
| Process restart needed | | php-fpm / mod_php once; cgi and cli pick it up on the next start |

The upload-progress feature is the only casualty. Browsers have reported upload progress natively
(`XMLHttpRequest.upload.onprogress`) since 2012, and every mainstream application uses that, so in
practice the feature is dormant. An application that still polls `$_SESSION` for progress simply
sees no entry: the upload itself completes normally.

## Why this beats the ini setting

`session.upload_progress.enabled = Off` is what every advisory suggests. It targets the same code,
so it is not wrong. It is weaker in four concrete ways.

**1. The ini can be re-enabled from below you; the guard cannot.**
`session.upload_progress.enabled` is declared `ZEND_INI_PERDIR` with a compiled-in default of `1`
(session.c:849-850). `PERDIR` means every per-directory layer may set it: a `.user.ini` in any
customer docroot (CGI/FastCGI), `php_flag` in `.htaccess` (mod_php), `php_value` in a pool file. An
`=Off` in `conf.d` is silently undone by one line in one site. The only ini form that locks it is
`php_admin_flag` in every FPM pool, which still leaves CLI, CGI and mod_php uncovered. The guard
writes `NULL` into a C function pointer at module init. No ini layer, no `ini_set()`, no application
code has a way to write that pointer back.

**2. The ini gate sits inside the handler; the guard sits in front of it.**
With the ini off, the parser still calls into the session extension on every multipart event, and
the handler returns early *after* consulting the flag (session.c:3103-3108: it first forwards to a
chained callback, then `if (!PS(rfc1867_enabled)) return retval;`). Any code before that check, or a
future change that moves the check, still runs. With the guard, the parser's own `NULL` test skips
the call: the session extension never sees a multipart event at all.

**3. One mechanism covers every SAPI and every installed version.**
`phpenmod -s ALL` (Debian), a `php.d` drop-in (EA4), a `php.conf.d` drop-in (CustomBuild) loads the
guard into fpm, cli, cgi and apache2 for every discovered version, including a phpMyAdmin-only one.
The ini equivalent is a mix of `php_admin_flag` per pool, `conf.d` for CLI, `php_admin_flag` in
Apache vhosts for mod_php, each with its own way to be missed.

**4. It is verifiable per process, not per config file.**
`php --ri hp_uploadprogress_guard` reports whether the callback was actually detached in the
running build, and `grep hp_uploadprogress_guard /proc/<fpm-master-pid>/maps` shows it is mapped in
the live master. An ini value only tells you what one file says, not what won after all layers were
merged.

What both approaches share: they only help if the bug is in that handler. On that point they are
equal, and that is why the "stronger" claim is limited to the mechanism, not to the coverage.

## Compatibility

* **PHP versions:** 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5 (one source file, no
  per-version patches). 5.4/5.5 build the same way; no official Docker image exists to prebuild them.
* **ABI:** a PHP extension's ABI is the Zend module API number of the minor version plus the NTS/ZTS
  flavour (checked at load time). The prebuilt files are NTS x86_64 and load on any NTS build of that
  minor: Sury, Remi, cPanel EA4, DirectAdmin CustomBuild, the official Docker images. ZTS builds need
  a rebuild from source.
* **libc:** since v2 the binaries carry the multipart parser and therefore do import versioned glibc
  symbols. They are built on the oldest Debian image that ships each minor (stretch for 5.6 to 7.3,
  buster for 7.4 to 8.1, bullseye for 8.2 to 8.4, bookworm for 8.5) and `build.sh` refuses any file
  that needs more than `GLIBC_2.14` (`objdump -T`), so they load on Debian 8+, Ubuntu 14.04+ and EL 7+.
  Do not rebuild them on a glibc 2.38+ host without that check: `strtoll` then binds to
  `__isoc23_strtoll@GLIBC_2.38` and the file refuses to load on anything older.

## Install

### Build from source (any PHP, any flavour)

```sh
cd src && phpize && ./configure && make
# -> modules/hp_uploadprogress_guard.so ; `make install` drops it in extension_dir
```

### Prebuilt

Pick `dist/hp_uploadprogress_guard-<X.Y>.so` for your minor version, verify it against
`dist/SHA256SUMS`, copy it to `php -n -r 'echo PHP_EXTENSION_DIR;'` as `hp_uploadprogress_guard.so`,
and add an ini with `extension=hp_uploadprogress_guard.so` to the scan dir of every SAPI.

### Debian / Ubuntu with Sury packages

```sh
V=8.3
install -m 0644 dist/hp_uploadprogress_guard-$V.so "$(php$V -n -r 'echo PHP_EXTENSION_DIR;')/hp_uploadprogress_guard.so"
install -m 0644 ansible/mods-available-hp_uploadprogress_guard.ini /etc/php/$V/mods-available/hp_uploadprogress_guard.ini
phpenmod -v $V -s ALL hp_uploadprogress_guard
systemctl restart php$V-fpm        # and apache2 if you run mod_php
```

### cPanel EA4

```sh
for root in /opt/cpanel/ea-php*; do
    [ -x "$root/root/usr/bin/php" ] || continue
    v=$(basename "$root" | sed -E 's/^ea-php([0-9])([0-9]+)$/\1.\2/')
    install -m 0644 "dist/hp_uploadprogress_guard-$v.so" "$root/root/usr/lib64/php/modules/hp_uploadprogress_guard.so"
    install -m 0644 ansible/20-hp_uploadprogress_guard.ini "$root/root/etc/php.d/20-hp_uploadprogress_guard.ini"
done
/scripts/restartsrv_apache_php_fpm   # cgi/lsapi SAPIs need no restart
```

### DirectAdmin CustomBuild

```sh
for bin in /usr/local/php[0-9]*/bin/php; do
    d=$(dirname "$(dirname "$bin")"); v=$(basename "$d" | sed -E 's/^php([0-9])([0-9]+)$/\1.\2/')
    install -m 0644 "dist/hp_uploadprogress_guard-$v.so" "$("$bin" -n -r 'echo PHP_EXTENSION_DIR;')/hp_uploadprogress_guard.so"
    install -m 0644 ansible/20-hp_uploadprogress_guard.ini "$d/lib/php.conf.d/20-hp_uploadprogress_guard.ini"
    systemctl restart "php-fpm${v/./}"
done
```

Re-run after a CustomBuild PHP rebuild, or hook it into `custombuild/custom/hooks/php/post/`.

### Ansible

`ansible/` holds the task files we run in production (they expect the `.so` files under
`files/uploadprogress-guard/` of a role and a `php_uploadprogress_guard_enabled` boolean for the
opt-out/teardown path). They discover installed versions on the host, so nothing is hardcoded.

## Verify

```sh
php -m | grep hp_uploadprogress_guard
php --ri hp_uploadprogress_guard          # expect: ... callback detached => yes
php-fpm8.3 -m | grep hp_uploadprogress_guard
grep -c hp_uploadprogress_guard /proc/$(systemctl show -p MainPID --value php8.3-fpm)/maps   # > 0
```

Do **not** judge by `session.upload_progress.enabled` in `phpinfo()`: it stays `On`. The guard works
underneath the ini, not through it.

End to end: put `test/probe.php` in a docroot and run `python3 test/fcgi-probe.py <fpm socket>
<path to probe.php>`. Expected: `files=1 size=200000 err=0` and `session_keys=` (empty). Without the
guard the last line reads `session_keys=upload_progress_probe`.

## Remove

Delete the ini (`phpdismod hp_uploadprogress_guard` on Debian) and the `.so`, restart php-fpm. The
Ansible task files do this when `php_uploadprogress_guard_enabled: false`.

## Tests performed (21 October 2026)

All runs below were done before the fleet rollout; outputs are verbatim.

**1. Build and load on every supported minor** (`build.sh`, official `php:<X.Y>-cli` images). Each
version printed `LOADED` and `rfc1867 (session.upload_progress) callback detached => yes`:
8.5.11, 8.4.26, 8.2.34, 8.1.34, 8.0.30, 7.4.33, 7.3.33, 7.2.34, 7.1.33, 7.0.33, 5.6.40 (8.3.35 first,
by hand).

**2. Functional test, built-in server, PHP 8.3** (`test/run-builtin-server.sh 8.3`; the probe printed `guard_loaded`/`upload_progress_ini` at the time, now `guard`/`ini`):

```
===== without guard: multipart upload WITH progress field + session cookie
guard_loaded=0  upload_progress_ini=1
post_keys=PHP_SESSION_UPLOAD_PROGRESS,name
files=1 size=300000 err=0
session_keys=upload_progress_probe
===== with guard: multipart upload WITH progress field + session cookie
guard_loaded=1  upload_progress_ini=1
post_keys=PHP_SESSION_UPLOAD_PROGRESS,name
files=1 size=300000 err=0
session_keys=
```

Same request, same ini, same upload: the progress entry disappears, nothing else changes.

**3. Binary hygiene** (`readelf --dyn-syms`, `readelf -V`): undefined symbols are
`php_rfc1867_callback`, `php_info_print_table_start/row/end`, `__cxa_finalize`, `__gmon_start__`,
`_ITM_*`. No `GLIBC_*` version requirements.

**4. Real Sury build, php-fpm SAPI** (Debian 13, Sury php8.4-fpm 8.4.26): `.so` loaded with
`php -n -d extension=`, reported detached. Then `test/fcgi-probe.py` against
`/run/php/php8.4-fpm.sock`:

```
sapi=fpm-fcgi guard=1 ini=1
post=PHP_SESSION_UPLOAD_PROGRESS,name files=1 size=200000 err=0
session_keys=
```

and `grep -c hp_uploadprogress_guard /proc/<master pid>/maps` = 5.

**5. Real panel builds**: cPanel EA4 `ea-php83` 8.3.35 on AlmaLinux 10.2 (glibc 2.39) and
DirectAdmin CustomBuild `php84` 8.4.22 on Debian 13 both loaded the prebuilt file and reported
detached. On cPanel a fresh `php-cgi -m` (the SAPI those hosts use) lists the module.

**6. Ansible rollout validation** (tag-scoped `phpguard` runs with the fleet playbook, then a second
run for idempotency, then a full untagged deploy on the Debian test host):

| Host | Platform | Versions guarded | Result |
|---|---|---|---|
| ansibletest | Debian 13 / Sury | 8.4 | `failed=0`, second run `changed=0`, full deploy `ok=1506 failed=0` |
| web1, web2, web3 | Debian / Sury, via AWX | 8.3+8.4, 7.4+8.3+8.4, 8.4 | `changed=4` each, fpm restarted, idempotent re-run |
| cpanel1.staging | cPanel EA4, AlmaLinux 10 | 8.1, 8.2, 8.3, 8.4 | `failed=0`, second run `changed=0` |
| directadmin1.staging | DirectAdmin CustomBuild, Debian | 8.2, 8.3, 8.4 | `failed=0`, second run `changed=0`, all three fpm restarted |

Per host afterwards: every version's `php -m` lists the module, `--ri` says detached, fpm masters
map the library, conf.d/php.d/php.conf.d carry the ini.

## Repository layout

```
src/        hp_uploadprogress_guard.c, config.m4
dist/       prebuilt NTS x86_64 .so per PHP minor + SHA256SUMS
build.sh    rebuild dist/ from the official php:<X.Y>-cli images
test/       probe.php, run-builtin-server.sh (Docker functional test), fcgi-probe.py (php-fpm direct)
ansible/    the task files and ini files we deploy (Debian/Sury, cPanel EA4, DirectAdmin)
```

## License

MIT. Built by Hosted Power. Use it, audit it, rebuild it; and install the official PHP packages as
soon as your vendor ships them.
