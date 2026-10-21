/*
 * hp_uploadprogress_guard - owns PHP's multipart/form-data post handler.
 *
 * At MINIT the SAPI post entry for multipart/form-data (main/rfc1867.c's handler) is replaced by
 * ours. Two modes, selected by the INI_SYSTEM setting hp_uploadprogress_guard.mode:
 *   parse  (default) hand the request to the copy of main/rfc1867.c compiled into this module
 *                    (rfc1867_copy.c): the parser of the fixed PHP release, with ext/session's
 *                    upload-progress callback compiled out and, since v3, a memory-headroom guard
 *                    that stops the request (413, $_POST/$_FILES dropped) before any step could
 *                    exhaust memory_limit, so no out-of-memory bailout can start inside the parser.
 *   native           leave PHP's own parser in place (use once the patched PHP packages are installed);
 *                    "off" is not usable as a value because PHP's ini parser turns it into ""
 *   block            refuse the request before any parsing: the body is never read, $_POST and
 *                    $_FILES stay empty, the response code is set to 415 and a warning is logged.
 *                    Emergency mode for CVE-2026-109618 / CVE-2026-109619 while no fix exists.
 * hp_uploadprogress_guard.allow_ips: comma separated client IPs that are always parsed (admins, monitoring).
 * hp_uploadprogress_guard.detach_upload_progress (default 1): at MINIT, after ext/session has started, drop
 *   ext/session's multipart upload-progress handler (php_session_rfc1867_callback) from main/rfc1867.c's
 *   callback pointer, so that handler is unreachable whatever session.upload_progress.* says.
 * All settings are PHP_INI_SYSTEM: php.ini / php-fpm.conf only, never .user.ini, .htaccess or ini_set().
 *
 * mbstring: its multibyte hooks (encoding detection, mb-aware getword/basename) are file-static in mbstring
 * and registered into PHP's own rfc1867.c only, so the carried parser cannot run them. They are used solely
 * when mbstring.encoding_translation is On (PHP_INI_PERDIR), so such a request is handed to PHP's native
 * parser instead (the callback detach still applies to it); everything else is byte-identical.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "SAPI.h"
#include "rfc1867.h"
#include "ext/standard/php_versioning.h"
#include <string.h>

#define HP_MPG_VERSION "3.0.1"
#define HP_MPG_NAME "hp_uploadprogress_guard"

SAPI_API SAPI_POST_HANDLER_FUNC(hp_rfc1867_post_handler);
static SAPI_POST_HANDLER_FUNC(hp_upg_dispatch);

static sapi_post_entry hp_upg_entry = { MULTIPART_CONTENT_TYPE, sizeof(MULTIPART_CONTENT_TYPE) - 1, NULL, hp_upg_dispatch };
static int hp_upg_installed = 0;
static int hp_upg_detached = 0;
static int hp_upg_php_patched = 0;
static int hp_upg_mbstring = 0;
static char hp_upg_php_version[32] = "";

/* First PHP release of each branch that contains the official fix; any branch newer than the last entry
 * was released with it. Older branches keep their version number when a vendor backports the fix, so they
 * are never reported as patched here (mode=parse then keeps the carried fixed parser, which is harmless on
 * a patched build). */
static const struct { const char *branch; const char *fixed; } hp_upg_fixed[] = {
	{ "8.6.", "8.6.0" }, { "8.5.", "8.5.12" }, { "8.4.", "8.4.27" }, { "8.3.", "8.3.36" }, { "8.2.", "8.2.35" }, { NULL, NULL }
};

static void hp_upg_detect_patched(void)
{
	zval *v;
	size_t i;
	int major = 0, minor = 0;
#if PHP_VERSION_ID < 70000
	zval **vv;
	if (zend_hash_find(EG(zend_constants), "PHP_VERSION", sizeof("PHP_VERSION"), (void **) &vv) == SUCCESS) {
		zend_constant *c = (zend_constant *) *vv;
		v = &c->value;
	} else {
		return;
	}
#else
	v = zend_get_constant_str("PHP_VERSION", sizeof("PHP_VERSION") - 1);
	if (!v) {
		return;
	}
#endif
	if (Z_TYPE_P(v) != IS_STRING) {
		return;
	}
	strncpy(hp_upg_php_version, Z_STRVAL_P(v), sizeof(hp_upg_php_version) - 1);
	for (i = 0; hp_upg_fixed[i].branch; i++) {
		if (strncmp(hp_upg_php_version, hp_upg_fixed[i].branch, strlen(hp_upg_fixed[i].branch)) == 0) {
			hp_upg_php_patched = php_version_compare(hp_upg_php_version, hp_upg_fixed[i].fixed) >= 0;
			return;
		}
	}
	{
		/* no sscanf/strtol: on glibc >= 2.38 they bind to GLIBC_2.38 symbols and the .so stops loading on older hosts */
		const char *p = hp_upg_php_version;
		while (*p >= '0' && *p <= '9') major = major * 10 + (*p++ - '0');
		if (*p == '.') {
			p++;
			while (*p >= '0' && *p <= '9') minor = minor * 10 + (*p++ - '0');
		}
	}
	if (major > 8 || (major == 8 && minor > 6)) {
		hp_upg_php_patched = 1;
	}
}

/* mbstring.encoding_translation=On: only PHP's own parser has mbstring's hooks, see the header comment. */
static int hp_upg_native_needed(void)
{
	return hp_upg_mbstring && INI_INT("mbstring.encoding_translation");
}

PHP_INI_BEGIN()
	PHP_INI_ENTRY("hp_uploadprogress_guard.mode", "parse", PHP_INI_SYSTEM, NULL)
	PHP_INI_ENTRY("hp_uploadprogress_guard.allow_ips", "", PHP_INI_SYSTEM, NULL)
	PHP_INI_ENTRY("hp_uploadprogress_guard.detach_upload_progress", "1", PHP_INI_SYSTEM, NULL)
PHP_INI_END()

static int hp_upg_client_allowed(void)
{
	const char *allow = INI_STR("hp_uploadprogress_guard.allow_ips");
	char *ip;
	int allowed = 0;

	if (!allow || !*allow) {
		return 0;
	}
#if PHP_VERSION_ID < 70000
	ip = sapi_getenv("REMOTE_ADDR", sizeof("REMOTE_ADDR") - 1 TSRMLS_CC);
#else
	ip = sapi_getenv("REMOTE_ADDR", sizeof("REMOTE_ADDR") - 1);
#endif
	if (ip && *ip) {
		size_t iplen = strlen(ip);
		const char *p = allow;
		while (*p) {
			const char *q;
			while (*p == ' ' || *p == ',') p++;
			q = p;
			while (*q && *q != ',' && *q != ' ') q++;
			if ((size_t)(q - p) == iplen && memcmp(p, ip, iplen) == 0) {
				allowed = 1;
				break;
			}
			p = q;
		}
	}
	if (ip) {
		efree(ip);
	}
	return allowed;
}

static SAPI_POST_HANDLER_FUNC(hp_upg_dispatch)
{
	const char *mode = INI_STR("hp_uploadprogress_guard.mode");

	if (mode && strcasecmp(mode, "block") == 0 && !hp_upg_client_allowed()) {
		/* Nothing is read from the body; the SAPI discards it. */
		SG(sapi_headers).http_response_code = 415;
		/* error log only: never the output stream, whatever display_errors says */
#if PHP_VERSION_ID < 70000
		php_log_err("hp_uploadprogress_guard: multipart/form-data request refused (mode=block)" TSRMLS_CC);
#else
		php_log_err("hp_uploadprogress_guard: multipart/form-data request refused (mode=block)");
#endif
		return;
	}
#if PHP_VERSION_ID < 70000
	if (hp_upg_native_needed()) {
		rfc1867_post_handler(content_type_dup, arg TSRMLS_CC);
		return;
	}
	hp_rfc1867_post_handler(content_type_dup, arg TSRMLS_CC);
#else
	if (hp_upg_native_needed()) {
		rfc1867_post_handler(content_type_dup, arg);
		return;
	}
	hp_rfc1867_post_handler(content_type_dup, arg);
#endif
}

static PHP_MINIT_FUNCTION(hp_uploadprogress_guard)
{
	REGISTER_INI_ENTRIES();
	hp_upg_detect_patched();
#ifdef HP_UPG_TEST_FORCE_PARSE
	hp_upg_php_patched = 0; /* test builds only: exercise the carried parser on a patched engine */
#endif
#if PHP_VERSION_ID < 70000
	hp_upg_mbstring = zend_hash_exists(&module_registry, "mbstring", sizeof("mbstring"));
#else
	hp_upg_mbstring = zend_hash_str_exists(&module_registry, "mbstring", sizeof("mbstring") - 1);
#endif
	{
		const char *mode = INI_STR("hp_uploadprogress_guard.mode");
		/* native: never replace. parse on a PHP that already carries the fix: step aside too. */
		if (!((mode && strcasecmp(mode, "native") == 0) || (hp_upg_php_patched && !(mode && strcasecmp(mode, "block") == 0)))) {
#if PHP_VERSION_ID < 70000
			sapi_unregister_post_entry(&hp_upg_entry TSRMLS_CC);
			if (sapi_register_post_entry(&hp_upg_entry TSRMLS_CC) == SUCCESS) {
#else
			sapi_unregister_post_entry(&hp_upg_entry);
			if (sapi_register_post_entry(&hp_upg_entry) == SUCCESS) {
#endif
				hp_upg_installed = 1;
			}
		}
	}
	if (INI_BOOL("hp_uploadprogress_guard.detach_upload_progress") && php_rfc1867_callback != NULL) {
		php_rfc1867_callback = NULL;
		hp_upg_detached = 1;
	}
	return SUCCESS;
}

static PHP_MSHUTDOWN_FUNCTION(hp_uploadprogress_guard)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}

static PHP_MINFO_FUNCTION(hp_uploadprogress_guard)
{
	php_info_print_table_start();
	php_info_print_table_row(2, HP_MPG_NAME, "enabled");
	php_info_print_table_row(2, "version", HP_MPG_VERSION);
	php_info_print_table_row(2, "multipart/form-data handler replaced", hp_upg_installed ? "yes" : "no");
	php_info_print_table_row(2, "mode", INI_STR("hp_uploadprogress_guard.mode"));
	php_info_print_table_row(2, "parser memory-headroom guard", hp_upg_installed ? "yes (memory_limit > 0)" : "no (parser not replaced)");
	php_info_print_table_row(2, "mbstring.encoding_translation requests", hp_upg_installed ? (hp_upg_mbstring ? "handed to PHP's parser" : "n/a (mbstring not loaded)") : "n/a");
	php_info_print_table_row(2, "running PHP already carries the official fix", hp_upg_php_patched ? (hp_upg_installed ? "yes" : "yes (parser replacement skipped)") : "no");
	php_info_print_table_row(2, "session.upload_progress handler detached", hp_upg_detached ? "yes" : "no");
	php_info_print_table_end();
	DISPLAY_INI_ENTRIES();
}

static const zend_module_dep hp_upg_deps[] = {
	ZEND_MOD_OPTIONAL("session")
	ZEND_MOD_OPTIONAL("mbstring")
	ZEND_MOD_END
};

zend_module_entry hp_uploadprogress_guard_module_entry = {
	STANDARD_MODULE_HEADER_EX,
	NULL,
	hp_upg_deps,
	HP_MPG_NAME,
	NULL,
	PHP_MINIT(hp_uploadprogress_guard),
	PHP_MSHUTDOWN(hp_uploadprogress_guard),
	NULL,
	NULL,
	PHP_MINFO(hp_uploadprogress_guard),
	HP_MPG_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_HP_UPLOADPROGRESS_GUARD
ZEND_GET_MODULE(hp_uploadprogress_guard)
#endif
