PHP_ARG_ENABLE(hp_uploadprogress_guard, whether to enable hp_uploadprogress_guard,
[  --enable-hp-uploadprogress-guard   Enable hp_uploadprogress_guard], yes)
if test "$PHP_HP_UPLOADPROGRESS_GUARD" != "no"; then
  dnl The carried multipart parser is one copy of main/rfc1867.c per PHP branch (rfc1867/rfc1867_copy-X.Y.c).
  dnl Pick the copy of the PHP this build targets; a prepared rfc1867_copy.c (build.sh) takes precedence.
  HP_UPG_SRCDIR="${srcdir:-.}"
  if test ! -f "$HP_UPG_SRCDIR/rfc1867_copy.c"; then
    HP_UPG_PHP_BRANCH=`$PHP_CONFIG --version | cut -d. -f1,2`
    if test ! -f "$HP_UPG_SRCDIR/rfc1867/rfc1867_copy-$HP_UPG_PHP_BRANCH.c"; then
      AC_MSG_ERROR([no carried parser for PHP $HP_UPG_PHP_BRANCH (rfc1867/rfc1867_copy-$HP_UPG_PHP_BRANCH.c)])
    fi
    AC_MSG_NOTICE([using rfc1867/rfc1867_copy-$HP_UPG_PHP_BRANCH.c])
    cp "$HP_UPG_SRCDIR/rfc1867/rfc1867_copy-$HP_UPG_PHP_BRANCH.c" "$HP_UPG_SRCDIR/rfc1867_copy.c"
  fi
  PHP_NEW_EXTENSION(hp_uploadprogress_guard, hp_uploadprogress_guard.c rfc1867_copy.c, $ext_shared)
fi
