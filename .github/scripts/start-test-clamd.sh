#!/usr/bin/env bash
# Start a throwaway clamd for CI that knows only the EICAR test file.
#
# Run as root (clamd drops to the clamav user itself, the way a real
# install does, so Ensign's "refuse a root clamd" check sees a normal
# daemon). No signatures are downloaded: a one-line hash signature for the
# EICAR test file is all the database there is, so the test is fast and
# gives the same result on every run.
#
# Ubuntu confines clamd with AppArmor, and its profile only lets clamd read
# its standard config file (/etc/clamav/clamd.conf) and create its
# standard socket (/run/clamav/clamd.ctl). So this script uses both, and
# OVERWRITES that config -- fine on a throwaway CI machine, not on yours.
# It refuses to run unless $CI is set (GitHub Actions sets CI=true).
# The other paths stay under /var/lib/clamav, /run/clamav and
# /var/log/clamav, which the profile also allows.
#
# Prints nothing on success; the socket is $SOCKET.
set -euo pipefail

if [ -z "${CI:-}" ]; then
    echo "refusing to run outside CI: this overwrites /etc/clamav/clamd.conf" >&2
    exit 1
fi

SOCKET=/run/clamav/clamd.ctl
CONF=/etc/clamav/clamd.conf
DB=/var/lib/clamav/ensign-test
LOG=/var/log/clamav/ensign-test.log

# clamscan too: Ensign sends files larger than clamd scans to it. On
# Debian/Ubuntu it is a separate package (clamav) that clamav-daemon
# doesn't pull in.
if ! command -v clamd >/dev/null || ! command -v clamscan >/dev/null; then
    # policy-rc.d: stop the package from starting its own clamd and
    # freshclam services; freshclam would download the full signature set.
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod +x /usr/sbin/policy-rc.d
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q clamav-daemon clamav
    rm -f /usr/sbin/policy-rc.d
fi

mkdir -p "$DB" /run/clamav /var/log/clamav
chown clamav:clamav /run/clamav /var/log/clamav

# The EICAR string, built from two halves so this script itself never
# contains the whole thing (some scanners flag files that do).
eicar="X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR"
eicar+="-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"
md5=$(printf '%s' "$eicar" | md5sum | cut -d' ' -f1)
size=$(printf '%s' "$eicar" | wc -c)
# .hdb format: MD5:size:name
echo "$md5:$size:Ensign.Test.EICAR" > "$DB/ensign-test.hdb"
# .ndb format: name:target:offset:hex -- the EICAR body anywhere in any
# file, so a large file with EICAR inside it (padded past clamd's limit)
# is detected too. A hash signature can only match the exact 68-byte file.
# (Built from halves for the same reason as above: this script itself
# must not match the signature it writes.)
body="EICAR-STANDARD"
body+="-ANTIVIRUS-TEST-FILE"
body_hex=$(printf '%s' "$body" | od -An -tx1 | tr -d ' \n')
echo "Ensign.Test.EICAR-Body:0:*:$body_hex" > "$DB/ensign-test.ndb"
chown -R clamav:clamav "$DB"

cat > "$CONF" <<CONF
LocalSocket $SOCKET
LocalSocketMode 666
DatabaseDirectory $DB
User clamav
LogFile $LOG
Foreground no
CONF

clamd -c "$CONF"

for _ in $(seq 1 60); do
    [ -S "$SOCKET" ] && exit 0
    sleep 1
done
echo "clamd did not create $SOCKET within 60s" >&2
cat "$LOG" >&2 || true
exit 1
