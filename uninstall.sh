#!/bin/bash -e
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

trap 'rc="$?"
      trap "" INT TERM QUIT HUP EXIT ERR
      [ $rc -eq 0 ] || {
      tput bel
      echo
      echo "Script $0 failed unexpectedly" >&2; }
      exit $rc' INT TERM QUIT HUP EXIT ERR

[ "$(id -u)" -eq 0 ] || {
  echo 'This script must be run as "root", so that it can uninstall "isodhcp"'
  exit
}

# De-activating system integration
echo 'Disabling systemd daemon...'
systemctl stop isodhcp >&/dev/null || :
systemctl disable isodhcp || :
rm -f '/etc/systemd/system/isodhcp.service'

# Deleting user
echo 'Deleting "isodhcp" user...'
userdel -r isodhcp || :

# Deleting links
echo 'Deleting symbolic links...'
daemon="$(type --path isodhcp)"
bin="$(readlink -f "${daemon}")"
[ -x "${bin}" ]
dst="${bin%/*}"
man='/usr/share/man'
if ! [[ "${dst}" =~ ^'/usr' ]]; then
  sys='/'
  [ -d "${sys}/bin" ] || sys='/usr'
elif [[ "${dst}" =~ ^'/usr' ]] && ! [[ "${dst}" =~ ^'/usr/local' ]]; then
  sys='/usr'
else
  sys='/usr/local'
  man='/usr/local/share/man'
fi

# Deleting installed files
echo 'Deleting installed files...'
[ -x "${dst}/isodhcp" ] && rm -rf "${dst}"
rm -f "${sys}/bin/isodhcp"
rm -f "${man}/man8/isodhcp.8"*
mandb
