#!/bin/bash -e
export LC_ALL='C'
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

trap 'rc="$?"
      trap "" INT TERM QUIT HUP EXIT ERR
      [ "${rc}" -eq 0 ] || {
      tput bel
      echo
      echo "Script ${0} failed unexpectedly" >&2; }
      exit "${rc}"' INT TERM QUIT HUP EXIT ERR

[ "$(id -u)" -eq 0 ] || {
  echo 'This script must be run as "root"'
  exit 1
}

# Stop and disable service
echo -n 'Disabling systemd daemon...'

# Try to detect installation path before we kill the unit info
service_path=''
if systemctl cat 'isodhcp' >&/dev/null; then
  exe="$(systemctl cat isodhcp |
         sed 's/^\s*ExecStart\s*=\s*\(\S\+\).*/\1/i;t1;d;:1;q')"
  candidate="${exe%/*}"
  if [ -f "${candidate}/isodhcp.py" ]; then
    service_path="${candidate}"
  else
    # For "venv" environments, need to go up two more directories
    candidate="${candidate%/*/*}"
    [ ! -f "${candidate}/isodhcp.py" ] || service_path="${candidate}"
  fi
fi

systemctl stop 'isodhcp' >&/dev/null || :
systemctl disable 'isodhcp' >&/dev/null || :
rm -f '/etc/systemd/system/isodhcp.service'
systemctl daemon-reload
echo ' done.'

# Determine paths to clean
dst=''
if [ -n "${service_path}" ]; then
  dst="${service_path}"
elif command -v 'isodhcp' >&/dev/null; then
  # Fallback: resolve symlink /usr/local/bin/isodhcp -> /opt/isodhcp/isodhcp
  real_path="$(readlink -f "$(command -v isodhcp)")"
  candidate="${real_path%/*}"
  [ ! -f "${candidate}/isodhcp.py" ] || dst="${candidate}"
fi

# Clean symbolic links & man pages
echo -n 'Removing system links...'
rm -f '/usr/local/bin/isodhcp' '/usr/bin/isodhcp' '/bin/isodhcp'
rm -f '/usr/local/share/man/man8/isodhcp.8'* \
      '/usr/share/man/man8/isodhcp.8'*
echo ' done.'

# Remove main directory
if [ -z "${dst}" ]; then
  echo
  echo 'Could not auto-detect installation directory.'
  read -p 'Enter installation path to remove (e.g. /usr/local/lib/isodhcp): ' dst
  if [ ! -f "${dst}/isodhcp.py" ]; then
    echo "Warning: isodhcp.py not found in \"${dst}\"."
    read -p 'Are you sure you want to delete this directory? [y/N] ' confirm
    [[ "${confirm}" =~ ^[Yy] ]] || dst=''
  fi
fi

if [ -n "${dst}" ] && [ -d "${dst}" ]; then
  echo -n "Removing files from \"${dst}\"..."
  if [[ "${dst}" == '/' ]] || [[ "${dst}" == '/usr' ]] || \
     [[ "${dst}" == '/usr/bin' ]] || [[ "${dst}" == '/home' ]]; then
    echo ' Skipped (unsafe path).'
  else
    rm -rf "${dst}"
    echo ' done.'
  fi
else
    echo 'Installation directory not found or skipped.'
fi

# Delete user
echo -n 'Removing "isodhcp" user...'
if id 'isodhcp' >&/dev/null; then
  userdel -r isodhcp >&/dev/null || :
  echo ' done.'
else
  echo ' not found.'
fi

echo -n 'Updating man database...'
mandb -q >&/dev/null || :
echo ' done.'

echo
echo 'Uninstall complete.'
