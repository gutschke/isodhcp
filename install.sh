#!/bin/bash -e
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

SOURCES=(isodhcp{,.8,.8.md,.py,.service} {install,uninstall}.sh LICENSE README.md)
DEP='pyroute2 scapy'

trap 'rc="$?"
      trap "" INT TERM QUIT HUP EXIT ERR
      [ $rc -eq 0 ] || {
      tput bel
      echo
      echo "Script $0 failed unexpectedly" >&2; }
      exit $rc' INT TERM QUIT HUP EXIT ERR

[ "$(id -u)" -eq 0 ] || {
  echo 'This script must be run as "root"'
  exit 1
}

# Dependency check
missing=""
for cmd in python3 gzip mandb systemctl useradd tput; do
  if ! command -v "$cmd" >&/dev/null; then
    missing="$missing $cmd"
  fi
done

# Check for venv module (common omission on Debian/Ubuntu)
if ! python3 -c 'import venv' >&/dev/null; then
  echo 'Error: Python3 "venv" module is missing.'
  echo '  On Debian/Ubuntu, install it with: apt install python3-venv'
  exit 1
fi

if [ -n "$missing" ]; then
  echo "Error: Missing required system tools:$missing"
  exit 1
fi

script="$(readlink -f "$(type -P "$0")")"
src="${script%/*}"
U="$(tput smul)"
R="$(tput rmul)"

# Choose installation directory
cat <<EOF
${U}isodhcp${R} needs to be installed in its own system directory. Common
choices are ${U}/usr/local/lib/isodhcp${R} or ${U}/opt/isodhcp${R}.
EOF
while :; do
  read -p 'Install path [/usr/local/lib/isodhcp]: ' dst
  [ -n "${dst}" ] || dst='/usr/local/lib/isodhcp'
  [[ "${dst}" =~ ^/ ]] && break || :
done

# Determine system paths
man='/usr/share/man'
if ! [[ "${dst}" =~ ^'/usr' ]]; then
  [ -d "/bin" ] && sys='/' || sys='/usr'
elif [[ "${dst}" =~ ^'/usr' ]] && ! [[ "${dst}" =~ ^'/usr/local' ]]; then
  sys='/usr'
else
  sys='/usr/local'
  man='/usr/local/share/man'
fi

# Install files
echo -n 'Copying source files...'
mkdir -m0755 -p "${dst}"
for file in "${SOURCES[@]}"; do
  [ ! -e "${src}/${file}" ] || cp "${src}/${file}" "${dst}/"
done
echo ' done.'

# Setup python venv
echo -n 'Setting up Python virtual environment...'
(
  cd "${dst}"
  rm -rf 'venv'
  python3 -m 'venv' 'venv'
  ./venv/bin/pip3 install --upgrade 'pip' >&/dev/null
  ./venv/bin/pip3 install ${DEP} >/dev/null

  # Create the symlink for the process name
  # This ensures 'ps' shows 'isodhcp' instead of 'python3'
  ln -sf 'python3' 'venv/bin/isodhcp'
)
echo ' done.'

# System Integration
echo -n 'Creating symbolic links...'
# Binary
rm -f "${sys}/bin/isodhcp"
ln -s "${dst}/isodhcp" "${sys}/bin/isodhcp"

# Man Page
rm -f "${man}/man8/isodhcp.8.gz"
mkdir -p "${man}/man8"
gzip -c "${dst}/isodhcp.8" >"${man}/man8/isodhcp.8.gz"
echo ' done.'

echo -n 'Updating man database...'
mandb -q >&/dev/null || echo " (warning: mandb failed)"
echo ' done.'

# Service & user
echo -n 'Configuring user and storage...'
state_dir="/var/lib/isodhcp"
if ! id 'isodhcp' >&/dev/null; then
  useradd -d "${state_dir}" -U -M -r -s '/usr/sbin/nologin' 'isodhcp'
fi
mkdir -p "${state_dir}"
chown 'isodhcp:isodhcp' "${state_dir}"
chmod 750 "${state_dir}"
echo ' done.'

echo -n 'Installing systemd service...'
rm -f '/etc/systemd/system/isodhcp.service'
# Symlink for "single source of truth" configuration
ln -s "${dst}/isodhcp.service" '/etc/systemd/system/isodhcp.service'

# Reload
systemctl daemon-reload
systemctl stop isodhcp >&/dev/null || :
systemctl enable isodhcp >&/dev/null
echo ' done.'

# Finished
cat <<EOF

${U}isodhcp${R} is now installed.

1. Edit configuration:   ${U}${dst}/isodhcp.service${R}
   (Linked from /etc/systemd/system/isodhcp.service)
2. Start service:        ${U}sudo systemctl start isodhcp${R}
3. Check status:         ${U}sudo systemctl status isodhcp${R}
4. Examine log messages: ${U}sudo journalctl -xeu isodhcp${R}
5. Read manual:          ${U}man isodhcp${R}
6. Uninstall:            ${U}${dst}/uninstall.sh${R}

EOF
