#!/bin/bash -e
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
SOURCES='{isodhcp{,.8,.8.md,.py,.service},{,un}install.sh,LICENSE,README.md}'
DEP='pyroute2 scapy'

trap 'rc="$?"
      trap "" INT TERM QUIT HUP EXIT ERR
      [ $rc -eq 0 ] || {
      tput bel
      echo
      echo "Script $0 failed unexpectedly" >&2; }
      exit $rc' INT TERM QUIT HUP EXIT ERR

[ "$(id -u)" -eq 0 ] || {
  echo 'This script must be run as "root", so that it can install "isodhcp"'
  exit
}

script="$(readlink -f "$(type --path "$0")")"
src="${script%/*}"
U=$(tput smul)
R=$(tput rmul)

# Choose installation directory
cat <<EOF
${U}isodhcp${R} needs to be installed in its own system directory. Common
choices are ${U}/usr/local/lib/isodhcp${R} or ${U}/opt/isodhcp${R}. But you
might have a different local convention.
EOF
while :; do
  read -p 'Install path [/usr/local/lib/isodhcp]: ' dst
  [ -n "${dst}" ] || dst='/usr/local/lib/isodhcp'
  [[ "${dst}" =~ ^/ ]] && break || :
done

# Find suitable system-wide directories for installing binary and man page
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

# Copying source files to target directory
echo -n 'Copying source files...'
mkdir -m0755 -p "${dst}"
(dst="$(readlink -f "${dst}")"
 cd "${src}"
 eval "SOURCES=(\$(echo ${SOURCES}))"
 cp "${SOURCES[@]}" "${dst}"
 echo)

# Setting up Python
echo -n 'Setting up Python virtual environment...'
(cd "${dst}"
 rm -rf 'venv'
 echo
 python3 -m venv venv
 venv/bin/pip3 install ${DEP}
 ln -s python3 venv/bin/isodhcp
)

# Creating symbolic links
echo -n 'Creating symbolic links...'
rm -f "${sys}/bin/isodhcp"
ln -s "${dst}/isodhcp" "${sys}/bin/isodhcp"
rm -f "${man}/man8/isodhcp.8"
mkdir -p "${man}/man8"
gzip <"${dst}/isodhcp.8" >"${man}/man8/isodhcp.8.gz"
echo
mandb
rm -f '/etc/systemd/system/isodhcp.service'
ln -s "${dst}/isodhcp.service" '/etc/systemd/system/isodhcp.service'

# Creating user
echo 'Creating "isodhcp" user'
grep isodhcp /etc/passwd ||
useradd -d /var/lib/isodhcp -U -M -r -s /usr/sbin/nologin isodhcp

# Setting up systemd service
echo 'Setting up systemd integration...'
systemctl daemon-reload
systemctl stop isodhcp >&/dev/null || :
systemctl enable isodhcp

# Finished
cat <<EOF

${U}isodhcp${R} is now installed as a ${U}systemd${R} service.
The service hasn't been started yet, as you should first edit
${U}${dst}/isodhcp.service${R} for your local needs.

Type ${U}man isodhcp${R} for detailed documentation. And once you
have everything set up, run ${U}sudo systemctl start isodhcp${R}.
You can check on the service with ${U}sudo systemctl status isodhcp${R},
or with ${U}sudo journalctl -xeu isodhcp${R}.
EOF
