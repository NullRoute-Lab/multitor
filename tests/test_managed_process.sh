#!/usr/bin/env bash
# Exercise process recognition with inert procfs records, without signalling a PID.
set -eu
_lib="$(cd "$(dirname "$0")/../lib" && pwd)"
# shellcheck source=lib/DestroyProcess
source "${_lib}/DestroyProcess"
fixture=$(mktemp -d)
trap 'rm -r "$fixture"' EXIT
_multitor_directory="$fixture/data"
record="$fixture/4242"
mkdir -p "$record/ns" "${_multitor_directory}/9000"
ln -s /proc/self/ns/pid "$record/ns/pid"
ln -s /proc/self/ns/mnt "$record/ns/mnt"
check() {
  local expected="$1" name="$2"
  shift 2
  printf '%s\n' "$name" > "$record/comm"
  printf '%s\0' "$@" > "$record/cmdline"
  local found=no
  if _is_managed_process "$record"; then found=yes
  elif [[ $? == 2 ]]; then found=uncertain
  fi
  [[ "$found" == "$expected" ]]
}
cfg="${_multitor_directory}/9000/9000.torrc"
check yes tor tor -f "$cfg"
check yes tor tor -f "$cfg" --RunAsDaemon 1
check no tor tor -f /etc/tor/torrc
check no tor tor -f "${_multitor_directory}/9000/9001.torrc"
check yes python3 python3 "${_lib}/custom_lb.py" --listen-port 16378
check yes python3 python3 "${_lib}/api_server.py"
check no python3 python3 /elsewhere/api_server.py "${_lib}/api_server.py"
check no bash bash -c "python3 ${_lib}/custom_lb.py"
check no tor tor
# Identical paths in another mount namespace do not belong to this launcher.
rm "$record/ns/mnt"
ln -s /proc/self/ns/net "$record/ns/mnt"
check no tor tor -f "$cfg"
# A nonroot Tor's namespace links can be unreadable to Docker root.
rm "$record/ns/pid" "$record/ns/mnt"
printf 'NSpid:\t4242\n' > "$record/status"
cat /proc/self/mountinfo > "$record/mountinfo"
printf '4242\n' > "${_multitor_directory}/9000/9000.pid"
check yes tor tor -f "$cfg"
check no python3 python3 "${_lib}/api_server.py"
printf 'NSpid:\t4242\t10\n' > "$record/status"
check no tor tor -f "$cfg"
printf 'NSpid:\t4242\n' > "$record/status"
printf 'foreign mount\n' > "$record/mountinfo"
check no tor tor -f "$cfg"
cat /proc/self/mountinfo > "$record/mountinfo"
printf '1777\n' > "${_multitor_directory}/9000/9000.pid"
check uncertain tor tor -f "$cfg"
