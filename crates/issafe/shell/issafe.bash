# issafe paste guard for bash 4 or later. Load with: eval "$(issafe --shell-init bash)"
# A risky-looking line is held on Enter and checked; Enter again on the same line runs it.
# Enter becomes a two-key macro: the first key runs the check, which rebinds the second key to
# accept the line or only redraw it. Readline looks each key up as it arrives, so this works.

if (( BASH_VERSINFO[0] < 4 )); then
  echo "issafe: the paste guard needs bash 4 or later; this is bash $BASH_VERSION" >&2
  return 0 2>/dev/null || exit 0
fi

_issafe_held=""

_issafe_wants_check() {
  case $1 in
    *curl*|*wget*|*base64*|*osascript*|*iwr*|*Invoke-WebRequest*|*irm*|*dscl*|*"security find-"*|*LaunchAgents*|*crontab*|*--dangerously-skip-permissions*|*--yolo*|*--trust-all-tools*) return 0 ;;
  esac
  return 1
}

_issafe_check() {
  local line=$READLINE_LINE
  bind '"\C-x\C-h": accept-line'
  if [[ -n $line && $line != "$_issafe_held" ]] && _issafe_wants_check "$line"; then
    if ! command issafe --guard -- "$line"; then
      _issafe_held=$line
      echo "issafe: press Enter again to run it anyway, or change the line." >&2
      bind '"\C-x\C-h": redraw-current-line'
      return
    fi
  fi
  _issafe_held=""
}

bind -x '"\C-x\C-g": _issafe_check'
bind '"\C-x\C-h": accept-line'
bind '"\C-m": "\C-x\C-g\C-x\C-h"'
bind '"\C-j": "\C-x\C-g\C-x\C-h"'
