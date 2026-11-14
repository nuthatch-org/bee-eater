# issafe paste guard for zsh. Load with: eval "$(issafe --shell-init zsh)"
# A risky-looking line is held on Enter and checked; Enter again on the same line runs it.

typeset -g _issafe_held=""

_issafe_wants_check() {
  [[ $1 == *(curl|wget|base64|osascript|iwr|Invoke-WebRequest|irm|dscl|security\ find-|LaunchAgents|crontab|--dangerously-skip-permissions|--yolo|--trust-all-tools)* ]]
}

_issafe_accept_line() {
  local line=$BUFFER
  if [[ -n $line && $line != "$_issafe_held" ]] && _issafe_wants_check "$line"; then
    zle -I
    command issafe --guard -- "$line"
    if (( $? != 0 )); then
      _issafe_held=$line
      print -u2 -- "issafe: press Enter again to run it anyway, or change the line."
      return 0
    fi
  fi
  _issafe_held=""
  if (( ${+widgets[_issafe_prev_accept_line]} )); then
    zle _issafe_prev_accept_line
  else
    zle .accept-line
  fi
}

# `zle -A` would only alias the old widget, and the alias follows the redefinition below, so a
# widget someone else defined is re-registered under its own name instead.
case ${widgets[accept-line]} in
  user:_issafe_accept_line) ;;
  user:*) zle -N _issafe_prev_accept_line ${widgets[accept-line]#user:} ;;
esac
zle -N accept-line _issafe_accept_line
