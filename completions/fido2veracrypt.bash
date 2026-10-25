# bash completion for fido2veracrypt.

_fido2veracrypt_containers() {
  local cur=$1 slot
  for slot in "$cur"*.fido2veracrypt_meta; do
    [[ -e $slot ]] && COMPREPLY+=("${slot%.fido2veracrypt_meta}")
  done
  if (( ${#COMPREPLY[@]} == 0 )); then
    COMPREPLY=($(compgen -f -- "$cur"))
  fi
}

_fido2veracrypt() {
  local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
  local commands="create adopt open close add-key remove-key rotate status list-keys completions help"
  COMPREPLY=()
  if (( COMP_CWORD == 1 )); then
    COMPREPLY=($(compgen -W "$commands" -- "$cur"))
    return
  fi
  local command=${COMP_WORDS[1]}
  if [[ $prev == --label && $command == remove-key ]]; then
    local labels
    labels=$(fido2veracrypt list-keys "${COMP_WORDS[2]}" 2>/dev/null | grep -v '^(' | sed -n 's/  .*//p')
    COMPREPLY=($(compgen -W "$labels" -- "$cur"))
    return
  fi
  if [[ $prev == --size || $prev == --label ]]; then
    return
  fi
  case $command in
    create) flags="--size --label" ;;
    adopt) flags="--label" ;;
    close) flags="--force" ;;
    add-key) flags="--label --recovery" ;;
    remove-key) flags="--label" ;;
    completions) COMPREPLY=($(compgen -W "zsh bash" -- "$cur")); return ;;
    *) flags="" ;;
  esac
  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "$flags" -- "$cur"))
  elif (( COMP_CWORD == 2 )); then
    _fido2veracrypt_containers "$cur"
  fi
}

complete -F _fido2veracrypt fido2veracrypt
