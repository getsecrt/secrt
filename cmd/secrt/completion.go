package main

const bashCompletion = `_secrt() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="create claim burn version help completion"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
        return 0
    fi

    case "${prev}" in
        create)
            COMPREPLY=($(compgen -W "--ttl --api-key --base-url --json --text --file --passphrase-prompt --passphrase-env --passphrase-file --help" -- "${cur}"))
            ;;
        claim)
            COMPREPLY=($(compgen -W "--base-url --json --passphrase-prompt --passphrase-env --passphrase-file --help" -- "${cur}"))
            ;;
        burn)
            COMPREPLY=($(compgen -W "--api-key --base-url --json --help" -- "${cur}"))
            ;;
        completion)
            COMPREPLY=($(compgen -W "bash zsh fish" -- "${cur}"))
            ;;
    esac
    return 0
}
complete -F _secrt secrt
`

const zshCompletion = `#compdef secrt

_secrt() {
    local -a commands
    commands=(
        'create:Encrypt and upload a secret'
        'claim:Retrieve and decrypt a secret'
        'burn:Destroy a secret (requires API key)'
        'version:Show version'
        'help:Show help'
        'completion:Output shell completion script'
    )

    _arguments -C \
        '1:command:->command' \
        '*::arg:->args'

    case "$state" in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[1] in
                create)
                    _arguments \
                        '--ttl[TTL for secret]:ttl:' \
                        '--api-key[API key]:key:' \
                        '--base-url[Server URL]:url:' \
                        '--json[Output as JSON]' \
                        '--text[Secret text]:text:' \
                        '--file[Secret file]:file:_files' \
                        '--passphrase-prompt[Prompt for passphrase]' \
                        '--passphrase-env[Passphrase env var]:var:' \
                        '--passphrase-file[Passphrase file]:file:_files' \
                        '--help[Show help]'
                    ;;
                claim)
                    _arguments \
                        '--base-url[Server URL]:url:' \
                        '--json[Output as JSON]' \
                        '--passphrase-prompt[Prompt for passphrase]' \
                        '--passphrase-env[Passphrase env var]:var:' \
                        '--passphrase-file[Passphrase file]:file:_files' \
                        '--help[Show help]'
                    ;;
                burn)
                    _arguments \
                        '--api-key[API key]:key:' \
                        '--base-url[Server URL]:url:' \
                        '--json[Output as JSON]' \
                        '--help[Show help]'
                    ;;
                completion)
                    _arguments '1:shell:(bash zsh fish)'
                    ;;
            esac
            ;;
    esac
}

_secrt
`

const fishCompletion = `complete -c secrt -f
complete -c secrt -n '__fish_use_subcommand' -a create -d 'Encrypt and upload a secret'
complete -c secrt -n '__fish_use_subcommand' -a claim -d 'Retrieve and decrypt a secret'
complete -c secrt -n '__fish_use_subcommand' -a burn -d 'Destroy a secret (requires API key)'
complete -c secrt -n '__fish_use_subcommand' -a version -d 'Show version'
complete -c secrt -n '__fish_use_subcommand' -a help -d 'Show help'
complete -c secrt -n '__fish_use_subcommand' -a completion -d 'Output shell completion script'

complete -c secrt -n '__fish_seen_subcommand_from create' -l ttl -d 'TTL for secret'
complete -c secrt -n '__fish_seen_subcommand_from create' -l api-key -d 'API key'
complete -c secrt -n '__fish_seen_subcommand_from create' -l base-url -d 'Server URL'
complete -c secrt -n '__fish_seen_subcommand_from create' -l json -d 'Output as JSON'
complete -c secrt -n '__fish_seen_subcommand_from create' -l text -d 'Secret text'
complete -c secrt -n '__fish_seen_subcommand_from create' -l file -d 'Secret file' -F
complete -c secrt -n '__fish_seen_subcommand_from create' -l passphrase-prompt -d 'Prompt for passphrase'
complete -c secrt -n '__fish_seen_subcommand_from create' -l passphrase-env -d 'Passphrase env var'
complete -c secrt -n '__fish_seen_subcommand_from create' -l passphrase-file -d 'Passphrase file' -F

complete -c secrt -n '__fish_seen_subcommand_from claim' -l base-url -d 'Server URL'
complete -c secrt -n '__fish_seen_subcommand_from claim' -l json -d 'Output as JSON'
complete -c secrt -n '__fish_seen_subcommand_from claim' -l passphrase-prompt -d 'Prompt for passphrase'
complete -c secrt -n '__fish_seen_subcommand_from claim' -l passphrase-env -d 'Passphrase env var'
complete -c secrt -n '__fish_seen_subcommand_from claim' -l passphrase-file -d 'Passphrase file' -F

complete -c secrt -n '__fish_seen_subcommand_from burn' -l api-key -d 'API key'
complete -c secrt -n '__fish_seen_subcommand_from burn' -l base-url -d 'Server URL'
complete -c secrt -n '__fish_seen_subcommand_from burn' -l json -d 'Output as JSON'

complete -c secrt -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
`
