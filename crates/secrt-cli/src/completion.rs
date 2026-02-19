pub const BASH_COMPLETION: &str = r#"_secrt() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="send get burn gen generate list info sync auth config version help completion"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
        return 0
    fi

    case "${prev}" in
        send)
            COMPREPLY=($(compgen -W "gen generate --ttl --api-key --base-url --json --text --file --show --hidden --silent --multi-line --trim --qr --passphrase-prompt --passphrase-env --passphrase-file --help" -- "${cur}"))
            ;;
        get)
            COMPREPLY=($(compgen -W "--output --base-url --json --silent --passphrase-prompt --passphrase-env --passphrase-file --help" -- "${cur}"))
            ;;
        burn)
            COMPREPLY=($(compgen -W "--api-key --base-url --json --silent --help" -- "${cur}"))
            ;;
        gen|generate)
            COMPREPLY=($(compgen -W "send --length --no-symbols --no-numbers --no-caps --grouped --count --json --help" -- "${cur}"))
            ;;
        info)
            COMPREPLY=($(compgen -W "--api-key --base-url --json --silent --help" -- "${cur}"))
            ;;
        sync)
            COMPREPLY=($(compgen -W "--api-key --base-url --silent --help" -- "${cur}"))
            ;;
        auth)
            COMPREPLY=($(compgen -W "login setup status logout --base-url --help" -- "${cur}"))
            ;;
        config)
            COMPREPLY=($(compgen -W "init path set-passphrase delete-passphrase --force" -- "${cur}"))
            ;;
        completion)
            COMPREPLY=($(compgen -W "bash zsh fish" -- "${cur}"))
            ;;
    esac
    return 0
}
complete -F _secrt secrt
"#;

pub const ZSH_COMPLETION: &str = r#"#compdef secrt

_secrt() {
    local -a commands
    commands=(
        'send:Encrypt and upload a secret'
        'get:Retrieve and decrypt a secret'
        'burn:Destroy a secret (requires API key)'
        'gen:Generate a random password'
        'generate:Generate a random password'
        'info:Show metadata for a secret'
        'sync:Import notes encryption key from a sync link'
        'auth:Manage authentication'
        'config:Show config / init / path'
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
                send)
                    _arguments \
                        '1:input source:(gen generate)' \
                        '--ttl[TTL for secret]:ttl:' \
                        '--api-key[API key]:key:' \
                        '--base-url[Server URL]:url:' \
                        '--json[Output as JSON]' \
                        '--text[Secret text]:text:' \
                        '--file[Secret file]:file:_files' \
                        {-s,--show}'[Show input as you type]' \
                        '--hidden[Hide input]' \
                        '--silent[Suppress status output]' \
                        {-m,--multi-line}'[Multi-line input]' \
                        '--trim[Trim whitespace]' \
                        {-Q,--qr}'[Display share URL as QR code]' \
                        {-p,--passphrase-prompt}'[Prompt for passphrase]' \
                        '--passphrase-env[Passphrase env var]:var:' \
                        '--passphrase-file[Passphrase file]:file:_files' \
                        '--help[Show help]'
                    ;;
                get)
                    _arguments \
                        {-o,--output}'[Write output to file (- for stdout)]:path:_files' \
                        '--base-url[Server URL]:url:' \
                        '--json[Output as JSON]' \
                        '--silent[Suppress status output]' \
                        {-p,--passphrase-prompt}'[Prompt for passphrase]' \
                        '--passphrase-env[Passphrase env var]:var:' \
                        '--passphrase-file[Passphrase file]:file:_files' \
                        '--help[Show help]'
                    ;;
                burn)
                    _arguments \
                        '--api-key[API key]:key:' \
                        '--base-url[Server URL]:url:' \
                        '--json[Output as JSON]' \
                        '--silent[Suppress status output]' \
                        '--help[Show help]'
                    ;;
                gen|generate)
                    _arguments \
                        '1:subcommand:(send)' \
                        {-L,--length}'[Password length]:length:' \
                        {-S,--no-symbols}'[Exclude symbols]' \
                        {-N,--no-numbers}'[Exclude digits]' \
                        {-C,--no-caps}'[Exclude uppercase letters]' \
                        {-G,--grouped}'[Group characters by type]' \
                        '--count[Generate multiple passwords]:count:' \
                        '--json[Output as JSON]' \
                        '--help[Show help]'
                    ;;
                info)
                    _arguments \
                        '--api-key[API key]:key:' \
                        '--base-url[Server URL]:url:' \
                        '--json[Output as JSON]' \
                        '--silent[Suppress output]' \
                        '--help[Show help]'
                    ;;
                sync)
                    _arguments \
                        '--api-key[API key]:key:' \
                        '--base-url[Server URL]:url:' \
                        '--silent[Suppress output]' \
                        '--help[Show help]'
                    ;;
                auth)
                    _arguments \
                        '1:subcommand:(login setup status logout)' \
                        '--base-url[Server URL]:url:'
                    ;;
                config)
                    _arguments \
                        '1:subcommand:(init path set-passphrase delete-passphrase)' \
                        '--force[Overwrite existing config file]'
                    ;;
                completion)
                    _arguments '1:shell:(bash zsh fish)'
                    ;;
            esac
            ;;
    esac
}

_secrt
"#;

pub const FISH_COMPLETION: &str = r#"complete -c secrt -f
complete -c secrt -n '__fish_use_subcommand' -a send -d 'Encrypt and upload a secret'
complete -c secrt -n '__fish_use_subcommand' -a get -d 'Retrieve and decrypt a secret'
complete -c secrt -n '__fish_use_subcommand' -a burn -d 'Destroy a secret (requires API key)'
complete -c secrt -n '__fish_use_subcommand' -a gen -d 'Generate a random password'
complete -c secrt -n '__fish_use_subcommand' -a generate -d 'Generate a random password'
complete -c secrt -n '__fish_use_subcommand' -a info -d 'Show metadata for a secret'
complete -c secrt -n '__fish_use_subcommand' -a sync -d 'Import notes encryption key from a sync link'
complete -c secrt -n '__fish_use_subcommand' -a auth -d 'Manage authentication'
complete -c secrt -n '__fish_use_subcommand' -a config -d 'Show config / init / path'
complete -c secrt -n '__fish_use_subcommand' -a version -d 'Show version'
complete -c secrt -n '__fish_use_subcommand' -a help -d 'Show help'
complete -c secrt -n '__fish_use_subcommand' -a completion -d 'Output shell completion script'

complete -c secrt -n '__fish_seen_subcommand_from send' -l ttl -d 'TTL for secret'
complete -c secrt -n '__fish_seen_subcommand_from send' -l api-key -d 'API key'
complete -c secrt -n '__fish_seen_subcommand_from send' -l base-url -d 'Server URL'
complete -c secrt -n '__fish_seen_subcommand_from send' -l json -d 'Output as JSON'
complete -c secrt -n '__fish_seen_subcommand_from send' -l text -d 'Secret text'
complete -c secrt -n '__fish_seen_subcommand_from send' -l file -d 'Secret file' -F
complete -c secrt -n '__fish_seen_subcommand_from send' -s s -l show -d 'Show input as you type'
complete -c secrt -n '__fish_seen_subcommand_from send' -l hidden -d 'Hide input'
complete -c secrt -n '__fish_seen_subcommand_from send' -l silent -d 'Suppress status output'
complete -c secrt -n '__fish_seen_subcommand_from send' -s m -l multi-line -d 'Multi-line input'
complete -c secrt -n '__fish_seen_subcommand_from send' -l trim -d 'Trim whitespace'
complete -c secrt -n '__fish_seen_subcommand_from send' -s Q -l qr -d 'Display share URL as QR code'
complete -c secrt -n '__fish_seen_subcommand_from send' -s p -l passphrase-prompt -d 'Prompt for passphrase'
complete -c secrt -n '__fish_seen_subcommand_from send' -l passphrase-env -d 'Passphrase env var'
complete -c secrt -n '__fish_seen_subcommand_from send' -l passphrase-file -d 'Passphrase file' -F
complete -c secrt -n '__fish_seen_subcommand_from send' -a 'gen generate' -d 'Generate and share a password'

complete -c secrt -n '__fish_seen_subcommand_from get' -s o -l output -d 'Write output to file (- for stdout)' -F
complete -c secrt -n '__fish_seen_subcommand_from get' -l base-url -d 'Server URL'
complete -c secrt -n '__fish_seen_subcommand_from get' -l json -d 'Output as JSON'
complete -c secrt -n '__fish_seen_subcommand_from get' -l silent -d 'Suppress status output'
complete -c secrt -n '__fish_seen_subcommand_from get' -s p -l passphrase-prompt -d 'Prompt for passphrase'
complete -c secrt -n '__fish_seen_subcommand_from get' -l passphrase-env -d 'Passphrase env var'
complete -c secrt -n '__fish_seen_subcommand_from get' -l passphrase-file -d 'Passphrase file' -F

complete -c secrt -n '__fish_seen_subcommand_from burn' -l api-key -d 'API key'
complete -c secrt -n '__fish_seen_subcommand_from burn' -l base-url -d 'Server URL'
complete -c secrt -n '__fish_seen_subcommand_from burn' -l json -d 'Output as JSON'
complete -c secrt -n '__fish_seen_subcommand_from burn' -l silent -d 'Suppress status output'

complete -c secrt -n '__fish_seen_subcommand_from gen generate' -s L -l length -d 'Password length'
complete -c secrt -n '__fish_seen_subcommand_from gen generate' -s S -l no-symbols -d 'Exclude symbols'
complete -c secrt -n '__fish_seen_subcommand_from gen generate' -s N -l no-numbers -d 'Exclude digits'
complete -c secrt -n '__fish_seen_subcommand_from gen generate' -s C -l no-caps -d 'Exclude uppercase letters'
complete -c secrt -n '__fish_seen_subcommand_from gen generate' -s G -l grouped -d 'Group characters by type'
complete -c secrt -n '__fish_seen_subcommand_from gen generate' -l count -d 'Generate multiple passwords'
complete -c secrt -n '__fish_seen_subcommand_from gen generate' -l json -d 'Output as JSON'
complete -c secrt -n '__fish_seen_subcommand_from gen generate' -a 'send' -d 'Generate and share a password'

complete -c secrt -n '__fish_seen_subcommand_from info' -l api-key -d 'API key'
complete -c secrt -n '__fish_seen_subcommand_from info' -l base-url -d 'Server URL'
complete -c secrt -n '__fish_seen_subcommand_from info' -l json -d 'Output as JSON'
complete -c secrt -n '__fish_seen_subcommand_from info' -l silent -d 'Suppress output'

complete -c secrt -n '__fish_seen_subcommand_from sync' -l api-key -d 'API key'
complete -c secrt -n '__fish_seen_subcommand_from sync' -l base-url -d 'Server URL'
complete -c secrt -n '__fish_seen_subcommand_from sync' -l silent -d 'Suppress output'

complete -c secrt -n '__fish_seen_subcommand_from auth' -a 'login setup status logout' -d 'Auth subcommand'
complete -c secrt -n '__fish_seen_subcommand_from auth' -l base-url -d 'Server URL'

complete -c secrt -n '__fish_seen_subcommand_from config' -a 'init path set-passphrase delete-passphrase' -d 'Config subcommand'
complete -c secrt -n '__fish_seen_subcommand_from config' -l force -d 'Overwrite existing config file'

complete -c secrt -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
"#;
