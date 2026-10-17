#!/usr/bin/env bash
set -euo pipefail
project_root="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
extras=''
case "${1:-}" in
    -h|--help)
        cat <<'HELP'
Uso: bash /caminho/PenPilot/install.sh [--screenshots]

Instala o pacote no .venv do projeto e cria ~/.local/bin/penpilot.
Não precisa de sudo. Configura o PATH no Bash e no Zsh, se presente.
--screenshots  Instala também Playwright (o navegador é instalado separadamente).
-h, --help     Mostra esta ajuda.
HELP
        exit 0 ;;
    --screenshots) extras='[screenshots]' ;;
    '') ;;
    *) echo "Opção desconhecida: $1. Use -h." >&2; exit 2 ;;
esac
if (( $# > 1 )); then echo 'Use install.sh -h para ver as opções.' >&2; exit 2; fi
launcher_path="$HOME/.local/bin/penpilot"
if [[ -e "$launcher_path" || -L "$launcher_path" ]]; then
    if [[ "$(readlink -f -- "$launcher_path")" != "$project_root/penpilot.sh" ]]; then
        echo "Já existe outro comando em $launcher_path; nenhum arquivo foi substituído." >&2
        exit 1
    fi
fi
if [[ ! -x "$project_root/.venv/bin/python" ]]; then
    python3 -m venv "$project_root/.venv"
fi
"$project_root/.venv/bin/python" -m pip install -e "$project_root$extras"
mkdir -p -- "$HOME/.local/bin"
ln -sfn -- "$project_root/penpilot.sh" "$launcher_path"
# Interactive terminals do not necessarily load ~/.profile.
path_marker='# PenPilot: comandos locais do usuário'
for shell_rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ "$shell_rc" == "$HOME/.bashrc" || -f "$shell_rc" ]] || continue
    if ! grep -Fq "$path_marker" "$shell_rc" 2>/dev/null; then
        cat >> "$shell_rc" <<'SHELL_PATH'

# PenPilot: comandos locais do usuário
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH" ;;
esac
SHELL_PATH
    fi
done
echo 'PATH configurado para novos terminais. Em um terminal já aberto, execute:'
echo '  export PATH="$HOME/.local/bin:$PATH"'
printf '\nInstalado: %s\n'  "$launcher_path"
case ":$PATH:" in
    *":$HOME/.local/bin:"*) echo 'Teste em qualquer pasta: penpilot -h' ;;
    *) printf 'Nesta sessão, ative o comando com:\n  export PATH="$HOME/.local/bin:$PATH"\nDepois: penpilot -h\n' ;;
esac
if [[ -n "$extras" ]]; then
    printf 'Se não houver Chromium instalado, execute:\n  "%s/.venv/bin/python" -m playwright install chromium\n' "$project_root"
fi
