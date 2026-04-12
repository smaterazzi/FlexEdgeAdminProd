#!/bin/bash
#
# FlexEdgeAdmin - SMC Management CLI Launcher
# Usage: ./smc.sh [--tenant ID] <command> [options]
#

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Virtual environment path (at project root)
VENV_PATH="$PROJECT_ROOT/venv"

# Ensure shared module is importable
export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_color() {
    echo -e "${1}${2}${NC}"
}

# Activate venv if present
activate_venv() {
    if [ -d "$VENV_PATH" ]; then
        source "$VENV_PATH/bin/activate"
    fi
}

# Parse --tenant flag before the command
TENANT_ARGS=()
while [[ "$1" == --tenant || "$1" == -t ]]; do
    TENANT_ARGS+=("$1" "$2")
    shift 2
done

show_help() {
    echo ""
    print_color "$BLUE" "FlexEdgeAdmin - SMC Management CLI"
    echo "========================================"
    echo ""
    echo "Usage: ./smc.sh [--tenant ID] <command> [options]"
    echo ""
    print_color "$GREEN" "Global Options:"
    echo ""
    echo "  --tenant ID, -t ID         Use tenant from tenants.json"
    echo "                             (or set DEFAULT_TENANT env var)"
    echo "  SMC_API_KEY=...            API key (env var, required for tenant mode)"
    echo ""
    print_color "$GREEN" "Commands:"
    echo ""
    echo "  connect                    Test SMC connection"
    echo ""
    echo "  inquiry <options>          Query SMC objects"
    echo "    --list-types             List available object types"
    echo "    --type TYPE              Object type to query"
    echo "    --name NAME              Filter by name"
    echo "    --details                Show full details"
    echo ""
    echo "  firewall <subcommand>      Manage firewalls"
    echo "    list                     List all firewalls"
    echo "    show --name NAME         Show firewall details"
    echo "    interfaces --name NAME   List interfaces"
    echo "    add-interface            Add Layer 3 interface"
    echo "    add-vlan                 Add VLAN sub-interface"
    echo "    add-ip                   Add IP to interface"
    echo "    delete-interface         Delete interface"
    echo "    update-interface         Update interface"
    echo "    refresh --name NAME      Refresh policy"
    echo "    upload --name NAME       Upload policy"
    echo "    pending --name NAME      View pending changes"
    echo ""
    print_color "$GREEN" "Quick Examples:"
    echo ""
    echo "  SMC_API_KEY=xxx ./smc.sh --tenant prod connect"
    echo "  ./smc.sh firewall list"
    echo "  ./smc.sh inquiry --list-types"
    echo ""
    print_color "$GREEN" "Documentation:"
    echo ""
    echo "  ./smc.sh help connect      Show connect.py guide"
    echo "  ./smc.sh help inquiry      Show inquiry.py guide"
    echo "  ./smc.sh help firewall     Show firewall.py guide"
    echo ""
}

show_module_help() {
    local module=$1
    local doc_file="$PROJECT_ROOT/docs/cli/${module}.md"

    if [ -f "$doc_file" ]; then
        if command -v less &> /dev/null; then
            less "$doc_file"
        elif command -v more &> /dev/null; then
            more "$doc_file"
        else
            cat "$doc_file"
        fi
    else
        print_color "$RED" "Error: Documentation not found for '$module'"
        echo "Available: connect, inquiry, firewall"
    fi
}

# Main script logic
case "$1" in
    ""|"-h"|"--help"|"help")
        if [ -n "$2" ]; then
            show_module_help "$2"
        else
            show_help
        fi
        ;;

    "connect")
        activate_venv
        python "$SCRIPT_DIR/connect.py" "${TENANT_ARGS[@]}" "${@:2}"
        ;;

    "inquiry")
        activate_venv
        python "$SCRIPT_DIR/inquiry.py" "${TENANT_ARGS[@]}" "${@:2}"
        ;;

    "firewall"|"fw")
        activate_venv
        python "$SCRIPT_DIR/firewall.py" "${TENANT_ARGS[@]}" "${@:2}"
        ;;

    "setup")
        print_color "$BLUE" "Setting up FlexEdgeAdmin..."
        cd "$PROJECT_ROOT"

        if [ ! -d "$VENV_PATH" ]; then
            print_color "$YELLOW" "Creating virtual environment..."
            python3 -m venv venv
        fi

        print_color "$YELLOW" "Activating virtual environment..."
        source "$VENV_PATH/bin/activate"

        print_color "$YELLOW" "Installing dependencies..."
        pip install -r requirements.txt

        # Copy example configs if real ones don't exist
        if [ ! -f "$PROJECT_ROOT/config/tenants.json" ]; then
            cp "$PROJECT_ROOT/config/tenants.json.example" "$PROJECT_ROOT/config/tenants.json"
            print_color "$YELLOW" "Created config/tenants.json from template — edit with your SMC details"
        fi

        print_color "$GREEN" "Setup complete!"
        echo ""
        echo "Next steps:"
        echo "  1. Edit config/tenants.json with your SMC server details"
        echo "  2. Set SMC_API_KEY environment variable"
        echo "  3. Run: ./smc.sh --tenant prod connect"
        ;;

    *)
        print_color "$RED" "Unknown command: $1"
        echo "Run './smc.sh help' for usage information"
        exit 1
        ;;
esac
