#!/system/bin/sh
# nhddctl - NHDD Control Script
# Quick wrapper for common NHDD operations
# Usage: nhddctl <command> [args]

NHDD="/data/local/tmp/nhdd"
DEFAULT_DIR="/data/local/tmp/nhdd_dump"

scan() {
    local target="$1"
    local dir="${2:-$DEFAULT_DIR}"
    if [ -z "$target" ]; then
        echo "Usage: nhddctl scan <pid|package> [output_dir]"
        return 1
    fi
    $NHDD "$target" "$dir"
}

dump() {
    local pkg="$1"
    local dir="${2:-$DEFAULT_DIR}"
    if [ -z "$pkg" ]; then
        echo "Usage: nhddctl dump <package> [output_dir]"
        return 1
    fi
    echo "[*] Force stopping $pkg..."
    am force-stop "$pkg"
    sleep 1
    echo "[*] Launching $pkg..."
    monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
    echo "[*] Waiting for app to load (4s)..."
    sleep 4
    echo "[*] Running NHDD..."
    $NHDD "$pkg" "$dir"
}

case "${1:-}" in
    scan) scan "$2" "$3" ;;
    dump) dump "$2" "$3" ;;
    *)
        echo "NHDD - No-Hook DEX Dumper Control"
        echo "Usage: nhddctl <command> [args]"
        echo ""
        echo "Commands:"
        echo "  scan <pid|package> [dir]  Scan running app for DEX files"
        echo "  dump <package> [dir]      Restart app + scan (quick dump)"
        ;;
esac
