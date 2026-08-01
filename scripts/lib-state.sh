komizo_state() {
	sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1
}
