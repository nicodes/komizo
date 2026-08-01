if [ -f __SYSTEM_LOG__ ]; then
	tail -c 4000000 __SYSTEM_LOG__ 2>/dev/null | awk -F'\t' -v from=__FROM__ -v to=__TO__ '
		$1 == "S" && $2 + 0 >= from && $2 + 0 <= to'
fi
