[formats]
timefmt = "%d(%d-%m (%T.ms)) %-5V [%p:%F:%L] %m%n"

[rules]
*.*         "${node["zlog"].logfile}"; timefmt
