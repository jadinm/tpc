# Router daemons

*activate_rerouting* installs the approriate tc and iptable rules

A netfilter program is run to catch packets marked by tc and sen them to a controller.
*nf_queue* (obtained after running `make`) is this program 

