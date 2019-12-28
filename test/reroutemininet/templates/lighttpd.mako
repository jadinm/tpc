server.document-root = "${node.lighttpd.web_dir}"
dir-listing.activate = "enable"
server.pid-file      = "${node.lighttpd.pid_file}"
server.errorlog      = "${node.lighttpd.logfile}"

# listen to ipv4
server.bind = "0.0.0.0"
server.port = ${node.lighttpd.port}
# listen to ipv6
$SERVER["socket"] == "[::]:${node.lighttpd.port}" {  }
