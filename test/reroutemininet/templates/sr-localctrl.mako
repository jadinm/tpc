{
% for key in node["sr-localctrl"].extras:
    % if type(node["sr-localctrl"].extras[key]) == int:
    "${key}": ${node["sr-localctrl"].extras[key]},
    % else:
    "${key}": "${node["sr-localctrl"].extras[key]}",
    % endif
% endfor
    "zlogfile": "${node["sr-localctrl"].zlog_cfg_filename}",
    "ovsdb-server": "${node["sr-localctrl"].ovsdb_server}",
    "ovsdb-database": "${node["sr-localctrl"].ovsdb_database}",
    "ovsdb-client": "${node["sr-localctrl"].ovsdb_client}",
    "ntransacts": ${node["sr-localctrl"].ntransacts},
    "dest_map_id": ${node["sr-localctrl"].dest_map_id}
}
