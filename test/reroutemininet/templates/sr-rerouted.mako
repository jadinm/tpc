{
% for key in node["sr-rerouted"].extras:
    % if type(node["sr-rerouted"].extras[key]) == int:
    "${key}": ${node["sr-rerouted"].extras[key]},
    % else:
    "${key}": "${node["sr-rerouted"].extras[key]}",
    % endif
% endfor
    "zlogfile": "${node["sr-rerouted"].zlog_cfg_filename}",
    "ovsdb-server": "${node["sr-rerouted"].ovsdb_server}",
    "ovsdb-database": "${node["sr-rerouted"].ovsdb_database}",
    "ovsdb-client": "${node["sr-rerouted"].ovsdb_client}",
    "ntransacts": ${node["sr-rerouted"].ntransacts}
}
