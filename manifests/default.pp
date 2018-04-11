$default_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

$zlog_version = "1.2.12"
$zlog_release_url = "https://github.com/HardySimpson/zlog/archive/${zlog_version}.tar.gz"
$zlog_root_dir = "/home/vagrant"
$zlog_source_path = "${zlog_root_dir}/zlog-${zlog_version}"
$zlog_download_path = "${zlog_source_path}.tar.gz"
$zlog_path = "/usr/local/lib/libzlog.so"

$srnmininet_repo = "https://bitbucket.org/jadinm/srnmininet.git"
$srnmininet_path = "/home/vagrant/srnmininet"
$srn_bin_path = "/home/vagrant/srn/bin"

Package {
  allow_virtual => true,
  ensure        => installed,
  require       => Exec['apt-update'],
}
Exec { path => $default_path }

exec { 'apt-update':
  command => 'apt-get update',
}

# Miscellaneous
package { 'git': }

# SRN and SRNMininet
exec { 'srnmininet-download':
  require => Package['git'],
  creates => $srnmininet_path,
  command => "git clone ${srnmininet_repo} ${srnmininet_path}",
}
exec { 'srnmininet-provision':
  require => [ Exec['srnmininet-download'] ],
  creates => $srn_bin_path,
  cwd     => $srnmininet_path,
  command => "puppet apply --verbose --debug --parser future manifests/default.pp",
  timeout => 1800,
}

# Project depedencies
exec { 'zlog-download':
  require => Exec['apt-update'],
  creates => $zlog_source_path,
  command => "wget -O - ${zlog_release_url} > ${zlog_download_path} &&\
              tar -xvzf ${zlog_download_path} -C ${zlog_root_dir};"
}
exec { 'zlog':
  require => [ Exec['apt-update'], Exec['zlog-download'] ],
  cwd => $zlog_source_path,
  creates => $zlog_path,
  path => "${default_path}:${zlog_source_path}",
  command => "make &&\
              make install &&\
	      /sbin/ldconfig -v &&\
              rm ${zlog_download_path};"
}
package { 'libmnl-dev': }
package { 'libnetfilter-queue-dev': }

# Activate ECN
exec { 'ecn':
  command => "bash -c 'if ! cat /etc/sysctl.conf | grep net.ipv4.tcp_ecn=1; then echo net.ipv4.tcp_ecn=1 >> /etc/sysctl.conf; fi'",
}

