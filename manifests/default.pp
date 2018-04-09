$default_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

$quagga_version = "1.2.4"
$quagga_release_url = "http://download.savannah.gnu.org/releases/quagga/quagga-${quagga_version}.tar.gz"
$quagga_root_dir = "/home/vagrant"
$quagga_source_path = "${quagga_root_dir}/quagga-${quagga_version}"
$quagga_download_path = "${quagga_source_path}.tar.gz"
$quagga_path = "/home/vagrant/quagga"

$zlog_version = "1.2.12"
$zlog_release_url = "https://github.com/HardySimpson/zlog/archive/${zlog_version}.tar.gz"
$zlog_root_dir = "/home/vagrant"
$zlog_source_path = "${zlog_root_dir}/zlog-${zlog_version}"
$zlog_download_path = "${zlog_source_path}.tar.gz"
$zlog_path = "/usr/local/lib/libzlog.so"

$ipmininet_repo = "https://github.com/oliviertilmans/ipmininet.git"
$ipmininet_path = "/home/vagrant/ipmininet"
$sr6mininet_repo = "https://bitbucket.org/jadinm/sr6mininet.git"
$sr6mininet_path = "/home/vagrant/sr6mininet"

Package {
  allow_virtual => true,
  ensure        => installed,
  require       => Exec['apt-update'],
}
Exec { path => $default_path }

exec { 'apt-update':
  command => 'apt-get update',
}

# Python packages
package { 'python-setuptools': }
package { 'python-pip': }
package { 'py2-ipaddress':
  require  => Package['python-pip'],
  provider => 'pip',
}
package { 'mako':
  require  => Package['python-pip'],
  provider => 'pip',
}
package { 'six':
  require  => Package['python-pip'],
  provider => 'pip',
}

# Networking
package { 'wireshark': }
package { 'traceroute': }
package { 'tcpdump': }
package { 'bridge-utils': }
package { 'mininet': }
package { 'radvd': }

# Compilation
package { 'libreadline6': }
package { 'libreadline6-dev':
  require => [ Exec['apt-update'], Package['libreadline6'] ],
}
package { 'gawk': }
package { 'automake': }
package { 'libtool':
  require => [ Exec['apt-update'], Package['m4'], Package['automake'] ],
}
package { 'm4': }
package { 'bison': }
package { 'flex': }
package { 'pkg-config': }
package { 'dia': }
package { 'texinfo': }
package { 'libc-ares-dev': }
package { 'cmake': }

# Miscellaneous
package { 'xterm': }
package { 'man': }
package { 'git': }
package { 'valgrind': }
package { 'vim': }

# SSH redirection
package { 'xauth': }

# Locale settings
exec { 'locales':
  require => Exec['apt-update'],
  command => "locale-gen fr_BE.UTF-8; update-locale",
}

# IPMininet

exec { 'ipmininet-download':
  require => Package['git'],
  creates => $ipmininet_path,
  command => "git clone ${ipmininet_repo} ${ipmininet_path}",
}
exec { 'ipmininet':
  require => [ Exec['apt-update'], Package['mininet'], Package['mako'], Exec['ipmininet-download'] ],
  command => "pip install -e ${ipmininet_path}",
}
exec { 'sr6mininet-download':
  require => Package['git'],
  creates => $sr6mininet_path,
  command => "git clone ${sr6mininet_repo} ${sr6mininet_path}",
}
exec { 'sr6mininet':
  require => [ Exec['apt-update'], Package['mininet'], Package['mako'], Exec['ipmininet'], Exec['sr6mininet-download'] ],
  command => "pip install -e ${sr6mininet_path}",
}

# Quagga

$compilation = [ Exec['locales'], Package['libreadline6-dev'], Package['gawk'], Package['libtool'], Package['libc-ares-dev'], Package['bison'], Package['flex'], Package['pkg-config'], Package['dia'], Package['texinfo'] ]

exec { 'quagga-download':
  require => Exec['apt-update'],
  creates => $quagga_source_path,
  command => "wget -O - ${quagga_release_url} > ${quagga_download_path} &&\
              tar -xvzf ${quagga_download_path} -C ${quagga_root_dir};"
}
exec { 'quagga':
  require => [ Exec['apt-update'], Exec['quagga-download'] ] + $compilation,
  cwd => $quagga_source_path,
  creates => $quagga_path,
  path => "${default_path}:${quagga_source_path}",
  command => "configure --prefix=${quagga_path} &&\
              make &&\
              make install &&\
              rm ${quagga_download_path} &&\
              echo \"# quagga binaries\" >> /etc/profile &&\
              echo \"PATH=\\\"${quagga_path}/bin:${quagga_path}/sbin:\\\$PATH\\\"\" >> /etc/profile &&\
              echo \"alias sudo=\'sudo env \\\"PATH=\\\$PATH\\\"\'\" >> /etc/profile &&\
              echo \"# quagga binaries\" >> /root/.bashrc &&\
              echo \"PATH=\\\"${quagga_path}/bin:${quagga_path}/sbin:\\\$PATH\\\"\" >> /root/.bashrc &&\
              PATH=${quagga_path}/sbin:${quagga_path}/bin:\$PATH;",
}

group { 'quagga':
  ensure => 'present',
}
user { 'vagrant':
  groups => 'quagga',
}
user { 'root':
  groups => 'quagga',
}

# Project depedencies
exec { 'zlog-download':
  require => Exec['apt-update'],
  creates => $zlog_source_path,
  command => "wget -O - ${zlog_release_url} > ${zlog_download_path} &&\
              tar -xvzf ${zlog_download_path} -C ${zlog_root_dir};"
}
exec { 'zlog':
  require => [ Exec['apt-update'], Exec['zlog-download'] ] + $compilation,
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
  command => "if ! cat /etc/sysctl.conf | grep net.ipv4.tcp_ecn=1; then echo \"net.ipv4.tcp_ecn=1\" >> /etc/sysctl.conf; fi;",
}

