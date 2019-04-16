$default_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

$srnmininet_repo = "https://bitbucket.org/jadinm/srnmininet.git"
$srnmininet_path = "/home/vagrant/srnmininet"
$srn_bin_path = "/home/vagrant/srn/bin"

$scapy_repo = "https://github.com/segment-routing/scapy.git"
$scapy_path = "/home/vagrant/scapy"

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
package {'libelf-dev': }  # Needed for virtualbox guest additions to work even after new kernel install
package { 'git': }
package { 'python-pip': }
package { 'iperf3': }
package { 'matplotlib':
  require => Package['python-pip'],
  provider => 'pip',
}
package { 'scipy':
  require  => Package['python-pip'],
  provider => 'pip',
}
package { 'python-tk': }
exec { 'download-scapy':
  require => Package['git'],
  creates => $scapy_path,
  command => "git clone ${scapy_repo} ${scapy_path} && chown -R vagrant:vagrant ${scapy_path}"
}
exec { 'scapy':
  require  => Package['python-pip'],
  command => "pip install -e ${scapy_path}",
}

# SRN and SRNMininet
exec { 'srnmininet-download':
  require => Package['git'],
  creates => $srnmininet_path,
  command => "git clone ${srnmininet_repo} ${srnmininet_path} && chown -R vagrant:vagrant ${srnmininet_path}",
}
exec { 'srnmininet-provision':
  require => [ Exec['srnmininet-download'] ],
  creates => $srn_bin_path,
  cwd     => $srnmininet_path,
  command => "puppet apply --verbose --debug --parser future manifests/default.pp",
  timeout => 1800,
}

# Project depedencies
package { 'libmnl-dev': }
package { 'libnetfilter-queue-dev': }

# Activate ECN
exec { 'ecn':
  command => "bash -c 'if ! cat /etc/sysctl.conf | grep net.ipv4.tcp_ecn=1; then echo net.ipv4.tcp_ecn=1 >> /etc/sysctl.conf; fi'",
}

