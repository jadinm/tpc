# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
	# Every Vagrant development environment requires a box. You can search for
	# boxes at https://atlas.hashicorp.com/search.
	config.vm.box = "segment-routing/ubuntu-16.04"

	config.vm.network "private_network", ip: "192.168.121.43"

	config.vm.synced_folder ".", "/home/vagrant/SR-ICMP-router", rsync__exclude: ["kernel/", "sr-rerouted", "sr-endhostd", "*.o", "linux-*"]

	config.vm.provision "shell", inline: <<-SHELL
		if ! which puppet; then
			apt-get update
			apt-get install -y puppet-common
		fi
	SHELL

	config.vm.provision "puppet" do |puppet|
		puppet.options = "--verbose --debug --parser future"
	end

	config.ssh.forward_x11 = true

	config.vm.provider "virtualbox" do |v|
		v.memory = 4096
		v.cpus = 4
		v.name = "srv6-rerouting"
	end
	config.vm.provider "libvirt" do |libvirt|
		libvirt.memory = 4096
		libvirt.cpus = 4
		libvirt.qemuargs :value => '-s' # XXX You have to turn off KASLR if necessary by adding “nokaslr” to the kernel command line to use gdb to debug the linux kernel
	end
end

