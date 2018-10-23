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
	config.ssh.forward_x11 = true

	config.vm.network :private_network, ip: "192.167.0.140"

	config.vm.synced_folder ".", "/home/vagrant/SR-ICMP-router"

	config.vm.provision "shell", inline: <<-SHELL
		if ! which puppet; then
			apt-get update
			apt-get install -y puppet-common
		fi
	SHELL

	config.vm.provision "puppet" do |puppet|
		puppet.options = "--verbose --debug --parser future"
	end

	config.vm.provider "virtualbox" do |v|
		v.name = "srv6-rerouting"
		v.customize ["modifyvm", :id, "--cpuexecutioncap", "50"]
		v.customize ["modifyvm", :id, "--cpus", "2"]
		v.customize ["modifyvm", :id, "--memory", "2048"]
	end
end

