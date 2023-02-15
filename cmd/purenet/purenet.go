package main

import (
	"github.com/flotter/purenet/daemon"
)

// Netplan compatible YAML
var netplan=`
network:
  version: 1
  renderer: pebble
  ethernets:
    eth0:
      dhcp4: true      
    eth1:
      dhcp4: true
  wifis:
    wlan0:
      dhcp4: true
      access-points:
        OPEN_WIFI:
          password:
        BHES_OFFICE:
          password: gifappel
`

func main() {
	// Start the network manager
	daemon.Start(netplan)
}
