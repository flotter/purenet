package daemon

import (
	"fmt"
	"log"
	"net"
	"time"
	"io/ioutil"
	"strings"
	"os"
	"os/signal"
	"syscall"

	"github.com/jsimonetti/rtnetlink"
	"github.com/jsimonetti/rtnetlink/rtnl"
        "github.com/mdlayher/netlink"
        "github.com/mdlayher/wifi"
        "golang.org/x/sys/unix"
//	"github.com/davecgh/go-spew/spew"
	"gopkg.in/yaml.v3"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"
	"github.com/insomniacslk/dhcp/netboot"
	probing "github.com/prometheus-community/pro-bing"
)

type Eth struct {
	Dhcp4 bool    			`yaml:"dhcp4"`
}

type Wifi struct {
	Dhcp4 bool                      `yaml:"dhcp4"`
	Aps map[string] struct {
		Password string         `yaml:"password"`
	}				`yaml:"access-points"`
}

type Plan struct {
	Network struct {
		Version int				`yaml:"version"`
		Renderer string				`yaml:"renderer"`
		Ethernets map[string] *Eth		`yaml:"ethernets"`
		Wifis map[string] *Wifi			`yaml:"wifis"`
	}						`yaml:"network"`
}

type ManagedIface struct {
	wifi *Wifi
	apOrder []string // Order of WIFI access points
	eth *Eth
}

type ManagedInterfaces map[string]ManagedIface
type ManagedInterfacesLookup struct {
	m ManagedInterfaces
	ifOrder []string // Order of network interfaces
}

type State int
const (
	STATE_UNKNOWN State = iota
	STATE_NO_IFACE
	STATE_WIFI_AP
	STATE_IFACE
	STATE_IFACE_WAIT
	STATE_IFACE_UP
	STATE_IFACE_IP
	STATE_IFACE_INTERNET
	STATE_IFACE_RESET
)

func PrintState(s State) string {
	switch s {
	case STATE_NO_IFACE:
		return "STATE_NO_IFACE"
	case STATE_WIFI_AP:
		return "STATE_WIFI_AP"
	case STATE_IFACE:
		return "STATE_IFACE"
	case STATE_IFACE_WAIT:
		return "STATE_IFACE_WAIT"
	case STATE_IFACE_UP:
		return "STATE_IFACE_UP"
	case STATE_IFACE_IP:
		return "STATE_IFACE_IP"
	case STATE_IFACE_INTERNET:
		return "STATE_IFACE_INTERNET"
	case STATE_IFACE_RESET:
		return "STATE_IFACE_RESET"
	}
	return "STATE_UNKNOWN"
}

type StateMachine struct {
	ifaces ManagedInterfacesLookup		// Information composed from the Netplan YAML
	currentIface string			// Selected interface
	cstate State				// Current state
	start  time.Time			// When we entered a new state
	pstate State				// Previous state
	interfaceRetries int			// How many retries of same interface of lost internet
	interfaceHadInternet bool		// Is our first attempt on this interface a failure
	wifiInterface *wifi.Interface		// Wifi interface structure
	currentApName string			// Currently used access point
}

// State machine state timeout. If the state machine is stuck in one state
// without the expected events taking place, we need a way to recover.
const STATE_TIMEOUT = (time.Second * 10)

// If internet stops working, retry the same interface before selecting the
// next available interface
const NO_INTERNET_RETRIES = 3

// Network Event Handler (and state machine)
func HandleEvent(s *StateMachine) {

	if s.pstate != s.cstate {
		if s.cstate == STATE_NO_IFACE {
			fmt.Printf("State: %s\n",PrintState(s.cstate))
		} else {
			fmt.Printf("State: %s (%s)\n",PrintState(s.cstate), s.currentIface)
		}

		// Record state entry
		s.start = time.Now()
	}
	s.pstate = s.cstate

	switch s.cstate {

	case STATE_NO_IFACE:
		// Select an interface
		s.interfaceRetries = 0
		s.currentApName = ""
		s.wifiInterface = nil
		s.interfaceHadInternet = false
		s.currentIface = findNextManagedInterface(s.ifaces, s.currentIface)
		if s.currentIface != "" {

			wifiClient, err := wifi.New()
			if err != nil {
				fmt.Printf("WIFI NL802.11 handle failed ...(%v)\n", err)
				os.Exit(1)
			}
			defer wifiClient.Close()

			// Is this a WIFI interface?
			ifaces, err := wifiClient.Interfaces()
			if err != nil {
				fmt.Printf("Cannot enumarate WIFI interfaces ...(%v)\n", err)
				os.Exit(1)
			}
			for _, wiface := range ifaces {
				if wiface.Name == s.currentIface {
					s.wifiInterface = wiface
				}
			}

			if s.wifiInterface != nil {
				fmt.Printf("WIFI Interface %s selected ...\n", s.currentIface)
				s.cstate = STATE_WIFI_AP
				break
			} else {
				fmt.Printf("Eternet Interface %s selected ...\n", s.currentIface)
				s.cstate = STATE_IFACE
				break
			}
		}

	case STATE_WIFI_AP:
		// Select the next WIFI AP for the current WIFI interface
		s.currentApName = findNextManagedInterfaceWifiAP(s.ifaces, s.currentIface, s.currentApName)
		fmt.Printf("Interface '%s' will attempt WIFI AP %s ...\n", s.currentIface, s.currentApName)

		if s.currentApName == "" {
			// We tried all available APs - end of the list
			// Lets pick another interface
			fmt.Printf("No more access points to try for interface %s ...\n", s.currentIface)
			s.cstate = STATE_NO_IFACE
			break
		} else {
			s.cstate = STATE_IFACE
			break
		}

	case STATE_IFACE:
		// Admin up
		fmt.Println("Interface UP requested ...")
		err := action_up(s.currentIface)
		if err != nil {
			fmt.Printf("Interface failure ...(%v)\n", err)
			s.cstate = STATE_NO_IFACE
			break
		}

		// Is this a WIFI interface?
		if s.wifiInterface != nil {
			wifiClient, err := wifi.New()
			if err != nil {
				fmt.Printf("WIFI NL802.11 handle failed ...(%v)\n", err)
				os.Exit(1)
			}
			defer wifiClient.Close()
			// Do we have a password?
			if s.ifaces.m[s.currentIface].wifi.Aps[s.currentApName].Password != "" {
				pass := s.ifaces.m[s.currentIface].wifi.Aps[s.currentApName].Password
				wifiClient.ConnectWPAPSK(s.wifiInterface, s.currentApName, pass)
				if err != nil {
					fmt.Printf("Connection failed (WPA PSK) ...(%v)\n", err)
					s.cstate = STATE_NO_IFACE
					break
				}
			} else {
				err := wifiClient.Connect(s.wifiInterface, s.currentApName)
				if err != nil {
					fmt.Printf("Connection failed (no auth) ...(%v)\n", err)
					s.cstate = STATE_NO_IFACE
					break
				}
			}
		}

		s.cstate = STATE_IFACE_WAIT

	case STATE_IFACE_WAIT:
		// Wait until up
		up, err := state_up(s.currentIface)
		if err != nil {
			fmt.Printf("Interface failure ...(%v)\n", err)
			s.cstate = STATE_NO_IFACE
			break
		}
		if up == true {
			fmt.Println("Interface UP ...")
			s.cstate = STATE_IFACE_UP
			break
		}

		if time.Now().Sub(s.start) > STATE_TIMEOUT {
			fmt.Println("Interface timeout waiting for UP ...")
			s.cstate = STATE_IFACE_RESET
			break
		}
	case STATE_IFACE_UP:

		netconf, err := dhclient4(s.currentIface, 3, false)
		if err != nil {
                        fmt.Printf("Interface DHCP request failed ...(%v)\n", err)
                        s.cstate = STATE_IFACE_RESET
			break
		}
		err = configureInterface(s.currentIface, &netconf.NetConf)
		if err != nil {
                        fmt.Printf("Interface ROUTES setup failed ... (%v)\n", err)
                        s.cstate = STATE_IFACE_RESET
			break
		}

		s.cstate = STATE_IFACE_IP

	case STATE_IFACE_IP:
		fmt.Println("Checking internet connectivity ...")

		// WIFI stats
		if s.wifiInterface != nil {
			wifiClient, err := wifi.New()
			if err != nil {
				fmt.Printf("WIFI NL802.11 handle failed ...(%v)\n", err)
				os.Exit(1)
			}
			defer wifiClient.Close()
			sta, err := wifiClient.StationInfo(s.wifiInterface)
			if err != nil {
				fmt.Printf("Station request error ...(%v)\n", err)
			} else {
				for _, st := range sta {
					fmt.Printf("Station details: Hardware Address %v, Signal strength %ddBm\n", st.HardwareAddr, st.Signal)
				}
			}
			bss, err := wifiClient.BSS(s.wifiInterface)
			if err != nil {
				fmt.Printf("BSS request error ...(%v)\n", err)
			} else {
				fmt.Printf("BSS details: SSID %s, Hardware Address %v, Frequency %d\n", bss.SSID, bss.BSSID, bss.Frequency)
			}
		}

		pinger, err := probing.NewPinger("www.google.com")
		if err != nil {
                        fmt.Printf("Interface ping setup failed ... (%v)\n", err)
                        s.cstate = STATE_IFACE_RESET
			break
                }
		pinger.SetPrivileged(true)
		pinger.Timeout = (time.Second * 3)
		pinger.Count = 3
		pinger.Run()

		stats := pinger.Statistics()
		if stats.PacketsRecv == 0 {
                        fmt.Println("Interface ping test failed ...")
                        s.cstate = STATE_IFACE_RESET
			break
		}

		s.cstate = STATE_IFACE_INTERNET

	case STATE_IFACE_INTERNET:
		s.interfaceHadInternet = true

		if time.Now().Sub(s.start) > STATE_TIMEOUT {
			fmt.Println("Internet connectivity re-check...")
			s.cstate = STATE_IFACE_IP
			break
		}

	case STATE_IFACE_RESET:
		// If its up, remove the address, which will remove the route
		up, err := state_up(s.currentIface)
		if err != nil {
			fmt.Printf("Interface failure ...(%v)\n", err)
			s.cstate = STATE_NO_IFACE
			break
		}
	        if up == true {
			fmt.Println("Removing IP address/route ...")
			err := removeInterfaceAddr(s.currentIface)
			if err != nil {
				fmt.Printf("Interface failure ...(%v)\n", err)
				s.cstate = STATE_NO_IFACE
				break
			}
		}

		// Disconnect from the AP if we are on WIFI
		if s.wifiInterface != nil {
			wifiClient, err := wifi.New()
			if err != nil {
				fmt.Printf("WIFI NL802.11 handle failed ...(%v)\n", err)
				os.Exit(1)
			}
			defer wifiClient.Close()

			err = wifiClient.Disconnect(s.wifiInterface)
			if err != nil {
				fmt.Printf("WIFI disconnect failure ...(%v)\n", err)
			}
		}

		// Admin down it so we are sure its inactive
                fmt.Println("Interface DOWN request issued ...")
		err = action_down(s.currentIface)
		if err != nil {
			fmt.Printf("Interface failure ...(%v)\n", err)
			s.cstate = STATE_NO_IFACE
			break
		}

		if s.interfaceRetries < NO_INTERNET_RETRIES && s.interfaceHadInternet {
			s.interfaceRetries += 1

                        fmt.Printf("Recovery attempt %d using same interface ...\n", s.interfaceRetries)
                        s.cstate = STATE_IFACE
			break
		}


		if s.wifiInterface != nil {
			fmt.Println("Requesting different access point option for current WIFI interface ...")
			s.cstate = STATE_WIFI_AP
			break
		} else {
			fmt.Println("Interface temporary blacklisted ...")
			s.cstate = STATE_NO_IFACE
			break
		}
	}
}

// Init Managed interfaces list
func initManagedInterfaceList(m *ManagedInterfacesLookup, p Plan) {
	m.m = make(map[string]ManagedIface)

	// First search Ethernet
	for k, v := range p.Network.Ethernets {
		m.ifOrder = append(m.ifOrder, k)
		m.m[k] = ManagedIface{eth: v}
	}
	// Second search Wifi
	for k, v := range p.Network.Wifis {
		m.ifOrder = append(m.ifOrder, k)
		var aps []string
		for ap, _ := range v.Aps {
			aps = append (aps, ap)
		}
		m.m[k] = ManagedIface{wifi: v, apOrder: aps}
	}
}

// Use the Netplan layout to return the next interface
// to try for an internet connection (round robin).
func findNextManagedInterface(m ManagedInterfacesLookup, curr string) string {
	next := curr
	// Only if this is not the first lookup
	if curr != "" {
		// Locate current and search forward
		for _, k := range m.ifOrder {
			// Only start looking after the current interface
			if _, err := net.InterfaceByName(k); err == nil && next == "" {
				return k
			} else if next == k {
				next = ""
			}
		}
	}

	// This must be true, but set it explicitly so we cannot get
	// stuck on a dodgy interface name that does not exist.
	next = ""

	// Wrapped search until current
	for _, k := range m.ifOrder {
		// Only start looking after the current interface
		if curr == k {
			// We tried every interface
			break
		} else if _, err := net.InterfaceByName(k); err == nil {
			return k
		}
	}

	return next
}

func findNextManagedInterfaceWifiAP(m ManagedInterfacesLookup, currIface string, currAp string) string {
	// Locate current and search forward
	for _, k := range m.m[currIface].apOrder {
		// Only start looking after the current interface
		if currAp == "" {
			return k
		} else if currAp == k {
			currAp = ""
		}
	}

	return currAp
}

func action_down(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}

	// Dial a connection to the rtnetlink socket
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Request the details of the interface
	msg, err := conn.Link.Get(uint32(iface.Index))
	if err != nil {
		return err
	}

	// Set the interface operationally DOWN
	err = conn.Link.Set(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   msg.Type,
		Index:  uint32(iface.Index),
		Flags:  0,
		Change: unix.IFF_UP,
	})
	if err != nil {
		return err
	}

	return nil
}

func action_up(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}

	// Dial a connection to the rtnetlink socket
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Request the details of the interface
	msg, err := conn.Link.Get(uint32(iface.Index))
	if err != nil {
		return err
	}

	state := msg.Attributes.OperationalState
	// If the link is already up, return immediately
	if state == rtnetlink.OperStateUp || state == rtnetlink.OperStateUnknown {
		return nil
	}

	// Set the interface operationally UP
	err = conn.Link.Set(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   msg.Type,
		Index:  uint32(iface.Index),
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
	})
	if err != nil {
		return err
	}

	return nil
}

func state_up(ifname string) (bool, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return false, err
	}

	// Dial a connection to the rtnetlink socket
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Request the details of the interface
	msg, err := conn.Link.Get(uint32(iface.Index))
	if err != nil {
		return false, err
	}

	state := msg.Attributes.OperationalState
	// If the link is already up, return immediately
	if state == rtnetlink.OperStateUp || state == rtnetlink.OperStateUnknown {
		//if *msg.Attributes.Carrier == 1 {
			return true, nil
		//}
	}

	return false, nil
}

func dhclient4(ifname string, attempts int, verbose bool) (*netboot.BootConf, error) {
	if attempts < 1 {
		attempts = 1
	}
	client := client4.NewClient()
	var (
		conv []*dhcpv4.DHCPv4
		err  error
	)
	for attempt := 0; attempt < attempts; attempt++ {
		//log.Printf("Attempt %d of %d", attempt+1, attempts)
		conv, err = client.Exchange(ifname)
		if err != nil && attempt < attempts {
			//log.Printf("Error: %v", err)
			continue
		}
		break
	}
	if verbose {
		for _, m := range conv {
			log.Print(m.Summary())
		}
	}
	if err != nil {
		return nil, err
	}
	// extract the network configuration
	netconf, err := netboot.ConversationToNetconfv4(conv)
	return netconf, err
}

func removeInterfaceAddr(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	rt, err := rtnl.Dial(nil)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := rt.Close(); err != nil {
			err = cerr
		}
	}()

	// remove current addresses
	addrs, err := rt.Addrs(iface, 0)
        if err != nil {
                return err
        }
	for _, addr := range addrs {
		err = rt.AddrDel(iface, addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func configureInterface(ifname string, netconf *netboot.NetConf) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	rt, err := rtnl.Dial(nil)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := rt.Close(); err != nil {
			err = cerr
		}
	}()

	// remove current addresses
	addrs, err := rt.Addrs(iface, 0)
        if err != nil {
                return err
        }
	for _, addr := range addrs {
		err = rt.AddrDel(iface, addr)
		if err != nil {
			return err
		}
	}

	// configure interfaces
	for _, addr := range netconf.Addresses {
		if err := rt.AddrAdd(iface, &addr.IPNet); err != nil {
			return fmt.Errorf("cannot configure %s on %s: %v", ifname, addr.IPNet, err)
		}
	}
	// configure /etc/resolv.conf
	resolvconf := ""
	for _, ns := range netconf.DNSServers {
		resolvconf += fmt.Sprintf("nameserver %s\n", ns)
	}
	if len(netconf.DNSSearchList) > 0 {
		resolvconf += fmt.Sprintf("search %s\n", strings.Join(netconf.DNSSearchList, " "))
	}
	if err = ioutil.WriteFile("/etc/resolv.conf", []byte(resolvconf), 0644); err != nil {
		return fmt.Errorf("could not write resolv.conf file %v", err)
	}

	// FIXME wut? No IPv6 here?
	// add default route information for v4 space. only one default route is allowed
	// so ignore the others if there are multiple ones
	if len(netconf.Routers) > 0 {
		// if there is a default v4 route, remove it, as we want to add the one we just got during
		// the dhcp transaction. if the route is not present, which is the final state we want,
		// an error is returned so ignore it
		dst := net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}
		// Remove a possible default route (dst 0.0.0.0) to the L2 domain (gw: 0.0.0.0), which is what
		// a client would want to add before initiating the DHCP transaction in order not to fail with
		// ENETUNREACH. If this default route has a specific metric assigned, it doesn't get removed.
		// The code doesn't remove any other default route (i.e. gw != 0.0.0.0).
		if err := rt.RouteDel(iface, net.IPNet{IP: net.IPv4zero}); err != nil {
			switch err := err.(type) {
			case *netlink.OpError:
				// ignore the error if it's -EEXIST or -ESRCH
				if !os.IsExist(err.Err) && err.Err != syscall.ESRCH {
					return fmt.Errorf("could not delete default route on interface %s: %v", ifname, err)
				}
			default:
				return fmt.Errorf("could not delete default route on interface %s: %v", ifname, err)
			}
		}

		src := netconf.Addresses[0].IPNet
		// TODO handle the remaining Routers if more than one

		// Default gateway
		if err := rt.RouteReplace(iface, dst, netconf.Routers[0], rtnl.WithRouteSrc(&src)); err != nil {
			return fmt.Errorf("could not add gateway %s for src %s dst %s to interface %s: %v", netconf.Routers[0], src, dst, ifname, err)
		}
	}

	return nil
}

func Start(netplan string) {

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Exit(1)
	}()

	fmt.Println("Purenet v1.0 starting ...")
	fmt.Println()

	var plan Plan
	err := yaml.Unmarshal([]byte(netplan), &plan)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// Run rtnetlink broadcast reader in a separate thread
	broadcast := make(chan *rtnetlink.LinkMessage, 10)
	bc, err := rtnetlink.Dial(&netlink.Config{Groups: unix.RTMGRP_LINK})
	if err != nil {
	        log.Fatal(err)
	}
	defer bc.Close()

	go func() {

		for {
			nls, _, err := bc.Receive()
			if err != nil {
				log.Fatal(err)
			}

			for i := range nls {
				 broadcast <- nls[i].(*rtnetlink.LinkMessage)
			}
		}
	}()

	ticker := time.NewTicker(time.Second)
	s := StateMachine{cstate: STATE_NO_IFACE, start: time.Now()}
	initManagedInterfaceList(&s.ifaces, plan)

	for {
		select {
		case <-broadcast:
			HandleEvent(&s)
		case <-ticker.C:
			HandleEvent(&s)
		}
	}
}
