package main

import (
	"fmt"
	"log"

	"github.com/jsimonetti/rtnetlink"
        "github.com/mdlayher/netlink"
        "golang.org/x/sys/unix"
//	"github.com/davecgh/go-spew/spew"
)


func main() {
	fmt.Println("purenet v1.0 starting ...")
	fmt.Println()

	// Dial a connection to the rtnetlink socket
	// and subscribe to the link state multicast
	// group.
	conn, err := rtnetlink.Dial(&netlink.Config{
                Groups: unix.RTMGRP_LINK,
        })
	if err != nil {
	        log.Fatal(err)
	}
	defer conn.Close()

	// Request a list of interfaces
	msgs, err := conn.Link.List()
	if err != nil {
	        log.Fatal(err)
	}

	for _, msg := range msgs {
		fmt.Printf("Iterface: %s, Carrier: %d\n", msg.Attributes.Name, *msg.Attributes.Carrier)
	}

	fmt.Println("Link Events ...")
	fmt.Println()

	for {
		nls, _, err := conn.Receive()
		if err != nil {
			log.Fatal(err)
		}

		msgs := make([]rtnetlink.LinkMessage, len(nls))
		for i := range nls {
			msgs[i] = *nls[i].(*rtnetlink.LinkMessage)
		}

		for _, msg := range msgs {
			fmt.Printf("Iterface: %s, Carrier: %d\n", msg.Attributes.Name, *msg.Attributes.Carrier)
		}
	}
}
