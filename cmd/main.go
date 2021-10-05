package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"github.com/dogasantos/prefixcheck"
)


func main() {
	options := parseOptions()
	var wg sync.WaitGroup

	if options.PrefixFile != "" {

		prefixfilestream, _ := ioutil.ReadFile(options.PrefixFile)
		prefixcontent := string(prefixfilestream)
		listofprefixes := strings.Split(prefixcontent, "\n")

		if options.Verbose == true {
			fmt.Printf("[*] Prefixes loaded: %d \n",len(listofprefixes))
		}
		
		targetfilestream, _ := ioutil.ReadFile(options.TargetFile)
		targetfilecontent := string(targetfilestream)
		listoftargetips := strings.Split(targetfilecontent, "\n")

		if options.Verbose == true{
			fmt.Printf("[*] Target ip address loaded: %d \n",len(targetfilecontent))
		}
		
		for _, prefix := range listofprefixes {
			wg.Add(1)
			go prefixcheck.checklist(listoftargetips,prefix,wg, options)

		}
		wg.Wait()
	} 

	if options.IpAddress != "" {
		ipv4 := netaddr.MustNewIPAddress(options.IpAddress)
		if ipv4.IsIPv4() {
			if ipv4.IsLoopback() {
				fmt.Printf("%s:loopback\n",options.IpAddress)
			} else {
				if ipv4.IsReserved() {
					fmt.Printf("%s:reserved\n",options.IpAddress)
				} else {

					if ipv4.IsPrivate() {
						fmt.Printf("%s:private\n",options.IpAddress)
					} else {
						fmt.Printf("%s:public\n",options.IpAddress)
					}
				}
			}
			
		} else {
			fmt.Printf("%s:invalid\n",options.IpAddress)
		}


	}
}




