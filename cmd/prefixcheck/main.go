package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	prefixcheck "github.com/dogasantos/prefixcheck/pkg/runner"
	"github.com/xgfone/netaddr"
)

type Options struct {
	PrefixFile			string
	TargetFile			string
	IpAddress			string
	Version				bool
	Verbose				bool
}

func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.PrefixFile, 		"p", "", "File containing the list of cidr prefixes related to the target")
	flag.StringVar(&options.TargetFile, 		"t", "", "List of single ip addresses that will be checked against those cidr prefixes")
	flag.StringVar(&options.IpAddress, 			"r", "", "Check if provided ip address is reserved/private or public (v4)")
	flag.BoolVar(&options.Version, 				"i", false, "Version info")
	flag.BoolVar(&options.Verbose, 				"v", false, "Verbose mode for debug purposes")

	flag.Parse()
	return options
}

func main() {
	var wg sync.WaitGroup
	options := parseOptions()
	if options.Version {
		fmt.Println("v0.2")
	}
	
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
			fmt.Printf("[*] Target ip address loaded: %d \n",len(listoftargetips))
		}
		
		for _, prefix := range listofprefixes {
			wg.Add(1)
			go prefixcheck.Checklist(listoftargetips, prefix, wg, options.Verbose)
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




