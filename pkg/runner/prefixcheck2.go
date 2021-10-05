package prefixcheck

import (
	"flag"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/mapcidr"
)

/*
func sliceContainsElement(slice []string, element string) bool {
	retval := false
	for _, e := range slice {
		if e == element {
			retval = true
		}
	}
	return retval
}
*/

func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.PrefixFile, 		"p", "", "File containing the list of cidr prefixes related to the target")
	flag.StringVar(&options.TargetFile, 		"t", "", "List of single ip addresses that will be checked against those cidr prefixes")
	flag.StringVar(&options.IpAddress, 			"r", "", "Check if provided ip address is reserved/private or public (v4)")
	flag.BoolVar(&options.Verbose, 				"v", false, "Verbose mode for debug purposes")

	flag.Parse()
	return options
}

func expandCidr(prefix string) ([]string, error) {
	iplist, err := mapcidr.IPAddresses(prefix)
	return iplist, err
}

func checkCidrAddress(verbose bool, singleip string, iplist []string, wg * sync.WaitGroup)  {
	for _, ipp := range iplist {
		if ipp == singleip {
			fmt.Println(singleip)
			break
		}
	}
}

func checklist(listoftargetips []string,prefix string, wg sync.WaitGroup, options *Options) { 
	defer wg.Done()
	for _, ipaddr := range listoftargetips {
		if strings.Split(ipaddr, ".")[0] == strings.Split(prefix, ".")[0] {
			iplist, err := expandCidr(prefix)
			if err == nil {
				if options.Verbose == true{
					fmt.Printf("[*] Checking pair: %s and %s\n",ipaddr,prefix)
				}
				//checkCidrAddress(options.Verbose, ipaddr, iplist, &wg)
				for _, ipp := range iplist {
					if ipp == ipaddr {
						fmt.Println(ipaddr)
						break
					}
				}

			} 
		}
	}
}
