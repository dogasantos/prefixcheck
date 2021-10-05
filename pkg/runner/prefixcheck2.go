package prefixcheck

import (
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/mapcidr"
)

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

func Checklist(listoftargetips []string,prefix string, wg * sync.WaitGroup, verbose bool) { 
	 
	for _, ipaddr := range listoftargetips {
		if strings.Split(ipaddr, ".")[0] == strings.Split(prefix, ".")[0] {
			iplist, err := expandCidr(prefix)
			if err == nil {
				if verbose == true{
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
	wg.Done()
}
