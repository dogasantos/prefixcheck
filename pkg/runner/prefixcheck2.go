package prefixcheck

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/xgfone/netaddr"
)

func CheckIp(ipaddr string) string {
	var result string
	ipv4 := netaddr.MustNewIPAddress(ipaddr)
		if ipv4.IsIPv4() {
			if ipv4.IsLoopback() {
				result = fmt.Sprintf("%s:loopback",ipaddr)
			} else {
				if ipv4.IsReserved() {
					result = fmt.Sprintf("%s:reserved",ipaddr)
				} else {

					if ipv4.IsPrivate() {
						result = fmt.Sprintf("%s:private",ipaddr)
					} else {
						result = fmt.Sprintf("%s:public",ipaddr)
					}
				}
			}
			
		} else {
			result = fmt.Sprintf("%s:invalid",ipaddr)
		}
	
	return result
}
func CheckForIp(listoftargetips []string,prefix string, wg * sync.WaitGroup, verbose bool) {
	for _, ipaddr := range listoftargetips {
		if strings.Split(ipaddr, ".")[0] == strings.Split(prefix, ".")[0] {
			_, cidrAddr, _ := net.ParseCIDR(prefix)
			if verbose == true{
				fmt.Printf("[*] Checking pair: %s and %s\n",ipaddr,prefix)
			}

			// testa se o ip eh valido/invalido/publico/
			if len(ipaddr) > 4 {
				result:=CheckIp(ipaddr)
				if strings.Contains("public",strings.Split(result, ":")[1]) {
					iptest := net.ParseIP(ipaddr)
					if cidrAddr.Contains(iptest) == true {
						fmt.Println(ipaddr)
					}
				}
			}
		}
	}
	wg.Done()
}

func CheckForCidr(listoftargetips []string,prefix string, wg * sync.WaitGroup, verbose bool) {
	for _, ipaddr := range listoftargetips {
		if strings.Split(ipaddr, ".")[0] == strings.Split(prefix, ".")[0] {
			//_, cidrAddr, _ = net.ParseCIDR(prefix)
			if verbose == true {
				fmt.Printf("[*] Checking pair: %s and %s\n",ipaddr,prefix)
				
			}
			else {
				fmt.Printf("%s,%s\n",ipaddr,prefix)
			}
		}
	}
	wg.Done()
}

func CheckForBoth(listoftargetips []string,prefix string, wg * sync.WaitGroup, verbose bool) {
	for _, ipaddr := range listoftargetips {
		if strings.Split(ipaddr, ".")[0] == strings.Split(prefix, ".")[0] {
			//_, cidrAddr, _ = net.ParseCIDR(prefix)
			if verbose == true {
				fmt.Printf("[*] Checking pair: %s and %s\n",ipaddr,prefix)
			}
			fmt.Printf("%s,%s\n",ipaddr,prefix)
		}
	}
	wg.Done()
}