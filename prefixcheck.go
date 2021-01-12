package main

import (
	"fmt"
	"strings"
	"io/ioutil"
	"sync"
	"flag"
	"github.com/projectdiscovery/mapcidr"
)

type Options struct {
	PrefixFile			string
	TargetFile			string
	Verbose				bool
}



func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.PrefixFile, 		"p", "", "File containing the list of cidr prefixes related to the target")
	flag.StringVar(&options.TargetFile, 		"t", "", "List of single ip addresses that will be checked against those cidr prefixes")
	flag.StringVar(&options.Verbose, 			"v", "", "Verbose mode for debug purposes")

	flag.Parse()
	return options
}

func expandCidr(prefix string) ([]string, error) {
	iplist, err := mapcidr.IPAddresses(prefix)
	return iplist, err
}

func checkCidrAddress(verbose bool, singleip string, prefix string, wg * sync.WaitGroup)  {
	defer wg.Done()
	
	iplist, err := expandCidr(prefix)
	if verbose == True {
		fmt.Printf("[*] Checking pair: %s and %s\n",singleip,prefix)
		fmt.Printf("[*] Prefix %s contains %d addresses\n",prefix,len(iplist))
	}
	if err == nil {
		for _, ipp := range iplist {
			if ipp == singleip {
				fmt.Println(singleip)
				break
			}
		}
	} else {
		if verbose == True {
			fmt.Printf("[*] Error expanding prefix %s:\n%s\n",prefix,err)	
		}
	}
}

func main() {
	options := parseOptions()
	var wg sync.WaitGroup
	if options.Verbose == True{
		fmt.Println("PrefixCheck is running")
	}

	prefixfilestream, _ := ioutil.ReadFile(options.PrefixFile)
	prefixcontent := string(prefixfilestream)
	listofprefixes := strings.Split(prefixcontent, "\n")
	if options.Verbose == True{
		fmt.Printf("[*] Prefixes loaded: %d \n",len(listofprefixes))
	}
	
	targetfilestream, _ := ioutil.ReadFile(options.TargetFile)
	targetfilecontent := string(targetfilestream)
	listoftargetips := strings.Split(targetfilecontent, "\n")
	if options.Verbose == True{
		fmt.Printf("[*] Target ip address loaded: %d \n",len(targetfilecontent))
	}
		
	for _, prefix := range listofprefixes {
		for _, ipaddr := range listoftargetips {
			if strings.Split(ipaddr, ".")[0] == strings.Split(prefix, ".")[0]{
				wg.Add(1)
				go checkCidrAddress(options.Verbose,ipaddr,prefix,&wg)
			}
		}
	}
	wg.Wait()
}



