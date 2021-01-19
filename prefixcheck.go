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

func sliceContainsElement(slice []string, element string) bool {
	retval := false
	for _, e := range slice {
		if e == element {
			retval = true
		}
	}
	return retval
}



func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.PrefixFile, 		"p", "", "File containing the list of cidr prefixes related to the target")
	flag.StringVar(&options.TargetFile, 		"t", "", "List of single ip addresses that will be checked against those cidr prefixes")
	flag.BoolVar(&options.Verbose, 				"v", false, "Verbose mode for debug purposes")

	flag.Parse()
	return options
}

func expandCidr(prefix string) ([]string, error) {
	iplist, err := mapcidr.IPAddresses(prefix)
	return iplist, err
}

func checkCidrAddress(verbose bool, singleip string, iplist []string, wg * sync.WaitGroup)  {
	defer wg.Done()
	for _, ipp := range iplist {
		if ipp == singleip {
			fmt.Println(singleip)
			break
		}
	}
}

func main() {
	options := parseOptions()
	var wg sync.WaitGroup
	var processed []string 

	if options.Verbose == true{
		fmt.Println("PrefixCheck is running")
	}

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
		for _, ipaddr := range listoftargetips {
			
			if strings.Split(ipaddr, ".")[0] == strings.Split(prefix, ".")[0] {
				iplist, err := expandCidr(prefix)
				if err == nil {
					if options.Verbose == true{
						fmt.Printf("[*] Checking pair: %s and %s\n",ipaddr,prefix)
					}
					if sliceContainsElement(processed, ipaddr) == false {
						processed = append(processed, ipaddr)
						wg.Add(1)
						go checkCidrAddress(options.Verbose, ipaddr, iplist, &wg)
					
					}
				} 
			}
		}
	}
	

	wg.Wait()
}



