package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	prefixcheck "github.com/dogasantos/prefixcheck/pkg/runner"
)

type Options struct {
	PrefixFile			string
	TargetFile			string
	IpAddress			string
	Version				bool
	Verbose				bool
	Mode				string

}

func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.PrefixFile, 		"p", "", "File containing the list of cidr prefixes")
	flag.StringVar(&options.TargetFile, 		"t", "", "List of single ip addresses that will be checked against those cidr prefixes")
	flag.StringVar(&options.IpAddress, 			"r", "", "Check if provided ip address is reserved/private or public (v4)")
	flag.BoolVar(&options.Version, 				"i", false, "Version info")
	flag.BoolVar(&options.Verbose, 				"v", false, "Verbose mode for debug purposes")
    flag.StringVar(&options.Mode, 				"m", "ip", "Mode (ip|cidr)")

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

		if options.Mode == "ip" { 
			
			for _, prefix := range listofprefixes {
				wg.Add(1)
				go prefixcheck.CheckForIp(listoftargetips, prefix, &wg, options.Verbose)
			}
			wg.Wait()
			return
		
		}
		if options.Mode == "cidr" { 
			for _, prefix := range listofprefixes {
				wg.Add(1)
				go prefixcheck.CheckForCidr(listoftargetips, prefix, &wg, options.Verbose)
			}
			wg.Wait()
			return
		}

		fmt.Println("Valid mode??")
	}

	if options.IpAddress != "" {
		fmt.Println(prefixcheck.CheckIp(options.IpAddress))
	}
}




