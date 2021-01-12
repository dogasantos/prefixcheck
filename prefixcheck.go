package main

import (
	"fmt"
	"strings"
	"io/ioutil"
	"sync"
	"flag"
	"github.com/projectdiscovery/mapcidr"
)

const banner = `
____            __ _       ____ _               _    
|  _ \ _ __ ___ / _(_)_  __/ ___| |__   ___  ___| | __
| |_) | '__/ _ \ |_| \ \/ / |   | '_ \ / _ \/ __| |/ /
|  __/| | |  __/  _| |>  <| |___| | | |  __/ (__|   < 
|_|   |_|  \___|_| |_/_/\_\\____|_| |_|\___|\___|_|\_\
======================================================
`
const Version = `0.2`

type Options struct {
	PrefixFile			string
	TargetFile			string
}


func showBanner() {
	fmt.Printf("%s", banner)
	fmt.Printf("\t\t\t\t\t\t\t\tversion: %s\n\n",Version)
}


func parseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.PrefixFile, 		"p", "", "File containing the list of cidr prefixes related to the target")
	flag.StringVar(&options.TargetFile, 		"t", "", "List of single ip addresses that will be checked against those cidr prefixes")
	flag.Parse()

	showBanner()
	return options
}

func expandCidr(prefix string) ([]string, error) {
	iplist, err := mapcidr.IPAddresses(prefix)
	return iplist, err
}

func checkCidrAddress(singleip string, prefix string, wg * sync.WaitGroup)  {
	defer wg.Done()
	iplist, err := expandCidr(prefix)
	if err == nil {
		for _, ipp := range iplist {
			if ipp == singleip {
				fmt.Println(singleip)
				break
			}
		}
	}
}

func main() {
	options := parseOptions()
	var wg sync.WaitGroup


	prefixfilestream, _ := ioutil.ReadFile(options.PrefixFile)
	prefixcontent := string(prefixfilestream)
	listofprefixes := strings.Split(prefixcontent, "\n")
	
	targetfilestream, _ := ioutil.ReadFile(options.TargetFile)
	targetfilecontent := string(targetfilestream)
    listoftargetips := strings.Split(targetfilecontent, "\n")
		
	for _, prefix := range listofprefixes {
		for _, ipaddr := range listoftargetips {
			if strings.Split(ipaddr, ".")[0] == strings.Split(prefix, ".")[0]{
				wg.Add(1)
				go checkCidrAddress(ipaddr,prefix,&wg)
			}
		}
	}
	wg.Wait()
}



