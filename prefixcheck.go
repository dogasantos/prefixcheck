package main

import (
	"fmt"
	"os"
	"bufio"
	"strings"
	"io/ioutil"
	"sync"
	"github.com/projectdiscovery/mapcidr"
)

func check(singleip string, prefix string, wg * sync.WaitGroup)  {
	defer wg.Done()
	iplist, _ := mapcidr.IPAddresses(prefix)
	for _, ipp := range iplist {
		if ipp == singleip {
			fmt.Println(singleip)
			break
		}
	}
}

func main() {

	if len(os.Args[1:]) == 0 {
		fmt.Printf("%s <prefix file> <list of ips>\n", os.Args[0] )
		fmt.Println("<prefix file> - a list of cidr taken from ASN that you want to use as base search")
		fmt.Println("<list of ips> - a list of ips taken from massdns or any other discovery method that you want to check if it belongs to those ASN prefixes")
		return 
	}
	var wg sync.WaitGroup

	pf, _ := os.Open(os.Args[1])
	defer pf.Close()
	prefixo := bufio.NewScanner(pf)

	bytesRead, _ := ioutil.ReadFile(os.Args[2])
	file_content := string(bytesRead)
    lines := strings.Split(file_content, "\n")
		
	for prefixo.Scan() {
		for _, singleip := range lines {
			if strings.Split(singleip, ".")[0] == strings.Split(prefixo.Text(), ".")[0]{
				wg.Add(1)
				go check(singleip,prefixo.Text(),&wg)
			}
		}
	}
	wg.Wait()
}



