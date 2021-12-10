//Attempts to identify differences between hosts of different environments
package main

import (
	"encoding/json";
	"flag";
	"fmt";
	"io/ioutil";
	"os";
	"os/exec";
	"sort";
	"strings"
)

const splash = `$$$$$$$$\                     $$\                                         
$$  _____|                    \__|                                        
$$ |      $$$$$$$\ $$\    $$\ $$\  $$$$$$\   $$$$$$\  $$$$$$$\  $$\   $$\ 
$$$$$\    $$  __$$\\$$\  $$  |$$ |$$  __$$\ $$  __$$\ $$  __$$\ $$ |  $$ |
$$  __|   $$ |  $$ |\$$\$$  / $$ |$$ |  \__|$$ /  $$ |$$ |  $$ |$$ |  $$ |
$$ |      $$ |  $$ | \$$$  /  $$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ |
$$$$$$$$\ $$ |  $$ |  \$  /   $$ |$$ |      \$$$$$$  |$$ |  $$ |\$$$$$$$ |
\________|\__|  \__|   \_/    \__|\__|       \______/ \__|  \__| \____$$ |
                                                                $$\   $$ |
                                                                \$$$$$$  |
                                                                 \______/ `

type TestSslOut struct {
	ScanResult []TestSslData `json:"scanResult"`
}

type TestSslData struct {
	TargetHost string `json:"targetHost"`
	Ip string `json:"ip"`
	Pretest []SslDetails `json:"pretest"`
	Protocols []SslDetails `json:"protocols"`
	Ciphers []SslDetails `json:"ciphers"`
	Pfs []SslDetails `json:"pfs"`
	ServerPreferences []SslDetails `json:"serverPreferences"`
	ServerDefaults []SslDetails `json:"serverDefaults"`
	HeaderResponse []SslDetails `json:"headerResponse"`
	Vulnerabilities []SslDetails `json:"vulnerabilities"`
	CipherTests []SslDetails `json:"cipherTests"`
	BrowserSimulations []SslDetails `json:"browserSimulations"`
}

type SslDetails struct{
	Id string `json:"id"`
	Severity string `json:"severity"`
	Finding string `json:"finding"`
}

type PrintDetails struct{
	Host string
	Findings SslDetails
}

func dedupFndSlice(fndSlice []PrintDetails) []PrintDetails{
	keys := make(map[PrintDetails]bool)
	list := []PrintDetails{}
	for _, entry := range fndSlice{
		if _, value := keys[entry]; !value{
			keys[entry] = true
			list = append(list,entry)
		}
	}
	return list
}

func printDiff(results2Print []PrintDetails){
	currentId := results2Print[0].Findings.Id
	fmt.Printf("\t==Finding id: %s==\n",currentId)
	for finding := 0; finding < len(results2Print); finding++{
		if results2Print[finding].Findings.Id != currentId{
			currentId = results2Print[finding].Findings.Id
			fmt.Printf("\t==Finding id: %s==\n",currentId)
		}
		fmt.Printf("\t\tHost: %s\n\t\tSeverity: %s\n\t\tFinding: %s\n\n",results2Print[finding].Host,results2Print[finding].Findings.Severity,results2Print[finding].Findings.Finding)
	}
}

func smallestHost(hostA []SslDetails, hostB []SslDetails) []SslDetails{
	var smallerHost []SslDetails
	if len(hostA) < len(hostB){
		smallerHost = hostA
	} else if len(hostA) == len(hostB){
		smallerHost = hostA
	}else{
		smallerHost = hostB
	}
	return smallerHost
}

func largestHost(hostA []SslDetails, hostB []SslDetails) ([]SslDetails,bool){
	var largerHost []SslDetails
	var hostALarger bool
	if len(hostA) > len(hostB){
		largerHost = hostA
		hostALarger = true
	} else{
		largerHost = hostB
		hostALarger = false
	}
	return largerHost, hostALarger
}

func alignAndCompareResults(hostAIssues []SslDetails, hostBIssues []SslDetails, hostnameA string, hostnameB string) []PrintDetails{
	var diffResults []PrintDetails
	//header response can have different lengths, check to see if there is an issue misalignment before starting comparisons
	for findingDetail:=0; findingDetail < len(smallestHost(hostAIssues,hostBIssues)); findingDetail++{
		//DON'T CHANGE THIS, EVERYTHING WILL BREAK AND BE SAD
		//need to set finding values to variables before comparison, otherwise FP's will happen for unknown reason
		findingA := hostAIssues[findingDetail]
		findingB := hostBIssues[findingDetail]
		largerHost,hostALarger := largestHost(hostAIssues,hostBIssues)
		smallerHost := smallestHost(hostAIssues,hostBIssues)

		//if the finding id's don't match some kind of misalignment has occurred
		match := false
		if findingA.Id != findingB.Id{
			//attempt to find id value later in other host's HeaderResponse slice
			for x:=findingDetail; x<len(largerHost);x++{
				findingX := largerHost[x].Id
				findingY := smallerHost[findingDetail].Id
				if findingX == findingY{
					match = true
					smallerHost = append(smallerHost,SslDetails{})
					copy(smallerHost[findingDetail+1:],smallerHost[findingDetail:])
					smallerHost[findingDetail] = SslDetails{largerHost[findingDetail].Id,"N/A","N/A"}
					break
				}
			}
		} else{
			match = true
		}
		//if the Id value wasn't in the other host's HeaderResponse slice, need to insert into slice
		if match == false{
			largerHost = append(largerHost,SslDetails{})
			copy(largerHost[findingDetail+1:],largerHost[findingDetail:])
			largerHost[findingDetail] = SslDetails{smallerHost[findingDetail].Id,"N/A","N/A"}
		}
		//need to overwrite old hostA and hostB values after appends happened
		if hostALarger{
			hostAIssues = largerHost
			hostBIssues = smallerHost
		} else {
			hostAIssues = smallerHost
			hostBIssues = largerHost
		}
		if findingA.Id != "DROWN_hint"{
			if findingA.Finding != findingB.Finding{
				diffResults = append(diffResults,PrintDetails{hostnameA, hostAIssues[findingDetail]}, PrintDetails{hostnameB,hostBIssues[findingDetail]})
			}
		}
	}
	return diffResults
}

func compareResults(results2Compare TestSslOut, testType string) bool{
	var printDetails,compReturn []PrintDetails
	for hostA:=0; hostA < len(results2Compare.ScanResult); hostA++{
		for hostB:=hostA+1; hostB < len(results2Compare.ScanResult); hostB++{
			hostnameA := results2Compare.ScanResult[hostA].TargetHost
			hostnameB := results2Compare.ScanResult[hostB].TargetHost
			switch testType{
			case "protocols":
				compReturn = alignAndCompareResults(results2Compare.ScanResult[hostA].Protocols,results2Compare.ScanResult[hostB].Protocols,hostnameA,hostnameB)
			case "ciphers":
				compReturn = alignAndCompareResults(results2Compare.ScanResult[hostA].Ciphers,results2Compare.ScanResult[hostB].Ciphers,hostnameA,hostnameB)
			case "pfs":
				compReturn = alignAndCompareResults(results2Compare.ScanResult[hostA].Pfs,results2Compare.ScanResult[hostB].Pfs,hostnameA,hostnameB)
			case "headerResponse":
				compReturn = alignAndCompareResults(results2Compare.ScanResult[hostA].HeaderResponse,results2Compare.ScanResult[hostB].HeaderResponse,hostnameA,hostnameB)
			case "vulnerabilities":
				compReturn = alignAndCompareResults(results2Compare.ScanResult[hostA].Vulnerabilities,results2Compare.ScanResult[hostB].Vulnerabilities,hostnameA,hostnameB)
			}
			//append returns from comparison to printDetails (otherwise it'll only print the last 2 hosts checked)
			for j:=0; j<len(compReturn);j++{
				printDetails = append(printDetails,compReturn[j])
			}
		}
	}
	//dedup the printDetails
	printDetails = dedupFndSlice(printDetails)
	//sort the printDetails by finding id
	sort.Slice(printDetails, func(i,j int) bool {return printDetails[i].Findings.Id < printDetails[j].Findings.Id})
	//if differences were found
	if len(printDetails) > 0{
		fmt.Println("[X] Difference in",testType,"discovered between environments")
		printDiff(printDetails)
		return true
	} else {
		fmt.Println("[$] Supported",testType,"are the same between environments")
		return false
	}
} //end func compareResults

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err){
		return false
	}
	return !info.IsDir()
}

func main(){
	//print splash
	fmt.Println(splash)

	//parse targets cli argument
	var targetsFile,jsonFile string
	flag.StringVar(&targetsFile, "targets", "", "Targets file")
	flag.StringVar(&jsonFile,"output","testsslOut.json","TestSsl output file name (defaults to testsslOut.json if not set)")
	noScan := flag.Bool("x",false,"Won't execute testssl scan, and will just read the provided output file for details")
	verbose := flag.Bool("v",false,"Enables verbosity during execution")
	flag.Parse()

	if targetsFile == "" {
		fmt.Println("[X] No targets file provided, exiting.")
	} else {
		//read targets file
		targetsFileContents, err := ioutil.ReadFile(targetsFile)
		if err != nil{
			fmt.Println("[X] File reading error", err)
			return
		} else {
			if *verbose{fmt.Println("[#] Contents of targets file:", string(targetsFileContents))}
			hostList := strings.Split(string(targetsFileContents),"\n")
			if *verbose{fmt.Println("[#] Contents of hostList array: ",hostList)}

			if *noScan != true && fileExists(jsonFile){
				fmt.Println("[X] Json output file already exists, skipping testssl scan")
				*noScan = true
			}

			//launch testssl scan to get data
			if *noScan != true{
				fmt.Println("[$] Executing testssl (this may take some time)...")
				out, err := exec.Command("testssl","--file",targetsFile,"-oJ",jsonFile).Output()
				if err != nil {
					fmt.Printf("[X] %s\n",err)
				}
				fmt.Println("[$] Command successfully executed")
				output := string(out[:])
				if *verbose{fmt.Println(output)}
			}

			//read JSON file
			jsonFileContents, err := ioutil.ReadFile(jsonFile)
			if err != nil{
				fmt.Println("[X] File reading error", err)
				return
			}
			//if *verbose{fmt.Println("[#] Contents of testssl json file:", string(jsonFileContents))}

			//check if json is formatted correctly
			var parsedJson TestSslOut
			if json.Valid(jsonFileContents){
				fmt.Println("[$] JSON output formatted correctly")
				//parse json into scanResult
				json.Unmarshal(jsonFileContents, &parsedJson)

			} else {
				fmt.Println("[X] JSON output formmatted incorrectly")
				return
			}

			//enumerate any significant differences in results between hosts
			compareResults(parsedJson,"protocols")
			compareResults(parsedJson,"ciphers")
			compareResults(parsedJson,"pfs")
			compareResults(parsedJson,"headerResponse")
			compareResults(parsedJson,"vulnerabilities")
		}//end of if/else file reading error for targetsFile
	}//end of if/else targetsFile == ""
}//end of main()
