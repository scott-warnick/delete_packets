package main

import (
	"database/sql"
	"dbtools"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	//"github.com/elliotchance/sshtunnel"

	_ "github.com/lib/pq"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func usage() {
	fmt.Println("delete_packets - Delete a list of CM packets")
	fmt.Println("usage:")
	fmt.Println("./delete_packets <db_flag> <DHD ticket number> <admin username> <database port>")
	fmt.Println("for example:")
	fmt.Println("./delete_packets PROD DHD-10205 scott.warnick 5499")
	fmt.Println("----------------------------------------------------------------------------------")
	fmt.Println("The database port must match the one specified in your SSH tunnel on the appropriate bastion host")
	fmt.Println("The database indicator must be one of INT, PP or PROD")
}

// Here is the main function. It calls routines to
// connect to the database,
// read the input packetlist file
// create a query based on the packet list and then execute the query.
func main() {
	//	//Get the arguments
	fmt.Println()
	args := os.Args[1:]
	if len(args) < 4 {
		usage()
		os.Exit(1)
	}

	port := 0

	//Validate the input parameters
	var ticket string
	var portString string
	var adminuser string
	var db_flag string

	fmt.Println("Capturing argument 1 - Database flag")
	db_flag = args[0]
	fmt.Printf("database flag = %s\n", db_flag)

	fmt.Println("Capturing argument 2 - DHD ticket number")
	ticket = args[1]
	fmt.Printf("ticket number=%s\n", ticket)

	fmt.Println("Capturing argument 3 - admin user")
	adminuser = args[2]
	fmt.Printf("adminuser =%s\n", adminuser)

	fmt.Println("Capturing argument 4 - database port")
	portString = strings.Trim(args[3], " \n")
	port = dbtools.ConvertPort(portString)

	if port == 0 {
		fmt.Println()
		fmt.Printf("Enter the port you are using to connect to the production database (e.g. 5498): ")
		fmt.Scanln(&portString)
		port = dbtools.ConvertPort(portString)
		fmt.Printf("port=%d\n", port)
	}

	if db_flag == "PROD" || db_flag == "PP" || db_flag == "UAT" || db_flag == "INT" {
		//Create an SSH tunnel to the postgres database specified by the dbflag indicator
		tunnel := dbtools.SetupSSHTunnel(db_flag, strconv.Itoa(port))
		if tunnel == nil {
			fmt.Printf("Failed to create SSH tunnel to the %s database server\n", db_flag)
			os.Exit(1)
		}
		// Start the tunnel server in the background. You will need to wait a
		// small amount of time for it to bind to the localhost port
		// before you can start sending connections.
		go tunnel.Start()
		time.Sleep(500 * time.Millisecond)
	} else {
		fmt.Printf("For databases that are not in the set PROD, PP, UAT and INT you must use an putty connection with an SSH tunnel or the database connection will fail\n")
		fmt.Printf("That will change when we add golang tunnels built to those databases\n")
	}
	fmt.Printf("Connecting to database using port %d\n", port)
	psqlInfo := dbtools.BuildConnectString(db_flag, port)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		fmt.Println("Could not connect to postgreSQL database. Port may be incorrect or SSH tunnel may not be open")
		fmt.Println(err)
		os.Exit(1)
	}

	defer db.Close()
	err = db.Ping()
	checkErr(err)

	fmt.Println("Connected to database successfully")

	var packetString string
	//var quotedString string

	modeChoice := dbtools.GetMode("Enter 't' to get the packet list from the terminal or 'r' to read it from the file packetlist.txt: ")
	fmt.Printf("mode choice = %s\n", modeChoice)
	if modeChoice == "r" {
		//Read the packetlist.txt file and convert it into a string of vendorpacketid's separated by commas
		//packetString, quotedString = dbtools.BuildPacketLists()
		packetString, _ = dbtools.BuildPacketLists()
		//fmt.Println(packetString)
		//fmt.Println("unquoted packet list:", packetString)
		//fmt.Println("quoted packet list:", quotedString)
	}
	if modeChoice == "t" {
		//Get the packet list from the terminal and convert it into a string of vendorpacketid's separated by strings
		//packetString, quotedString = dbtools.InputPacketLists()
		packetString, _ = dbtools.InputPacketLists()
		//fmt.Println("unquoted packet list:", packetString)
		//fmt.Println("quoted packet list:", quotedString)
	}

	//Get the number of packets in the packet string we just created
	packetList := strings.Split(packetString, ",")
	packetCount := len(packetList)
	fmt.Printf("packet count = %d\n", packetCount)

	//Find the packet ID and vendor ID for all of the packets in the list.
	//If the count of packet ID, vendor ID combinations is the same as the number of packets,
	//then all of the packet ID's are unique, meaning they belong to only one vendor.
	//If all the packets don't have the same vendor, complain and exit
	fmt.Println("Verifying that all of the packets in the list have a unique vendor ID")
	vendorQuery := dbtools.BuildVendorQuery(packetString)
	//fmt.Println(vendorQuery)
	vendorlist := dbtools.GetVendorList(db, vendorQuery)
	if len(vendorlist) <= 0 {
		fmt.Println("Vendor List is empty")
		fmt.Println("This probably means that one or packets were not found in the database.")
		os.Exit(1)
	}
	//fmt.Println(vendorlist)
	vendorCount := len(vendorlist)
	if vendorCount != packetCount {
		fmt.Printf("The number of packets %d retrieved by the vendor list query is not equal to the number of packets %d in the packet list \n", vendorCount, packetCount)
		fmt.Println("Case 1: If the number of packets found by the vendor list query is greater than the number of packets in the original list you have split packets in the list.")
		fmt.Println("In this case you must run the check_splits program. That program will find the after-split packets and delete them.")
		fmt.Println("Once the after-split packets are deleted you can run delete_packets again.")
		fmt.Println("Case 2: If the number of packets found by the vendor list query is less than the number of packets in the original list some packets in the orignal list have multiple vendors.")
		fmt.Println("In this case you must split the original packetlist into separate lists, one for each vendor. Once that is done you can run delete_packets on each list.\n")
		os.Exit(1)
	}

	//Show the deletedutc for each packet in the packet list
	fmt.Println()
	fmt.Println("Deletion status of packets in the list prepared using the vendorpacketid")
	dbtools.ShowPacketlistStatusVendorPID(db, packetString)

	//Show the deletedutc for each packet in the packet list
	fmt.Println()
	//fmt.Println("Deletion status of packets in the list prepared using the displaypacketid")
	//dbtools.ShowPacketlistStatusDisplayPID(db, quotedString)

	deleteQuery := dbtools.BuildDeleteQuery(ticket, adminuser, packetString)
	//fmt.Println("Query to be used to delete the packets in the list")
	//fmt.Println(deleteQuery)
	fmt.Println()

	confirmed := dbtools.Confirm("Should I use the standard database function these packets", 1)
	if confirmed {
		fmt.Println("Deletion confirmed - deleting packets")
		rows := dbtools.DeletePackets(db, deleteQuery)
		fmt.Printf("Rows affected = %d\n", rows)
		fmt.Println()
		fmt.Println("Deletion status of packets in the list prepared using the vendorpacketid")
		dbtools.ShowPacketlistStatusVendorPID(db, packetString)
		os.Exit(0)
	} else {
		fmt.Println("User aborted deletion")
		fmt.Println()
		//fmt.Println("Deletion status of packets in the list prepared using the vendorpacketid")
		//dbtools.ShowPacketlistStatusVendorPID(db, packetString)
		os.Exit(0)
	}

}
