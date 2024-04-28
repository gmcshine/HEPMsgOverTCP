package main

import (
    "fmt"
    "net"
    "time"
    "os"
    "strconv"
    "encoding/hex"
    "sync"
    "flag"
    /*
    "os/signal"
    "syscall"
    */
    "crypto/x509"
    "io/ioutil"
    "crypto/tls"
)

var enableTLS = false
var detailLog = false
var protocol = "tcp"
var ipaddr = "127.0.0.1"
var port = "9889"
var msgNumSend = 5 
var restTimerMicroSec = 1000000 //default 1 second 
var threadNum = 1
var hexString = "4845503302a7000000010007020000000200070600000007000810e100000008000804d200000009000a6602695d0000000a000a000df86d0000000b0007100000000c000a0000000000000003000a0102030400000004000a040302010009002800060000000f015601000150c000012d01000000000000010000000100000107400000276161612e696d736465762e6e736e2e636f6d3b313334353730313530303b3000000001154000000c00000000000001084000001b637363662e696d736465762e6e736e2e636f6d000000012840000016696d736465762e6e736e2e636f6d00000000011b40000016696d736465762e6e736e2e636f6d000000000104400000200000010a4000000c000028af000001024000000c010000000000027480000038000028af0000010a4000000c000028af0000027580000010000028af000000010000027680000010000028af0000000500000259c0000024000028af7369703a77696c646361726431323367406e736e2e636f6d0000025ac000001e000028af7369703a6373636630312e696d732e636f6d000000000266c0000010000028af0000000300000270c0000010000028af000000010009003a001c6869702e6873732e696d736465762e6e736e2e636f6d0009002c000d696e67726573730009022e000a010000000009022d001c6869702e6873732e696d736465762e6e736e2e636f6d0009003f009f7b22636e665f6e616d65223a2271646c616232222c22636e665f74797065223a2248737343616c6c50222c22696e7465726e616c5f7265666964223a2271646c6162322d68737363616c6c702d383663643634353538352d6a6b356866222c22782d6d73672d636f7272656c6174696f6e2d6964223a223137396638306565346261663038396136613839313464383662303138353964227d"
var hexString2 = "48455033029a000000010007020000000200070600000007000810e100000008000804d200000009000a6603c7bc0000000a000a00004e260000000b0007100000000c000a0000000000000003000a0102030400000004000a040302010009002800060000000f015601000150c000012d01000000000000010000000100000107400000276161612e696d736465762e6e736e2e636f6d3b313334353730313530303b3000000001154000000c00000000000001084000001b637363662e696d736465762e6e736e2e636f6d000000012840000016696d736465762e6e736e2e636f6d00000000011b40000016696d736465762e6e736e2e636f6d000000000104400000200000010a4000000c000028af000001024000000c010000000000027480000038000028af0000010a4000000c000028af0000027580000010000028af000000010000027680000010000028af0000000500000259c0000024000028af7369703a77696c646361726431323367406e736e2e636f6d0000025ac000001e000028af7369703a6373636630312e696d732e636f6d000000000266c0000010000028af0000000300000270c0000010000028af000000010009003a001d6d696e652e6873732e696d736465762e6e736e2e636f6d0009002c000d696e67726573730009022e000a010000000009022d001c6974732e6873732e696d736465762e6e736e2e636f6d0009003f00917b22636e665f6e616d65223a22222c22636e665f74797065223a22222c22696e7465726e616c5f7265666964223a2271646c6162322d68737363616c6c702d383663643634353538352d6a6b356866222c22782d6d73672d636f7272656c6174696f6e2d6964223a223137396638306565346261663038396136613839313464383662303138353964227d"


const version = "hepSender 0.1"
func createFlags() {
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Use %s like: %s [option]\n", version, os.Args[0])
        flag.PrintDefaults()
    }
    flag.BoolVar(&enableTLS, "tls", false, "Enable tls.")
    flag.BoolVar(&detailLog, "dl", false, "Print detail log.")
    flag.StringVar(&protocol, "tu", "tcp", "Protocol tcp or udp")
    flag.StringVar(&ipaddr, "da", "127.0.0.1", "Destination IP address")
    flag.StringVar(&port , "dp", "9889", "Destination port number")
    flag.IntVar(&msgNumSend, "mn", 5, "Number of messages to send")
    flag.IntVar(&restTimerMicroSec, "rn", 1000000, "Rest time (Microseconds) between 2 messages.") 
    flag.IntVar(&threadNum, "tn", 1, "Number of thread")
    flag.Parse()
}

func dumpConfig() {
    fmt.Println("====================Dump Configuraion Value=====================")
    fmt.Print("+ enableTLS:", enableTLS)
    fmt.Println("\t detailLog:", detailLog)
    fmt.Print("+ protocol:", protocol)
    fmt.Print("\t ipaddr:", ipaddr)
    fmt.Println("\t port:", port)

    fmt.Print("+ msgNumSend:", msgNumSend)
    fmt.Println("\t restTimerMicroSec:", restTimerMicroSec) 
    fmt.Println("+ threadNum:", threadNum)
    fmt.Println("================================================================")

}

var (
    CACertFilePath = "./cert/ca.crt"
    CertFilePath   = "./cert/client.crt"
    KeyFilePath    = "./cert/client.key"
)

func main() {
/*
    fmt.Println(">>>> Usage: ./hepSender [msgNumSend] [restTimerMicroSec] [threadNum] [protocol] [dstIP] [dstPort]]<<<<"); 
    args := os.Args
    argNum := len(args)
    fmt.Println("Run command : ", args); 
    if (argNum > 1){
        msgNumSend,_ = strconv.Atoi(os.Args[1])
    }
    if (argNum > 2){
        restTimerMicroSec,_ = strconv.Atoi(os.Args[2])
    }
    if (argNum > 3){
        threadNum,_ = strconv.Atoi(os.Args[3])
    }
    if (argNum > 4){
        protocol = os.Args[4]
    }
    if (argNum > 5){
        ipaddr = os.Args[5]
    }
    if (argNum > 6){
        port = os.Args[6]
    }
    if (argNum > 7){
        fmt.Println("Too many args, return !!!!!!")
        return
    }
*/

    fmt.Println(">>>> Usage: ./hepSender [-tls] [-dl] [-mn msgNumSend] [-rn restTimerMicroSec] [-tn threadNum] [-tu protocol] [-da dstIP] [-dp dstPort]<<<<"); 
    createFlags()
    dumpConfig()
    var dstAddr = ipaddr + ":" + port
    fmt.Println("Try to connect server ", dstAddr) 
    
    var conn net.Conn
    var connErr error
    if (enableTLS) {
        fmt.Println("TLS enabled")
        // load tls configuration
        cert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
        if err != nil {
            panic(err)
        }
        // Configure the client to trust TLS server certs issued by a CA.
        certPool, err := x509.SystemCertPool()
        //certPool := x509.NewCertPool()
        if err != nil {
            panic(err)
        }
        if caCertPEM, err := ioutil.ReadFile(CACertFilePath); err != nil {
            panic(err)
        } else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
            panic("invalid cert in CA PEM")
        }
        tlsConfig := &tls.Config{
            RootCAs:      certPool,
            Certificates: []tls.Certificate{cert},
        }
        conn, connErr = tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, protocol, dstAddr, tlsConfig)
        //TLS DONE
    } else {
        fmt.Println("NOT TLS") 
        conn, connErr = net.Dial(protocol, dstAddr)
    }

    if connErr != nil {
        fmt.Println(connErr)
        return
    }
    fmt.Println("Successfully Connected to server ", dstAddr) 

    var currentTime = time.Now()
    fmt.Println(currentTime)
    fmt.Println("......Start to send message now......")
    var wg sync.WaitGroup
    wg.Add(threadNum)

    //By default, only use one thread to send
    for i:=0;i<threadNum;i++{
        go sendHepMsg(conn, strconv.Itoa(i), wg.Done)
    }

    go monitorSomething(conn)
/*
    signals := make(chan os.Signal, 2)
    signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
    for {
        select {
        case <-signals:
            fmt.Println("Received STOP signal, sleep 500 ms.")
            time.Sleep(500 * time.Millisecond)
            fmt.Println("Close connection and Exit 0.")
            conn.Close()
            os.Exit(0)
        }   
    }   
*/
    wg.Wait()
    currentTime = time.Now()
    fmt.Println(currentTime)
    fmt.Println("......All messages are send. Close Connection. Adieu :-)")
    conn.Close()
}

func sendHepMsg(conn net.Conn, name string, done func()){
    defer done()
    //var currentTime = time.Now()
    //fmt.Println(currentTime)
    //fmt.Println("Sender goroutine" + name + " starts to send messages...")
    decodedByteArray, err := hex.DecodeString(hexString)
    decodedByteArray2, err := hex.DecodeString(hexString2)
    // Send some data to the server
    i := 1
    for i = 1; i <= msgNumSend; i++ {

        if i % 2 == 0 {
            _, err = conn.Write(decodedByteArray2)
        } else {
            _, err = conn.Write(decodedByteArray)
        }

        if err != nil {
            fmt.Println(err)
            return
        }
        //println("Sender " + name + "write to server. ", i)
        if restTimerMicroSec != 0 {
            time.Sleep(time.Duration(restTimerMicroSec) * time.Microsecond) 
        }

        if detailLog == true || (i % 10000) == 0 {
            fmt.Println(i, " messages have been send by Sender goroutine " + name)
        }
    }
    //var currentTime = time.Now()
    //fmt.Println(currentTime)
    fmt.Println("Sender goroutine " + name + " Done. Send message number is ", i - 1)
    //conn.Close()
}

func monitorSomething(conn net.Conn) {
    ticker := time.NewTicker(1 * time.Minute)
    for {
        select {
        case <-ticker.C:
            fmt.Println("How Time Flies! One Minute Passed!")
        }   
    }   
}
