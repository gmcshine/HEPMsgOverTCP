package main

import (
    "flag"
    "fmt"
    "bytes"
    "net"
    "os"
    "os/signal"
    "time"
    "syscall"
    "encoding/hex"
    "encoding/binary"
    "sync/atomic"
     "crypto/tls"
    "crypto/x509"
    "io/ioutil"
)

var (
    CACertFilePath = "./cert/ca.crt"
    CertFilePath   = "./cert/server.crt"
    KeyFilePath    = "./cert/server.key"
)

var name = "Conan"
var enableTLS = false
var detailLog = false 
var decodeAndCount = false 
var protocol = "tcp"
var ipaddr = "127.0.0.1"
var port = "9889"

var unknownCount uint64 = 0
var hepTcpCount  uint64 = 0

var minCount uint64 = 0
var conns [] net.Conn

const version = "hepReceiver 0.1"
func createFlags() {
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Use %s like: %s [option]\n", version, os.Args[0])
        flag.PrintDefaults()
    }
    flag.BoolVar(&enableTLS, "tls", false, "Enable tls.")
    flag.BoolVar(&detailLog, "dl", false, "print detail logs.")
    flag.BoolVar(&decodeAndCount, "dc", false, "Decode and count the number of HEP message")
    flag.StringVar(&protocol, "tu", "tcp", "Protocol tcp or udp")
    flag.StringVar(&ipaddr, "la", "", "Listening IP address. If not configured, listening on all address")
    flag.StringVar(&port , "lp", "9889", "Listenting port number")
    flag.Parse()
}

func dumpConfig() {
    fmt.Println("================Dump Configuraion Value=====================")
    fmt.Print("+ enableTLS:", enableTLS)
    fmt.Print("\t protocol:", protocol)
    fmt.Print("\t ipaddr:", ipaddr)
    fmt.Println("\t port:", port)

    fmt.Print("+ detailLog:", detailLog)
    fmt.Println("\t decodeAndCount:", decodeAndCount) 
    fmt.Println("============================================================")
}

func main() {
    /*
    fmt.Println("Usage: ./tcp_server [port]"); 
    args := os.Args
    argNum := len(args)
    fmt.Println("Run command : ", args); 
    if (argNum > 1){ 
        port = os.Args[1]
    }
    */

    fmt.Println("### Usage: ./hepReceiver [-tls] [-dl] [-dc] [-tu tcp/udp] [-la ipaddr] [-lp port] ###"); 
    createFlags()
    var ln net.Listener
    var errLn error
    if (enableTLS) {
        fmt.Println("Using TLS"); 
        // load tls configuration
        cert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
        if err != nil {
            panic(err)
        }

        // Configure the server to trust TLS client certs issued by a CA.
        certPool, err := x509.SystemCertPool()
        if caCertPEM, err := ioutil.ReadFile(CACertFilePath); err != nil {
            panic(err)
        } else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
            panic("invalid cert in CA PEM")
        }

        tlsConfig := &tls.Config{
            ClientAuth:   tls.RequireAndVerifyClientCert,  // enforce mTLS client authentication.
            ClientCAs:    certPool,
            Certificates: []tls.Certificate{cert},
        }

        fmt.Println("Listening with TLS on: " + protocol + "://" + ipaddr + ":" + port)
        ln, errLn = tls.Listen(protocol, ipaddr + ":" + port, tlsConfig)
    } else {
        fmt.Println("Listening on: " + protocol + "://" + ipaddr + ":" + port)
        ln, errLn = net.Listen(protocol, ipaddr + ":" + port)
    }

    if errLn != nil {
        fmt.Println(errLn)
        return
    }

    go sumSomething()
    go monitorSomething()

    // Accept incoming connections and handle them
    signals := make(chan os.Signal, 2)
    signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

    for {
        conn, err := ln.Accept()
        if err != nil {
            fmt.Println(err)
            continue
        }

        conns = append(conns, conn)
        
        // Handle the connection in a new goroutine
        if decodeAndCount == true {
            go handleRequestExtended(conn)
        } else {
            go handleRequestSimple(conn)
        }
    }

    defer ln.Close()
}

func sumSomething() {
    ticker := time.NewTicker(1 * time.Minute)
    for {
        select {
        case <-ticker.C:
            minCount++ 
            fmt.Println("Program has run for ", minCount, " minutes. ")
            if decodeAndCount == true { 
                fmt.Printf("Total number of message received hepTCP: %d, unknown: %d\n", hepTcpCount, unknownCount)
            }
        }
    }
}

func monitorSomething() {
    signals := make(chan os.Signal, 2)
    signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
    for {
        select {
        case <-signals:
            fmt.Printf("\033[1;31m")
            fmt.Println("\n!!!Received STOP signal, sleep 500 ms and then quit!!!")
            fmt.Printf("\033[0m")
            time.Sleep(500 * time.Millisecond)
            os.Exit(0)
        }
    }
}

// Print the received data with hex format.
func handleRequestSimple(conn net.Conn) {
    // Read incoming data
    buf := make([]byte, 2048)

    for {
        _, err := conn.Read(buf)
        if err != nil {
            fmt.Println(err)
            break;
        }

        // Print the incoming data
        //fmt.Printf("Received: %s\n", buf)
        encodedString := hex.EncodeToString(buf)
        if detailLog == true {
            fmt.Println("Received message with first 32 Hex String: ", encodedString[:32])
        } else {
            fmt.Print(">")
        }
    }

    fmt.Println("Close Connection.")
    defer conn.Close()
}

// Decode and count the number of incoming HEP message over TCP.
func handleRequestExtended(conn net.Conn) {
    var bufferPool bytes.Buffer
    message := make([]byte, 2097152)
    for {
        // Read the incoming connection into the buffer.
        n, err := conn.Read(message)
        if err != nil {
            fmt.Println("got error on tcp connection:", err.Error())
            break
        }

        bufferPool.Write(message[:n])
        for {
            dataHeader := make([]byte, 6)
            n, err := bufferPool.Read(dataHeader)
            if err != nil {
                if err.Error() != "EOF" {
                    fmt.Println("error during read buffer: ", err)
                }
                break
            }

            if n < 6 {
                fmt.Println("error during read buffer len < 6")
                break
            }

            if bytes.HasPrefix(dataHeader, []byte{0x48, 0x45, 0x50, 0x33}) {
                length := binary.BigEndian.Uint16(dataHeader[4:6])
                for {
                    if int(length) <= (bufferPool.Len() + 6) {
                        dataHeader = append(dataHeader, bufferPool.Next(int(length)-6)...)
                        atomic.AddUint64(&hepTcpCount, 1)
                        if detailLog == true || (hepTcpCount % 1000) == 0 {
                            fmt.Printf("Worker %s Get HEP message with length %d, total number is %d \n", name, length, atomic.LoadUint64(&hepTcpCount))
                        }
                        break
                    } else {
                        // Read the left part of the HEP message.
                        n, err := conn.Read(message)
                        if err != nil {
                            fmt.Print("Worker %s got error %s during reading message from connection:", name, err.Error())
                            bufferPool.Reset()
                            break
                        }
                        bufferPool.Write(message[:n])
                    }
                }
            } else {
                atomic.AddUint64(&unknownCount, 1)
                fmt.Println("Worker %s Get a new Unknown message, total number is ", name, atomic.LoadUint64(&unknownCount))
            }
        }
    }

    // Close the connection when you're done with it.
    fmt.Println("Close Connection.")
    defer conn.Close()
}

