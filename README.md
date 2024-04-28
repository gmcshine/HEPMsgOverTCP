# HEPMsgOverTCP
HEP(v3) message sender and receiver over TCP with optional mTLS support 

Build:
go build hepSender.go
go build hepReceiver.go

Usage
./hepReceiver [-tls] [-dl] [-dc] [-tu tcp/udp] [-la ipaddr] [-lp port]

  **Param,  Defaul value,    Description**
  -tls,  false,           "Enable tls."
  -dl,   false,           "Print detail log."
  -dc,   false,           "Decode and count the number of HEP message."
  -tu,   "tcp",           "Protocol tcp or udp"
  -la,   "127.0.0.1",     "Listening IP address"
  -lp,   "9889",          "Listening port number"


./hepSender [-tls] [-dl] [-mn msgNumSend] [-rn restTimerMicroSec] [-tn threadNum] [-tu protocol] [-da dstIP] [-dp dstPort]

  **Param,  Defaul value,    Description**
  -tls,  false,           "Enable tls."
  -dl,   false,           "Print detail log."
  -tu,   "tcp",           "Protocol tcp or udp"
  -da,   "127.0.0.1",     "Destination IP address"
  -dp,   "9889",          "Destination port number"
  -mn,   5,               "Number of messages to send"
  -rn,   1000000,         "Rest time (Microseconds) between 2 messages."


