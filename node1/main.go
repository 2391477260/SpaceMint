package main

import (
	"fmt"
	"hnust.javy.com/SpaceMint/client"
	"net"
)

func main() {
	fmt.Printf("我是node1\n")
	myAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30001,
	}
	c1 := client.NewClient(100000, 1, 30, 4, "node1Graph", myAddr)
	c1.AddNodeAddr(net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30002,
	})
	c1.AddNodeAddr(net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30003,
	})
	//开始监听30001端口
	listen := c1.StartListen()
	defer listen.Close()
	go c1.ReceiveData(listen)
	c1.OperaClient(listen)
}
