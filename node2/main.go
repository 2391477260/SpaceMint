package main

import (
	"fmt"
	"hnust.javy.com/SpaceMint/client"
	"net"
)

func main() {
	fmt.Printf("我是node2\n")
	myAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30002,
	}
	c2 := client.NewClient(100000, 1, 30, 4, "node2Graph", myAddr)
	c2.AddNodeAddr(net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30001,
	})
	c2.AddNodeAddr(net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30003,
	})
	//开始监听30002端口
	listen := c2.StartListen()
	defer listen.Close()
	go c2.ReceiveData(listen)
	c2.OperaClient(listen)
}
