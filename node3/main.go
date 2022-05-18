package main

import (
	"fmt"
	"hnust.javy.com/SpaceMint/client"
	"net"
)

func main() {
	fmt.Printf("我是node3\n")
	myAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30003,
	}
	c3 := client.NewClient(100000, 1, 30, 3, "node3Graph", myAddr)
	c3.AddNodeAddr(net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30001,
	})
	c3.AddNodeAddr(net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 30002,
	})
	//开始监听30003端口
	listen := c3.StartListen()
	defer listen.Close()
	go c3.ReceiveData(listen)
	c3.OperaClient(listen)
}

//开始接受数据
/*for{
	var recData [1024]byte
	var sendData []byte
	n,addr,err:=listen.ReadFromUDP(recData[:])
	if(err!=nil){
		fmt.Println("从udp读取失败,错误为",err)
		continue
	}
	fmt.Printf("recData:%v addr:%v count:%v\n",string(recData[:n]),addr,n)
	sendData=[]byte("已接受到"+addr.String()+"的消息")
	_,err = listen.WriteToUDP(sendData,addr)
	if(err!=nil){
		fmt.Println("发送消息失败，错误为",err)
		continue
	}

}*/
