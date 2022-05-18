package client

import (
	"crypto"
	sign "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/sha3"
	"hnust.javy.com/SpaceMint/block"
	"hnust.javy.com/SpaceMint/message"
	"hnust.javy.com/SpaceMint/pos"
	"hnust.javy.com/SpaceMint/util"
	"math"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

type Client struct {
	//client and system params
	sk   crypto.Signer    // signing secretkey
	pk   crypto.PublicKey // signing pubkey
	t    time.Duration    // how soon we add a block
	dist int              // how far to look back for challenge

	//sols []block.PoS // others' blocks

	//pos params
	index    int64
	prover   *pos.Prover
	verifier *pos.Verifier
	commit   pos.Commitment

	Blockchain  *block.BlockChain
	myAddr      *net.UDPAddr
	ClientsAddr []net.UDPAddr
	MessageNums int
}

var lock sync.Mutex //互斥锁

//新建客户端
func NewClient(t time.Duration, dist, beta int, index int64, graph string, addr *net.UDPAddr) *Client {
	sk, err := sign.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pk := sk.Public()
	pkBytes, err := json.Marshal(pk)
	if err != nil {
		panic(err)
	}

	prover := pos.NewProver(pkBytes, index, "Xi", graph)
	commit := prover.Init()
	verifier := pos.NewVerifier(pkBytes, index, beta, commit.Commit)
	c := Client{
		sk:   sk,
		pk:   pk,
		t:    t,
		dist: dist,

		index:      index, //客户端编号
		prover:     prover,
		verifier:   verifier,
		commit:     *commit,
		Blockchain: block.NewBlockChain("小简同学专属链条"),
		myAddr:     addr, //当前IP以及地址
	}
	return &c
}

// ReceiveData 接受数据处理方法
func (c *Client) ReceiveData(listen *net.UDPConn) {
	for {
		fmt.Println("正在监听端口：", listen.LocalAddr())
		var recData [1000 * 1024]byte
		n, addr, err := listen.ReadFromUDP(recData[:])
		if err != nil {
			fmt.Println("从udp读取失败,错误为", err)
			continue
		}
		fmt.Printf(" addr:%v count:%v\n", addr, n)
		var recMessage message.Message
		err = json.Unmarshal(recData[:n], &recMessage)
		if err != nil {
			fmt.Println("错误为：", err)
			return
		}
		fmt.Println("发送方操作：", recMessage.Explain)
		switch recMessage.Flag {
		case 1: //别的节点发来更新区块链信息，发送区块链信息给别的节点
			{
				bufferLength, buffer := c.ReadFromChain()
				sendMessage := message.NewMessage(2, "区块链信息", *new(block.PoS), buffer, bufferLength, c.Blockchain)
				c.SendToNode(sendMessage, listen, addr)
				break
			}
		case 2: //接受别的节点发送来的区块链信息，更新自己的区块链
			{
				bufferLength, _ := c.ReadFromChain()
				fmt.Println("进来了")
				if recMessage.ChainBufferLength >= bufferLength { //更新本地区块链
					FileInfo, err := c.Blockchain.Chain.Stat()
					filename := FileInfo.Name()
					err = c.Blockchain.Chain.Truncate(0)
					if err != nil {
						return
					}
					f, err := os.Create(filename)
					if err != nil {
						panic(err)
					}
					_, err = f.Write(recMessage.ChainBuffer)
					if err != nil {
						return
					}
					c.Blockchain.Chain = f
					c.Blockchain.LastBlock = recMessage.Blockchain.LastBlock
					c.Blockchain.SetSeekIndex(recMessage.Blockchain.SeekIndex())
					fmt.Println("更新成功")
					break
				} else {
					fmt.Println("无需更新")
					break
				}
			}
		case 3: //别的点添加的区块，验证成功后上链
			{
				/*				flag := c.ReturnMinQuality()
								c.MessageNums++
								if recMessage.SendPos.Quality == c.sols[flag].Quality && c.MessageNums == 1 {
									c.AddNewBlock(&c.sols[flag])
								}
								break*/

				addBlock := recMessage.SendPos
				nodes := c.verifier.SelectChallenges(addBlock.Challenge)
				if c.verifier.VerifySpace(nodes, addBlock.Answer.Hashes, addBlock.Answer.Parents, addBlock.Answer.Proofs, addBlock.Answer.PProofs) {
					c.AddNewBlock(addBlock, addBlock.Answer)
				} else {
					fmt.Println("区块不符合规定")
				}
				break
			}
		case 4:
			/*			{
						if len(c.sols) == 10 {
							flag := c.ReturnMinQuality()
							if c.sols[flag].Quality > recMessage.SendPos.Quality {
								lock.Lock()
								c.sols[flag] = recMessage.SendPos
								lock.Unlock()
								sendMessage := message.NewMessage(3, "准备添加的区块", c.sols[flag], nil, 0, nil)
								c.SendToEveryNode(sendMessage, listen)
							}
						} else if len(c.sols) < 10 {
							lock.Lock()
							c.sols = append(c.sols, recMessage.SendPos)
							fmt.Println(recMessage.SendPos.Quality)
							lock.Unlock()
						}
						break
					}*/
		}
	}
}

//客户端命令行操作
func (c *Client) OperaClient(listen *net.UDPConn) {
	for {
		var OperaName string = ""
		fmt.Println("请输入进行的操作：")
		//当程序执行到 fmt.Println("请输入进行的操作") ，会阻塞到这里，等待用户输入
		fmt.Scanln(&OperaName)
		switch OperaName {
		case "更新区块链":
			buffer := new([]byte)
			sendMessage := message.NewMessage(1, "更新区块链", *new(block.PoS), *buffer, 0, nil)
			c.SendToEveryNode(sendMessage, listen)
			break
		case "进行挖矿":
			for {
				challenge := c.GenerateChallenge()
				seed := make([]byte, 64)
				rand.Read(seed)
				challenge = append(challenge, seed...)
				prf := c.Mine(challenge)
				if prf.Quality <= 0.0001 {
					fmt.Println("该区块质量为：", prf.Quality)
					c.AddNewBlock(*prf, prf.Answer)
					sendMessage := message.NewMessage(3, "添加的区块", *prf, nil, 0, nil)
					c.SendToEveryNode(sendMessage, listen)
				}
			}

		case "修改区块链":
			fmt.Println("修改区块链")
			break
		}

	}
}

//找到客户端最小质量函数的节点编号
/*func (c *Client) ReturnMinQuality() int {
	flag := 0
	max := c.sols[0].Quality
	for i, x := range c.sols {
		if x.Quality < max {
			max = c.sols[i].Quality
			flag = i
		}
	}
	return flag
}*/

//向其他节点发送消息包
func (c *Client) SendToEveryNode(sendMessage *message.Message, listen *net.UDPConn) {
	sendData, _ := json.Marshal(sendMessage)
	for i, x := range c.ClientsAddr {
		fmt.Println("消息发送目标地址", x)
		_, err := listen.WriteToUDP(sendData, &c.ClientsAddr[i])
		if err != nil {
			fmt.Println("发送消息失败，错误为", err)
		}
	}
}

//向单个节点发送消息包
func (c *Client) SendToNode(sendMessage *message.Message, listen *net.UDPConn, addr *net.UDPAddr) {
	sendData, err := json.Marshal(sendMessage) //类转为json
	fmt.Println("发送信息为：", sendData)
	fmt.Println("发送目标地址为：", addr)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = listen.WriteToUDP(sendData, addr)
	if err != nil {
		fmt.Println("发送消息失败，错误为", err)
	}
}

//取出本地区块链的数据存入数据包
func (c *Client) ReadFromChain() (int, []byte) {
	file := c.Blockchain.Chain
	fileInfo, err := file.Stat() //获取文件属性
	if err != nil {
		fmt.Println(err)
		return 0, nil
	}

	fileSize := fileInfo.Size()      //文件大小
	buffer := make([]byte, fileSize) //设置一个byte的数组(buffer)

	n, err := file.Read(buffer) //读文件(拿取)
	if err != nil {
		fmt.Println(err)
		return 0, nil
	}
	fmt.Println("读取区块链的字节数为", n)
	return n, buffer
}

//开始监听自己绑定的端口
func (c *Client) StartListen() *net.UDPConn {
	//开始监听30001端口
	listen, err := net.ListenUDP("udp", c.myAddr)
	if err != nil {
		fmt.Println("listen failed,err:", err)
	}
	return listen
}

//获取本地保存的区块链
func (c *Client) GetMyBlockChain() *block.BlockChain {
	return c.Blockchain
}

//给客户端添加通信节点的地址
func (c *Client) AddNodeAddr(add net.UDPAddr) {
	c.ClientsAddr = append(c.ClientsAddr, add)
}

//给消息签名
func (c *Client) Sign(msg []byte) ([]byte, error) {
	return c.sk.Sign(rand.Reader, msg, crypto.SHA3_256)
}

//挖矿，生成共识
func (c *Client) Mine(challenge []byte) *block.PoS {
	nodes := c.verifier.SelectChallenges(challenge)
	hashes, parents, proofs, pProofs := c.prover.ProveSpace(nodes)
	a := block.Answer{
		Size:    c.index,
		Hashes:  hashes,
		Parents: parents,
		Proofs:  proofs,
		PProofs: pProofs,
	}
	p := block.PoS{
		Commit:    c.commit,
		Challenge: challenge,
		Answer:    a,
		Quality:   c.Quality(challenge, a),
	}
	return &p
}

// Compute quality of the answer. Also builds a verifier
// return: quality in float64
func (c *Client) Quality(challenge []byte, a block.Answer) float64 {
	nodes := c.verifier.SelectChallenges(challenge)
	if !c.verifier.VerifySpace(nodes, a.Hashes, a.Parents, a.Proofs, a.PProofs) {
		return -1
	}

	all := util.Concat(a.Hashes)
	answerHash := sha3.Sum256(all)
	x := new(big.Float).SetInt(new(big.Int).SetBytes(answerHash[:]))
	num, _ := util.Root(x, a.Size).Float64()
	den := math.Exp2(float64(1<<8) / float64(a.Size))
	return num / den
}

//从上一个区块生成一个字节数组，字节取值为0-256
func (c *Client) GenerateChallenge() []byte {
	var b *block.Block
	var err error
	if c.Blockchain.LastBlock < c.dist {
		b, err = c.Blockchain.Read(c.Blockchain.LastBlock)
	} else {
		b, err = c.Blockchain.Read(c.Blockchain.LastBlock - (c.dist - 1))
	}
	if err != nil {
		panic(err)
	}
	bin, err := b.MarshalBinary()
	if err != nil {
		panic(err)
	}
	challenge := sha3.Sum256(bin)
	return challenge[:]
}
func (c *Client) AddNewBlock(prf block.PoS, a block.Answer) {
	nodes := c.verifier.SelectChallenges(prf.Challenge)
	if c.verifier.VerifySpace(nodes, a.Hashes, a.Parents, a.Proofs, a.PProofs) {
		old, err := c.Blockchain.Read(c.Blockchain.LastBlock)
		if err != nil {
			panic(err)
		}
		// TODO: where do transactions come from??
		b := block.NewBlock(old, prf, nil, c.sk)
		c.Blockchain.Add(b)
		fmt.Printf("添加区块成功,该区块hash为%v个\n", b.Hash.Hash)
		fmt.Printf("区块签名为%v个\n", b.Sig.Tsig)
		fmt.Printf("区块id为%v,区块信息为%v\n", b.Id, b.Trans)
	} else {
		fmt.Println("该区块认证失败")
	}

}

// 运行一次协议的流程
/*func (c *Client) Round() {
	challenge := c.GenerateChallenge()
	prf := c.Mine(challenge)

	send := true

	select {
	/*case b := <-c.sols:
	// probably can't trust the others in final version..
	if b.Hash.Proof.Quality > prf.Quality {
		send = false
		break
	}
	default:
		break
	}

	if send {
		old, err := c.Blockchain.Read(c.Blockchain.LastBlock)
		if err != nil {
			panic(err)
		}
		// TODO: where do transactions come from??
		b := block.NewBlock(old, *prf, nil, c.sk)
		/*for _, r := range c.clients {
			err := r.Call("Client.SendBlock", b, nil)
			if err != nil {
				panic(err)
			}
		}
		fmt.Printf("最后的区块为第%v个\n", c.Blockchain.LastBlock)
		c.Blockchain.Add(b)
		fmt.Printf("添加区块成功,最后的区块为第%v个\n", c.Blockchain.LastBlock)
		fmt.Printf("该区块id为%v,该区块信息为%v\n", b.Id, b.Trans)
	}
}*/

/*func main() {
	/*fmt.Println("helloworld")
	idx := flag.Int("index", 1, "graph index")
	name := flag.String("name", "Xi", "graph name")
	dir := flag.String("file", "/media/storage/Xi", "graph location")
	mode := flag.String("mode", "gen", "mode:[gen|commit]")
	flag.Parse()

	pk := []byte{1}
	beta := 30
	now := time.Now()
	prover := pos.NewProver(pk, int64(*idx), *name, *dir)
	if *mode == "gen" {
		fmt.Printf("%d. Graph gen: %fs\n", *idx, time.Since(now).Seconds())
	} else if *mode == "commit" {
		now = time.Now()
		prover.Init()
		fmt.Printf("%d. Graph commit: %fs\n", *idx, time.Since(now).Seconds())
	} else if *mode == "check" {
		commit := prover.PreInit()
		root := commit.Commit
		verifier := pos.NewVerifier(pk, int64(*idx), beta, root)

		seed := make([]byte, 64)
		rand.Read(seed)
		cs := verifier.SelectChallenges(seed)

		now = time.Now()
		hashes, parents, proofs, pProofs := prover.ProveSpace(cs)
		fmt.Printf("Prove: %f\n", time.Since(now).Seconds())

		now = time.Now()
		if !verifier.VerifySpace(cs, hashes, parents, proofs, pProofs) {
			log.Fatal("Verify space failed:", cs)
		}else{
			fmt.Printf("Verify: %f\n", time.Since(now).Seconds())
		}
	}
	c := NewClient(100000, 1, 30, 4, "hello")
	c.round()
	c.round()
}*/
