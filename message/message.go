package message

import "hnust.javy.com/SpaceMint/block"

type Message struct {
	Flag              int
	Explain           string
	SendPos           block.PoS
	ChainBuffer       []byte
	ChainBufferLength int
	Blockchain        *block.BlockChain
}

func NewMessage(flag int, explain string, pos block.PoS, buffer []byte, bufferLength int, blockChain *block.BlockChain) *Message {
	return &Message{Flag: flag, Explain: explain, SendPos: pos, ChainBuffer: buffer, ChainBufferLength: bufferLength, Blockchain: blockChain}
}
