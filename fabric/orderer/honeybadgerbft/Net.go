package honeybadgerbft

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	ab "github.com/hyperledger/fabric/protos/orderer"
	"github.com/hyperledger/fabric/protos/utils"
)

var connectedOrderers = make(map[string]*net.TCPConn)
var registedChains = make(map[string]MessageChannels)
var listener *net.TCPListener
var sendChannels = make(map[string]chan ab.HoneyBadgerBFTMessage)

type MessageChannels struct {
	Send    chan ab.HoneyBadgerBFTMessage
	Receive chan *ab.HoneyBadgerBFTMessage
}

func Register(chainID string, connectAddresses []string, selfIndex int) (MessageChannels, error) {
	if result, exist := registedChains[chainID]; exist {
		return result, nil
	}
	channels := MessageChannels{
		Send:    make(chan ab.HoneyBadgerBFTMessage),
		Receive: make(chan *ab.HoneyBadgerBFTMessage),
	}
	registedChains[chainID] = channels
	//listen
	if err := listen(connectAddresses[selfIndex]); err != nil {
		return MessageChannels{}, err
	}
	//listen service
	var accepted = make(chan interface{})
	go acceptConnectionService(accepted)
	//dispathc
	for _, addr := range connectAddresses {
		sendChannels[addr] = make(chan ab.HoneyBadgerBFTMessage)
	}
	go dispatchByReceiverService(channels.Send, connectAddresses)
	//dial
	dial(connectAddresses)
	//send service
	for _, addr := range connectAddresses {
		go sendMessageService(chainID, selfIndex, addr)
	}
	//
	for range connectAddresses {
		<-accepted
	}

	return channels, nil
}

func dial(addresses []string) {
	finished := make(chan bool)
	dialOneFunc := func(address string) {
		address = strings.TrimSpace(address)
		if _, exist := connectedOrderers[address]; exist {
			return
		}
		tcpaddr, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			logger.Panic("Can not resolve address: ", address)
		}
		var tried int
		var tcpconn *net.TCPConn
		for { //TODO: better retry
			tcpconn, err = net.DialTCP("tcp", nil, tcpaddr)
			if err == nil {
				break
			}
			tried++
			logger.Debugf("Can not connect %s: %s", address, err)
			time.Sleep(3 * time.Second) //TODO: hardcoded
		}
		logger.Debugf("Connected to %s", address)
		connectedOrderers[address] = tcpconn
		finished <- true
		return
	}
	for _, addr := range addresses {
		go dialOneFunc(addr)
	}
	for range addresses {
		<-finished
	}
}

func dispatchByReceiverService(sendChan chan ab.HoneyBadgerBFTMessage, connectAddresses []string) {
	for {
		msg := <-sendChan
		receiver := int(msg.GetReceiver())
		sendChannels[connectAddresses[receiver]] <- msg // TODO: deal nil channel
	}
}

func sendMessageService(chainID string, selfIndex int, address string) {
	channel := sendChannels[address]
	for {
		msg := <-channel
		conn := connectedOrderers[address]
		msg.Sender = uint64(selfIndex)
		msg.ChainId = chainID

		switch (&msg).Type.(type) {
		case *ab.HoneyBadgerBFTMessage_ReliableBroadcast:
			switch (&msg).GetReliableBroadcast().Type.(type) {
			case *ab.HoneyBadgerBFTMessageReliableBroadcast_Val:
			default:
			}
		default:
		}

		data := utils.MarshalOrPanic(&msg)
		buf := bytes.NewBuffer(convertInt32ToBytes(int32(len(data))))
		buf.Write(data)
		_, err := conn.Write(buf.Bytes())
		if err != nil {
			logger.Panicf("Send message to %s failed: %s", address, err)
		}
	}
}

func convertInt32ToBytes(value int32) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, value)
	return bytesBuffer.Bytes()
}

func listen(address string) error {
	address = strings.TrimSpace(address)
	if listener != nil && listener.Addr().String() != address {
		return fmt.Errorf("Already listen %s, can not listen %s", listener.Addr().String(), address)
	}
	tcpaddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return err
	}
	tcplisten, err := net.ListenTCP("tcp", tcpaddr)
	if err != nil {
		return err
	}
	listener = tcplisten
	logger.Infof("HoneyBadgerBFT Service listen at %s", address)
	return nil
}

func acceptConnectionService(accepted chan interface{}) {
	logger.Debugf("Start accept connection at %s", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("Error occured when accepting an connection: %s", err)
			continue
		}
		logger.Debugf("Accepted a connection from %s", conn.RemoteAddr())
		go readConnectionService(conn)
		accepted <- nil
	}
}

func readConnectionService(connection net.Conn) {
	defer connection.Close()
	for {
		var buf = make([]byte, 4)
		length, err := connection.Read(buf)
		if err != nil {
			logger.Panicf("Error occured when reading message length from %s: %s", connection.RemoteAddr(), err)
		}
		if length != 4 {
			logger.Panicf("Can not read full message length bytes %s", connection.RemoteAddr())
		}
		msgLength, err := convertBytesToInt32(buf)
		if err != nil {
			logger.Panicf("Error occured when converting message length from bytes %s: %s", connection.RemoteAddr(), err)
		}
		buf = make([]byte, msgLength)
		length, err = connection.Read(buf)
		if err != nil {
			logger.Panicf("Error occured when reading from %s: %s", connection.RemoteAddr(), err)
		}
		if length != int(msgLength) {
			logger.Panicf("Can not read full message %s", connection.RemoteAddr())
		}
		processReceivedData(buf)
	}
}

func convertBytesToInt32(data []byte) (result int32, err error) {
	err = binary.Read(bytes.NewBuffer(data), binary.BigEndian, &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func processReceivedData(data []byte) error {
	var msg = new(ab.HoneyBadgerBFTMessage)
	if err := proto.Unmarshal(data, msg); err != nil {
		return err
	}
	chainID := msg.GetChainId()
	channels, exist := registedChains[chainID]
	if !exist {
		return fmt.Errorf("ChainID (%s) in received message not registered", chainID)
	}

	switch msg.Type.(type) {
	case *ab.HoneyBadgerBFTMessage_ReliableBroadcast:
		switch msg.GetReliableBroadcast().Type.(type) {
		case *ab.HoneyBadgerBFTMessageReliableBroadcast_Val:
		default:
		}
	default:
	}

	channels.Receive <- msg
	return nil
}
