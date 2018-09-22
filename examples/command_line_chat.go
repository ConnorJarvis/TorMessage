package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ConnorJarvis/TorMessage"
)

func main() {
	host := flag.Bool("host", false, "Set if you are the host of the chat")
	hostname := flag.String("hostname", "127.0.0.1:9000", "ip:port to listen on")
	name := flag.String("name", "User", "Display Name")
	extradata := flag.String("extradata", "", "If you are not the host enter the string given to you here")

	flag.Parse()

	chatInfo := tormessage.ChatInformation{
		Hostname: *hostname,
		Host:     *host,
		Name:     *name,
	}
	var chat tormessage.Chat
	if *host == true {
		chat = tormessage.NewChat(chatInfo)
		data, err := chat.InitializeConversation(nil)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(*data)
	} else {
		chat = tormessage.NewChat(chatInfo)
		data, err := chat.InitializeConversation(extradata)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(data)
	}
	go chat.StartServer()
	go chat.State().Conversation.StartSendService()
	go chat.State().Conversation.ReceiveMessageProcessor(chat.State().Conversation.State().ReceiveQueue)
	if *host == false {
		err := chat.InitiateConnection()
		if err != nil {
			fmt.Println(err)
		}
		time.Sleep(time.Second * 5)
		go chat.StartKeyNegotiatingService()
	}
	go printChat(chat.State().Conversation.State().DisplayQueue)
	listenToInput(chat)
}

func listenToInput(chat tormessage.Chat) {
	for {
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		chat.SendTextMessage(text)
	}
}

func printChat(messages chan tormessage.TextMessage) {
	for {
		message := <-messages
		fmt.Print("\n" + message.Name + ": " + message.Body)
	}
}

func printStats(hostChat tormessage.Chat) {
	for {
		fmt.Print("\n\nHost Chat:\n")
		fmt.Print("Send Keys: ")
		fmt.Print(len(hostChat.State().Conversation.State().SendingMessageKeys))
		fmt.Print("\nReceive Keys: ")
		fmt.Print(len(hostChat.State().Conversation.State().ReceivingMessageKeys))
		fmt.Print("\n\n")
		time.Sleep(time.Second * 5)
	}
}
