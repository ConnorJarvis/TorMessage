package main

type conversationTools struct {
	Conversation
	ConversationInfo
}

func NewConversation(info ConversationInfo) Conversation {
	return &conversationTools{ConversationInfo: info}
}
