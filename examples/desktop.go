package main

import (
	"fmt"

	astilectron "github.com/asticode/go-astilectron"
)

type desktopTools struct {
	Chat
	DesktopState DesktopInformation
}

func NewDesktop(desktopInformation DesktopInformation) Desktop {
	return &desktopTools{DesktopState: desktopInformation}
}

func (e *desktopTools) StartApp() error {
	// Initialize astilectron
	var a, err = astilectron.New(astilectron.Options{
		AppName:           "TorMessage",
		BaseDirectoryPath: "/Users/connorjarvis/Documents/TorMessage",
	})
	if err != nil {
		fmt.Println(err)
	}
	defer a.Close()

	// Start astilectron
	a.Start()

	// Blocking pattern
	a.Wait()
}
