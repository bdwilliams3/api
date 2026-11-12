package main

import (
	"sync"
	"time"
)

type sessionState struct {
	createdAt   time.Time
	aesTokenHex string
	edMsg       []byte
	kdfSalt     []byte

	lweA      [][]int64
	lweB      []int64
	lweQ      int64
	lweS      []int64
	lweN      int
	lweM      int
	flagNonce []byte
	flagCT    []byte
}

type oauthCodeState struct {
	challenge string
	clientID  string
	expires   time.Time
}

type appState struct {
	mu         sync.Mutex
	sessions   map[string]*sessionState
	oauthCodes map[string]oauthCodeState
}

var st = appState{
	sessions:   map[string]*sessionState{},
	oauthCodes: map[string]oauthCodeState{},
}

func getSession(id string) *sessionState {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.sessions[id]
	if !ok {
		return nil
	}
	if time.Since(s.createdAt) > time.Hour {
		delete(st.sessions, id)
		return nil
	}
	return s
}
