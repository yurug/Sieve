package web

import (
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

const (
	googleProfileGeneral = "general"
	googleProfileGmail   = "gmail"
	// The gmail profile asks for the narrowest scopes VPA's mail features need
	// (Google restricted-scope verification): search and read, then drafts and
	// sends. gmail.modify (labels, archive, trash) is not requested.
	gmailReadonlyScope = "https://www.googleapis.com/auth/gmail.readonly"
	gmailComposeScope  = "https://www.googleapis.com/auth/gmail.compose"
)

// gmailProfileScopes is a function so no caller can mutate a shared slice.
func gmailProfileScopes() []string { return []string{gmailReadonlyScope, gmailComposeScope} }

// An omitted profile is the historical, six-service Sieve connection. It is
// deliberately not changed when an existing connection is re-authorized.
func googleOAuthProfile(raw string) (string, error) {
	switch raw {
	case "", googleProfileGeneral:
		return googleProfileGeneral, nil
	case googleProfileGmail:
		return googleProfileGmail, nil
	default:
		return "", fmt.Errorf("unknown Google OAuth profile")
	}
}

func googleOAuthScopesFor(profile string) []string {
	if profile == googleProfileGmail {
		return gmailProfileScopes()
	}
	return append([]string(nil), googleOAuthScopes...)
}

// RFC 6749 §5.1 permits omitting scope when it equals the requested scope.
// A supplied scope is authoritative; neither callback query parameters nor
// historical grants may stand in for the token endpoint's response.
func googleGrantedScopes(token *oauth2.Token, requested, required []string) ([]string, string, error) {
	granted, source := append([]string(nil), requested...), "request"
	if raw := token.Extra("scope"); raw != nil {
		value, ok := raw.(string)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, "", fmt.Errorf("invalid Google OAuth scope response")
		}
		granted, source = strings.Fields(value), "token"
	}
	set := make(map[string]bool, len(granted))
	for _, scope := range granted {
		set[scope] = true
	}
	for _, scope := range required {
		if !set[scope] {
			return nil, "", fmt.Errorf("Google OAuth did not grant required permission")
		}
	}
	return granted, source, nil
}
