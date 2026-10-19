package broker

import "fmt"

// Read-only stops a query from changing data, not from holding up the server
// it runs on. The credential's grant permits all of the constructs below, so
// the grant cannot stop them; none has a use in an accounting question.
//
// A locking read is still a SELECT. On InnoDB a plain SELECT takes no row
// locks, but FOR UPDATE and LOCK IN SHARE MODE lock every row they scan until
// the statement ends, which can stall the ingest writing new jobs for as long
// as the statement time limit allows. GET_LOCK and RELEASE_LOCK take or drop
// server-wide named locks that other applications on the server may rely on.
// SLEEP and BENCHMARK only spend the statement time.

// lockingClauses are word sequences that make a read take locks.
var lockingClauses = [][]string{
	{"FOR", "UPDATE"},
	{"LOCK", "IN", "SHARE", "MODE"},
}

// stallingFunctions are rejected when called, that is, followed by "(". A
// column of the same name is not a call.
var stallingFunctions = []string{"GET_LOCK", "RELEASE_LOCK", "RELEASE_ALL_LOCKS", "SLEEP", "BENCHMARK"}

// lockingOrStallingConstruct returns the first construct in query that would
// lock rows, take a named lock, or idle the server. Strings, quoted
// identifiers and comments are skipped, so prose that names one is accepted.
func lockingOrStallingConstruct(query string) (string, bool) {
	tokens, _ := lexQueryStructure(query)
	for i := range tokens {
		for _, clause := range lockingClauses {
			if wordsAt(tokens, i, clause) {
				return joinWords(clause), true
			}
		}
		for _, name := range stallingFunctions {
			if tokens[i].word == name && i+1 < len(tokens) && tokens[i+1].word == "(" {
				return name + "()", true
			}
		}
	}
	return "", false
}

func wordsAt(tokens []queryStructureToken, at int, words []string) bool {
	if at+len(words) > len(tokens) {
		return false
	}
	for j, word := range words {
		if tokens[at+j].word != word {
			return false
		}
	}
	return true
}

func joinWords(words []string) string {
	joined := words[0]
	for _, word := range words[1:] {
		joined += " " + word
	}
	return joined
}

// executableComment reports a MariaDB executable comment, /*! ... */ or
// /*M! ... */. The server runs what is inside it, so a guard that skips
// comments, as every guard here does, would not see a construct hidden in
// one. Ordinary comments, and comment markers inside strings, are allowed.
func executableComment(query string) bool {
	for i := 0; i < len(query); {
		switch {
		case query[i] == '\'' || query[i] == '"' || query[i] == '`':
			i = skipSQLQuoted(query, i)
		case query[i] == '#':
			i = skipSQLLine(query, i+1)
		case query[i] == '-' && i+1 < len(query) && query[i+1] == '-':
			i = skipSQLLine(query, i+2)
		case query[i] == '/' && i+1 < len(query) && query[i+1] == '*':
			body := query[i+2:]
			if len(body) > 0 && body[0] == '!' || len(body) > 1 && (body[0] == 'M' || body[0] == 'm') && body[1] == '!' {
				return true
			}
			i = skipSQLBlockComment(query, i+2)
		default:
			i++
		}
	}
	return false
}

// lockingOrStallingError explains the refusal so the model can drop the
// construct and retry; it is a malformed request, not an authorization answer.
func lockingOrStallingError(construct string) error {
	return fmt.Errorf("%s is not allowed: a read needs no lock, and this one would lock rows or "+
		"idle the shared accounting server for up to the statement time limit. Remove it and ask again", construct)
}
