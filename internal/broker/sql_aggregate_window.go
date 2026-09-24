package broker

import "strings"

// conflictingUngroupedAggregateWindow reports whether one SELECT scope mixes a
// plain aggregate with a window function without GROUP BY.
//
// In that shape the aggregate collapses the source rows to one row before the
// window function runs. The window therefore sees one value, not the source
// population. LIMIT 1 only hides the resulting single row; it does not repair
// the calculation. This is how a live query returned a zero median while the
// equivalent all-window query returned a non-zero value over the same 217 jobs.
//
// Query scopes matter. An outer COUNT/MAX over a subquery that computes a
// percentile is the recommended repair and must remain valid, so this scanner
// treats every SELECT independently and ignores nested SELECT scopes while
// examining their parent.
func conflictingUngroupedAggregateWindow(query string) bool {
	tokens, scopes := lexQueryStructure(query)
	for i := range tokens {
		if tokens[i].word != "SELECT" {
			continue
		}
		if selectScopeMixesAggregateAndWindow(tokens, scopes, i) {
			return true
		}
	}
	return false
}

type queryStructureToken struct {
	word  string
	scope int
	mate  int
}

type queryStructureScope struct {
	parent    int
	hasSelect bool
}

var plainAggregateNames = map[string]bool{
	"AVG": true, "BIT_AND": true, "BIT_OR": true, "BIT_XOR": true,
	"COUNT": true, "GROUP_CONCAT": true, "MAX": true, "MIN": true,
	"STD": true, "STDDEV": true, "STDDEV_POP": true, "STDDEV_SAMP": true,
	"SUM": true, "VAR_POP": true, "VAR_SAMP": true, "VARIANCE": true,
}

func selectScopeMixesAggregateAndWindow(tokens []queryStructureToken, scopes []queryStructureScope, selectAt int) bool {
	scope := tokens[selectAt].scope
	selectEnd, statementEnd := selectScopeBounds(tokens, scopes, selectAt)

	hasWindow := false
	hasPlainAggregate := false
	for i := selectAt + 1; i < selectEnd; i++ {
		if !tokenVisibleInSelectScope(tokens[i], scope, scopes) {
			continue
		}
		if tokens[i].word == "OVER" {
			hasWindow = true
		}
		if !plainAggregateNames[tokens[i].word] {
			continue
		}
		open := nextVisibleToken(tokens, scopes, scope, i+1, selectEnd)
		if open < 0 || tokens[open].word != "(" || tokens[open].mate < 0 {
			continue
		}
		after := nextVisibleToken(tokens, scopes, scope, tokens[open].mate+1, selectEnd)
		if after < 0 || tokens[after].word != "OVER" {
			hasPlainAggregate = true
		}
	}
	if !hasWindow || !hasPlainAggregate {
		return false
	}

	// A grouped query can legitimately aggregate each group and then apply a
	// window over the grouped rows. The separate GROUP BY/PARTITION BY guard
	// rejects the degenerate case where that partition contains one row.
	for i := selectEnd; i < statementEnd; i++ {
		if tokens[i].scope != scope || tokens[i].word != "GROUP" {
			continue
		}
		next := nextTokenInExactScope(tokens, scope, i+1, statementEnd)
		if next >= 0 && tokens[next].word == "BY" {
			return false
		}
	}
	return true
}

// selectScopeBounds returns the end of the SELECT list and the end of this
// SELECT arm. A UNION starts another arm in the same parenthesis scope.
func selectScopeBounds(tokens []queryStructureToken, scopes []queryStructureScope, selectAt int) (int, int) {
	scope := tokens[selectAt].scope
	selectEnd := len(tokens)
	statementEnd := len(tokens)
	foundFrom := false
	for i := selectAt + 1; i < len(tokens); i++ {
		if !scopeContains(scopes, scope, tokens[i].scope) {
			if !foundFrom {
				selectEnd = i
			}
			statementEnd = i
			break
		}
		if tokens[i].scope != scope {
			continue
		}
		if tokens[i].word == "UNION" {
			if !foundFrom {
				selectEnd = i
			}
			statementEnd = i
			break
		}
		if !foundFrom && tokens[i].word == "FROM" {
			selectEnd = i
			foundFrom = true
		}
	}
	if !foundFrom {
		return selectEnd, statementEnd
	}
	for i := selectEnd + 1; i < statementEnd; i++ {
		if !scopeContains(scopes, scope, tokens[i].scope) ||
			(tokens[i].scope == scope && tokens[i].word == "UNION") {
			statementEnd = i
			break
		}
	}
	return selectEnd, statementEnd
}

func nextVisibleToken(tokens []queryStructureToken, scopes []queryStructureScope, selectScope, from, until int) int {
	for i := from; i < until; i++ {
		if tokenVisibleInSelectScope(tokens[i], selectScope, scopes) {
			return i
		}
	}
	return -1
}

func nextTokenInExactScope(tokens []queryStructureToken, scope, from, until int) int {
	for i := from; i < until; i++ {
		if tokens[i].scope == scope {
			return i
		}
	}
	return -1
}

func tokenVisibleInSelectScope(token queryStructureToken, selectScope int, scopes []queryStructureScope) bool {
	for scope := token.scope; scope != selectScope; scope = scopes[scope].parent {
		if scope < 0 || scopes[scope].hasSelect {
			return false
		}
	}
	return true
}

func scopeContains(scopes []queryStructureScope, ancestor, scope int) bool {
	for scope >= 0 {
		if scope == ancestor {
			return true
		}
		scope = scopes[scope].parent
	}
	return false
}

// lexQueryStructure keeps only words and parentheses. Strings, quoted
// identifiers, and comments are skipped so examples in prose cannot trigger a
// correctness guard. Each parenthesis receives a scope id; function argument
// scopes remain visible to their SELECT, while a scope containing another
// SELECT is treated as a subquery.
func lexQueryStructure(query string) ([]queryStructureToken, []queryStructureScope) {
	scopes := []queryStructureScope{{parent: -1}}
	stack := []int{0}
	var openTokens []int
	var tokens []queryStructureToken

	for i := 0; i < len(query); {
		switch {
		case isSQLSpace(query[i]):
			i++
		case query[i] == '\'' || query[i] == '"' || query[i] == '`':
			i = skipSQLQuoted(query, i)
		case query[i] == '#':
			i = skipSQLLine(query, i+1)
		case query[i] == '-' && i+1 < len(query) && query[i+1] == '-':
			i = skipSQLLine(query, i+2)
		case query[i] == '/' && i+1 < len(query) && query[i+1] == '*':
			i = skipSQLBlockComment(query, i+2)
		case isSQLWordByte(query[i]):
			start := i
			for i < len(query) && isSQLWordByte(query[i]) {
				i++
			}
			tokens = append(tokens, queryStructureToken{
				word: strings.ToUpper(query[start:i]), scope: stack[len(stack)-1], mate: -1,
			})
		case query[i] == '(':
			parent := stack[len(stack)-1]
			child := len(scopes)
			scopes = append(scopes, queryStructureScope{parent: parent})
			tokens = append(tokens, queryStructureToken{word: "(", scope: parent, mate: -1})
			openTokens = append(openTokens, len(tokens)-1)
			stack = append(stack, child)
			i++
		case query[i] == ')':
			child := stack[len(stack)-1]
			tokens = append(tokens, queryStructureToken{word: ")", scope: child, mate: -1})
			closeAt := len(tokens) - 1
			if len(openTokens) > 0 {
				openAt := openTokens[len(openTokens)-1]
				openTokens = openTokens[:len(openTokens)-1]
				tokens[openAt].mate = closeAt
				tokens[closeAt].mate = openAt
			}
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			i++
		default:
			tokens = append(tokens, queryStructureToken{
				word: string(query[i]), scope: stack[len(stack)-1], mate: -1,
			})
			i++
		}
	}
	for _, token := range tokens {
		if token.word == "SELECT" {
			scopes[token.scope].hasSelect = true
		}
	}
	return tokens, scopes
}

func isSQLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func isSQLWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

func skipSQLQuoted(query string, at int) int {
	quote := query[at]
	for i := at + 1; i < len(query); i++ {
		if query[i] == '\\' {
			i++
			continue
		}
		if query[i] != quote {
			continue
		}
		if i+1 < len(query) && query[i+1] == quote {
			i++
			continue
		}
		return i + 1
	}
	return len(query)
}

func skipSQLLine(query string, at int) int {
	for at < len(query) && query[at] != '\n' {
		at++
	}
	return at
}

func skipSQLBlockComment(query string, at int) int {
	for at+1 < len(query) {
		if query[at] == '*' && query[at+1] == '/' {
			return at + 2
		}
		at++
	}
	return len(query)
}
