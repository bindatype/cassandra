---
name: rt-ticket-analysis-mcp
description: "RT tickets: oldest, per owner, aging. Ask cass_ask."
version: 1.0.0
author: Glen Maclachlan + Hermes Agent
---

# RT Ticket Analysis (MCP) Skill

The MCP edition of `rt-ticket-analysis`, for a Hermes that reaches Cassandra
through the `mcp__cassandra__cass_ask` tool instead of the `askcass` command.
Answers questions about Request Tracker tickets (the oldest open tickets,
tickets per owner, one owner's tickets, ticket aging) by asking Cassandra the
whole question. Cassandra gets counts and per-owner oldest tickets from RT
itself. This skill never rebuilds, regroups or recounts a ticket table by
hand.

## When to Use

Oldest open tickets, open tickets per owner, one person's tickets, backlog by
age, unowned tickets.

Not for ticket contents or correspondence. Cassandra returns metadata only:
subject, queue, status, owner, created, age_days.

## Prerequisites

`hermes mcp test cassandra` reports "Connected" and one tool. See the
`cassandra-mcp` skill.

## How to Run

One call per question: `mcp__cassandra__cass_ask` with `question` set to the
whole question in plain English. Relay the answer as written, including its
Scope and Limitation lines. Quote figures and ticket IDs from the structured
evidence in the result rather than retyping them.

## Quick Reference

| Want | Ask cass_ask |
|---|---|
| Open tickets per owner | "how many open tickets does each owner have?" |
| Each owner's oldest ticket | "what is the oldest open ticket for each owner? give owner, ticket ID and created date" |
| One owner's oldest ticket | "what is the oldest open ticket owned by <login>?" |
| One owner's tickets | "list the open tickets owned by <login>" |
| Unowned tickets | "list the open tickets owned by Nobody" |
| The N oldest tickets overall | "which open tickets were created more than 30 days ago? list the 10 oldest" |
| The N oldest within a recent window | "which open tickets were created in the last 365 days? list the 20 oldest" |
| Backlog by age | "how many open tickets were created before <date>?" |

Logins are written exactly as Cassandra shows them, e.g. `aklwong@gwu.edu`.

## Procedure

1. Ask the question you were asked, whole, in one call.
2. For several owners at once, ask for all owners in one call (the per-owner
   rows above). Ask once per owner only when you need each owner's full
   list, and never put several logins in one question.
3. Report numbers and ticket IDs exactly as Cassandra gave them.

## Pitfalls

- **Don't rebuild tables yourself.** Never group, sort or count a listing to
  answer a different question. A hand-built table covers one 100-row page,
  and every retyped row is a chance to mistype a login.
- **Each owner's oldest is not the oldest overall.** One owner can hold all
  of the N oldest tickets. Ask for "the N oldest" with an age bound.
- **An unbounded "oldest tickets" question sees the newest page.** Give an
  age bound.
- **Which queues are searched is Cassandra's configuration**, currently
  hpchelp, rtshelp, change, redcaphelp, alerts and lustrepurge. A person
  searching RT across all queues, or with `Status = '__Active__'`, can get a
  different count. Say which queues the answer covers when comparing.
- **There are no requesters.** The owner is the assigned staff member, not
  the person who filed the ticket.
- **Zero tickets for a login may be a typo.** Check the spelling against the
  per-owner counts before saying someone has none.
- **If the answer contradicts the question, the request was wrong; the data
  isn't empty.** If returned ages fall outside the bound you asked for, ask
  again with explicit dates ("created after 2025-10-02"). Never conclude
  that nothing exists.
- **Two answers that disagree are not a bug report yet.** Re-run the same
  question; report a data problem only if it repeats.

## Verification

"what is the oldest open ticket owned by aklwong@gwu.edu?" returned ticket
104416 (created 2025-10-02) on 2026-10-01, matching RT queried directly.
