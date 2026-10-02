---
name: rt-ticket-analysis
description: "RT tickets: oldest, per owner, aging. Answer via askcass."
version: 2.1.0
author: Glen Maclachlan + Hermes Agent
---

# RT Ticket Analysis Skill

Answers questions about Request Tracker tickets (the oldest open tickets,
tickets per owner, one owner's tickets, ticket aging) by asking `askcass` the
whole question. Cassandra gets counts and per-owner oldest tickets from RT
itself, in Go. This skill never rebuilds, regroups or recounts a ticket table
by hand.

## When to Use

Oldest open tickets, open tickets per owner, one person's tickets, backlog by
age, unowned tickets.

Not for ticket contents or correspondence. Cassandra returns metadata only:
subject, queue, status, owner, created, age_days.

## Prerequisites

`askcass` on PATH and working for this account. Check it with
`askcass "how many open tickets does each owner have?"`.

## How to Run

One `terminal` call per question:

```
askcass "<the whole question, in plain English>"
```

Relay the answer as written, including its Scope and Limitation lines.

## Quick Reference

| Want | Ask askcass |
|---|---|
| Open tickets per owner | "how many open tickets does each owner have?" |
| Each owner's oldest ticket | "what is the oldest open ticket for each owner? give owner, ticket ID and created date" |
| One owner's oldest ticket | "what is the oldest open ticket owned by <login>?" |
| One owner's tickets | "list the open tickets owned by <login>" |
| Unowned tickets | "list the open tickets owned by Nobody" |
| The N oldest tickets overall | "which open tickets were created more than 30 days ago? list the 10 oldest" |
| The N oldest within a recent window | "which open tickets were created in the last 365 days? list the 20 oldest" |
| Each owner's oldest within a window | "for open tickets created in the last 365 days, what is the oldest ticket for each owner?" |
| Backlog by age | "how many open tickets were created before <date>?" |

Logins are written exactly as askcass shows them, e.g. `aklwong@gwu.edu`.

## Procedure

1. Ask askcass the question you were asked, whole, in one call.
2. For a question about several owners at once, ask for all owners in one
   call (the per-owner rows above). Don't loop over owners unless you need
   each owner's full ticket list. Then ask once per owner, never with
   several logins in one question.
3. Report numbers and ticket IDs exactly as askcass gave them.

## Pitfalls

- **Don't rebuild tables yourself.** Never take a listing and group, sort or
  count it to answer a different question. Each owner's count and oldest
  ticket come from RT through Cassandra. A table rebuilt by hand covers one
  100-row page, and every retyped row is a chance to mistype. On 2026-10-01
  `aklwong` came out as `uklwong` that way.
- **Each owner's oldest is not the oldest overall.** One owner can hold all of
  the N oldest tickets: the five oldest on 2026-10-01 were all suarezm's. Ask
  for "the N oldest" with an age bound ("created more than 30 days ago"), not
  by combining owners.
- **An unbounded "oldest tickets" question sees the newest page.** Give an age
  bound. askcass says so when a page is the newest rather than the oldest.
- **There are no requesters.** The owner is the staff member assigned to the
  ticket, not the person who filed it. If asked for requesters, say askcass
  does not provide them.
- **Zero tickets for a login may be a typo.** askcass warns about this. Check
  the spelling against the per-owner counts before saying someone has none.
- **If the answer contradicts the question, the request was wrong; the data
  isn't empty.** Check the ages or dates askcass returns against the bound
  you asked for. On 2026-10-02, "less than 365 days old" came back as tickets
  1,724, 567 and 426 days old, because the bound had been reversed. The
  agent then wrote "no tickets are less than 365 days old", while 569 were.
  When results fall outside the bound, ask again with explicit dates
  ("created after 2025-10-02"). Never conclude that nothing exists.
- **Two askcass answers that disagree are not a bug report yet.** Re-run the
  same question. A one-off difference is almost always the model mis-copying a
  row. Report a data problem only if it repeats.

## Verification

`askcass "what is the oldest open ticket owned by aklwong@gwu.edu?"` returned
ticket 104416 (created 2025-10-02) on 2026-10-01, matching RT queried
directly.
