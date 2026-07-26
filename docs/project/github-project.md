---
title: Atlaso Development Project
description: Track Atlaso issues, pull requests, release scope, ownership, and delivery metadata in GitHub.
audience:
  - contributor
  - maintainer
status: current
---

# Atlaso Development Project

The public [Atlaso Development Project](https://github.com/users/mdaneri/projects/5) is the ongoing planning record for
repository issues and pull requests. GitHub automatically adds new items from `mdaneri/Atlaso`; maintainers then assign
the appropriate milestone and planning metadata. Repository issues and pull requests remain the source of truth for
assignees, labels, milestones, reviewers, and linked work.

## Release tracking

The [Release 1.0 milestone](https://github.com/mdaneri/Atlaso/milestone/1) identifies work included in the first stable
Atlaso release. The project continues after Release 1.0 so later milestones can use the same fields, views, and
automation.

New items enter the project without an assumed priority, complexity, or milestone. A maintainer triages those values
instead of treating an automated estimate as a delivery commitment.

## Project fields

| Field              | Source or allowed values              | Meaning                                       |
| ------------------ | ------------------------------------- | --------------------------------------------- |
| Owner              | `mdaneri`                             | Project-only delivery owner                   |
| Item kind          | Issue, Pull request                   | Repository item type                          |
| Work type          | Bug, Enhancement, Documentation       | Unambiguous type label or linked-issue type   |
| Priority           | P0, P1, P2, P3                        | Maintainer-assigned delivery priority         |
| Complexity         | XS, S, M, L, XL                       | Reproducible change-size proxy                |
| Opened             | GitHub creation date                  | Calendar date when the item was created       |
| Completed          | GitHub close or merge date            | Calendar date when completed                  |
| Cycle time (hours) | Creation to close or merge            | Elapsed wall-clock time, not engineering time |
| Changed files      | Pull-request metadata                 | Number of files changed                       |
| Changed lines      | Pull-request additions plus deletions | Total changed-line count                      |

Pull-request complexity uses the larger bucket produced by changed lines and changed files:

| Complexity | Changed lines | Changed files |
| ---------- | ------------- | ------------- |
| XS         | 0–200         | 0–5           |
| S          | 201–500       | 6–10          |
| M          | 501–1,500     | 11–25         |
| L          | 1,501–4,000   | 26–50         |
| XL         | >4,000        | >50           |

An issue inherits the highest complexity of its linked pull requests. Complexity remains empty when no linked delivery
evidence exists. Work type also remains empty when labels or linked issues do not identify exactly one type.

## Views and maintenance

- **Overview** is the complete issue and pull-request inventory.
- **Release 1.0** filters the current release milestone and groups work by status.
- **Open work** is the active backlog and work in progress.
- **Pull requests** focuses on delivery, reviewers, change size, and linked issues.
- **History** retains completed and closed work for cycle-time and complexity analysis.

Project insights summarize item counts by status, work type, and complexity. GitHub's built-in workflows set closed
issues and merged pull requests to **Done**. Maintainers should periodically filter for empty Owner, Work type, Priority,
Complexity, or Milestone values and triage them.

## Organization migration

When Atlaso moves to the `atlaso-project` organization, move this project with the repository through GitHub account
settings. After the move, verify the repository link and auto-add workflow and update this page to the organization-owned
project URL. Do not copy the project as a migration mechanism because a copy does not include the project items,
collaborators, repository link, or auto-add workflow.
