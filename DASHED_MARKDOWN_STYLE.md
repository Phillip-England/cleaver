# Dashed Markdown Style

This document defines the Markdown format expected by applications that produce content for Cleaver's rendered Markdown UI.

## Required page structure

Every page, including the first page, must begin with a page marker. A marker consists of a line containing at least three equals signs, a page title on its own line, and another line containing at least three equals signs.

```markdown
===
FIRST PAGE
===

# Header

- Some information
- More information
- Additional information
```

The opening and closing lines do not need to contain the same number of equals signs. Lines containing three or more equals signs are reserved for page markers and must not be used as ordinary page content.

## Multiple pages

Begin the next page with another complete titled marker:

```markdown
===
ACCOUNTS
===

# Account Details

- Primary account information
- Backup account information

==========
SERVERS
==========

# Server Details

- Production server information
- Development server information
```

Cleaver uses these titles for the rendered page navigation. Each page also receives its own navigation for the level-one headings it contains.

When a paged Markdown lock is opened in Cleaver's editor, the same titles become editor tabs. Editing is scoped to the selected page, and changing the page-title field updates the title written between its marker lines. Exporting reconstructs all pages into one Markdown document.

## Headings and list items

Within each page, organize content into sections. Each section should begin with a level-one Markdown heading, followed by one or more dashed list items.

Use a single `#` followed by a space for each section heading. Use `-` followed by a space for each list item.

Correct:

```markdown
- Some information
```

Incorrect:

```markdown
-Some information
```

The space after the dash is required for the line to be recognized as a Markdown list item.

## Multiple sections on a page

A document may contain multiple sections. Start every section with another level-one heading.

```markdown
===
CONTACTS
===

# Accounts

- Primary account information
- Backup account information

# Servers

- Production server information
- Development server information
```

## List-item content

A list item may contain plain text or standard inline Markdown, including emphasis, links, and inline code.

```markdown
===
RESOURCES
===

# Resources

- Plain text
- **Important information**
- [Project website](https://example.com)
- Run `example-command --option`
```

When Cleaver renders the document, every dashed list item receives its own copy button. The button copies the readable text of that item rather than its Markdown punctuation.

## Complete template

```markdown
===
FIRST PAGE
===

# First Section

- First item
- Second item

# Second Section

- First item
- Second item
```

Applications generating this format should:

- Begin every page, including the first, with an equals-sign line, a title, and another equals-sign line.
- Use at least three equals signs on each page-marker line.
- Never use a line of three or more equals signs as ordinary page content.
- Put a space between `#` and the heading text.
- Put a space between `-` and the list-item content.
- Keep each copyable value in its own list item.
- Use another level-one heading to begin a new section.
