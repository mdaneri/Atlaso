#!/usr/bin/env node
/** Render Markdown into visible policy prose while excluding quoted or retired text. */

import fs from 'node:fs'
import MarkdownIt from 'markdown-it'

const source = fs.readFileSync(0, 'utf8')
const markdown = new MarkdownIt({ html: true })
const tokens = markdown.parse(source, {})
const output = []
let blockquoteDepth = 0
let deletionDepth = 0
const suppressedHtml = []

const suppressedTags = new Set(['del', 's', 'strike', 'script', 'style', 'pre', 'textarea'])

function updateHtmlSuppression (content) {
  const tagPattern = /<(?<closing>\/)?(?<tag>[A-Za-z][A-Za-z0-9-]*)\b(?<attributes>(?:[^<>"']|"[^"]*"|'[^']*')*?)(?<selfClosing>\/)?\s*>/g
  for (const match of content.matchAll(tagPattern)) {
    const tag = match.groups.tag.toLowerCase()
    if (match.groups.closing) {
      for (let index = suppressedHtml.length - 1; index >= 0; index -= 1) {
        if (suppressedHtml[index] === tag) {
          suppressedHtml.splice(index, 1)
          break
        }
      }
      continue
    }
    const attributes = match.groups.attributes
    const hidden = /(?:^|\s)(?:hidden|aria-hidden\s*=\s*["']?true|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden))/i.test(attributes)
    if (suppressedTags.has(tag) || (hidden && !match.groups.selfClosing)) {
      suppressedHtml.push(tag)
    }
  }
}

function processInline (children) {
  for (const token of children || []) {
    if (token.type === 's_open') {
      deletionDepth += 1
      continue
    }
    if (token.type === 's_close') {
      deletionDepth = Math.max(0, deletionDepth - 1)
      continue
    }
    if (token.type === 'html_inline') {
      updateHtmlSuppression(token.content)
      continue
    }
    if (blockquoteDepth || deletionDepth || suppressedHtml.length) {
      continue
    }
    if (token.type === 'text') {
      output.push(token.content)
    } else if (token.type === 'softbreak' || token.type === 'hardbreak') {
      output.push('\n')
    }
  }
}

for (const token of tokens) {
  if (token.type === 'blockquote_open') {
    blockquoteDepth += 1
    continue
  }
  if (token.type === 'blockquote_close') {
    blockquoteDepth = Math.max(0, blockquoteDepth - 1)
    continue
  }
  if (token.type === 'inline') {
    processInline(token.children)
    output.push('\n')
  }
}

process.stdout.write(output.join(''))
