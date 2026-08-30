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

const suppressedTags = new Set(['del', 's', 'strike', 'script', 'style', 'pre', 'textarea', 'template'])
const voidTags = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'])

function hasHiddenAttributes (attributes) {
  if (/(?:^|\s)hidden(?:\s|=|$)/i.test(attributes)) {
    return true
  }
  const ariaHidden = attributes.match(/(?:^|\s)aria-hidden\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i)
  if (ariaHidden && (ariaHidden[1] || ariaHidden[2] || ariaHidden[3] || '').toLowerCase() === 'true') {
    return true
  }
  const style = attributes.match(/(?:^|\s)style\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i)
  const styleValue = style && (style[1] || style[2] || style[3] || '')
  return Boolean(styleValue && /(?:display\s*:\s*none|visibility\s*:\s*hidden)/i.test(styleValue))
}

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
    const hidden = hasHiddenAttributes(attributes)
    if (suppressedTags.has(tag) || (hidden && (!match.groups.selfClosing || !voidTags.has(tag)))) {
      suppressedHtml.push(tag)
    }
  }
}

function processHtmlBlock (content) {
  if (/^\s*<(?:!--|!|\?)/.test(content)) {
    return
  }
  const tagPattern = /<!--[\s\S]*?(?:-->|$)|<![^>]*>|<\?[\s\S]*?(?:\?>|$)|<\/?[A-Za-z][A-Za-z0-9-]*\b(?:[^<>"']|"[^"]*"|'[^']*')*?\/?\s*>/g
  let cursor = 0
  for (const match of content.matchAll(tagPattern)) {
    if (!blockquoteDepth && !suppressedHtml.length) {
      output.push(content.slice(cursor, match.index))
    }
    if (/^<\/?[A-Za-z]/.test(match[0])) {
      updateHtmlSuppression(match[0])
    }
    cursor = match.index + match[0].length
  }
  if (!blockquoteDepth && !suppressedHtml.length) {
    output.push(content.slice(cursor))
  }
  output.push('\n')
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
  } else if (token.type === 'html_block') {
    processHtmlBlock(token.content)
  }
}

process.stdout.write(output.join(''))
