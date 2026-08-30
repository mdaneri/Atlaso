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
const htmlStack = []

const suppressedTags = new Set(['del', 's', 'strike', 'script', 'style', 'pre', 'textarea', 'template', 'title'])
const voidTags = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'])
const rawTextTags = new Set(['script', 'style', 'textarea', 'title'])

function hasHiddenAttributes (attributes) {
  const parsedAttributes = new Map()
  const attributePattern = /(?:^|\s)([^\s"'=<>`/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g
  for (const match of attributes.matchAll(attributePattern)) {
    parsedAttributes.set(
      match[1].toLowerCase(),
      match[2] ?? match[3] ?? match[4] ?? null
    )
  }
  if (parsedAttributes.has('hidden')) {
    return true
  }
  if ((parsedAttributes.get('aria-hidden') || '').toLowerCase() === 'true') {
    return true
  }
  const styleValue = markdown.utils
    .unescapeAll(parsedAttributes.get('style') || '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
  const declarations = new Map()
  for (const declaration of styleValue.split(';')) {
    const separator = declaration.indexOf(':')
    if (separator < 0) {
      continue
    }
    const property = declaration.slice(0, separator).trim().toLowerCase()
    let value = declaration.slice(separator + 1).trim().toLowerCase()
    const important = /!\s*important\s*$/i.test(value)
    value = value.replace(/!\s*important\s*$/i, '').trim()
    const current = declarations.get(property)
    if (!current || important || !current.important) {
      declarations.set(property, { value, important })
    }
  }
  return (
    declarations.get('display')?.value === 'none' ||
    ['hidden', 'collapse'].includes(declarations.get('visibility')?.value)
  )
}

function isHtmlSuppressed () {
  return htmlStack.some(entry => entry.suppressed)
}

function updateHtmlSuppression (content) {
  const tagPattern = /<(?<closing>\/)?(?<tag>[A-Za-z][A-Za-z0-9-]*)\b(?<attributes>(?:[^<>"']|"[^"]*"|'[^']*')*?)(?<selfClosing>\/)?\s*>/g
  for (const match of content.matchAll(tagPattern)) {
    const tag = match.groups.tag.toLowerCase()
    const rawTextTag = htmlStack.length && htmlStack[htmlStack.length - 1].tag
    if (
      rawTextTags.has(rawTextTag) &&
      !(match.groups.closing && tag === rawTextTag)
    ) {
      continue
    }
    if (match.groups.closing) {
      for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
        if (htmlStack[index].tag === tag) {
          htmlStack.splice(index, 1)
          break
        }
      }
      continue
    }
    const attributes = match.groups.attributes
    const hidden = hasHiddenAttributes(attributes)
    if (!match.groups.selfClosing || !voidTags.has(tag)) {
      htmlStack.push({ tag, suppressed: suppressedTags.has(tag) || hidden })
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
    if (!blockquoteDepth && !isHtmlSuppressed()) {
      output.push(content.slice(cursor, match.index))
    }
    if (/^<\/?[A-Za-z]/.test(match[0])) {
      updateHtmlSuppression(match[0])
    }
    cursor = match.index + match[0].length
  }
  if (!blockquoteDepth && !isHtmlSuppressed()) {
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
    if (blockquoteDepth || deletionDepth || isHtmlSuppressed()) {
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
