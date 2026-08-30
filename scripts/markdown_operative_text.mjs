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

function splitCssFunctionArguments (value) {
  const argumentsList = []
  let current = ''
  let parenthesisDepth = 0
  for (const character of value) {
    if (character === '(') {
      parenthesisDepth += 1
    } else if (character === ')') {
      parenthesisDepth = Math.max(0, parenthesisDepth - 1)
    }
    if (character === ',' && parenthesisDepth === 0) {
      argumentsList.push(current.trim())
      current = ''
    } else {
      current += character
    }
  }
  argumentsList.push(current.trim())
  return argumentsList
}

function evaluateCalcExpression (value) {
  let index = 0
  function skipWhitespace () {
    while (/\s/.test(value[index] || '')) index += 1
  }
  function parseFactor () {
    skipWhitespace()
    let sign = 1
    if (value[index] === '+' || value[index] === '-') {
      if (value[index] === '-') sign = -1
      index += 1
      skipWhitespace()
    }
    if (value[index] === '(') {
      index += 1
      const nested = parseExpression()
      skipWhitespace()
      if (nested === null || value[index] !== ')') return null
      index += 1
      return sign * nested
    }
    const numeric = value.slice(index).match(/^(?:\d+(?:\.\d*)?|\.\d+)/)
    if (!numeric) return null
    index += numeric[0].length
    let parsed = Number.parseFloat(numeric[0])
    if (value[index] === '%') {
      parsed /= 100
      index += 1
    }
    return sign * parsed
  }
  function parseTerm () {
    let result = parseFactor()
    if (result === null) return null
    while (true) {
      skipWhitespace()
      const operator = value[index]
      if (operator !== '*' && operator !== '/') break
      index += 1
      const right = parseFactor()
      if (right === null || (operator === '/' && right === 0)) return null
      result = operator === '*' ? result * right : result / right
    }
    return result
  }
  function parseExpression () {
    let result = parseTerm()
    if (result === null) return null
    while (true) {
      skipWhitespace()
      const operator = value[index]
      if (operator !== '+' && operator !== '-') break
      index += 1
      const right = parseTerm()
      if (right === null) return null
      result = operator === '+' ? result + right : result - right
    }
    return result
  }
  const result = parseExpression()
  skipWhitespace()
  return result !== null && index === value.length ? result : null
}

function parseOpacityValue (value) {
  const numeric = value.match(/^([+-]?(?:\d+(?:\.\d*)?|\.\d+))(%)?$/)
  if (numeric) {
    const parsed = Number.parseFloat(numeric[1])
    return numeric[2] ? parsed / 100 : parsed
  }
  const functional = value.match(/^(calc|min|max|clamp)\((.*)\)$/)
  if (!functional) {
    return null
  }
  if (functional[1] === 'calc') {
    return evaluateCalcExpression(functional[2])
  }
  const values = splitCssFunctionArguments(functional[2]).map(parseOpacityValue)
  if (values.some(item => item === null)) {
    return null
  }
  if (functional[1] === 'min' && values.length > 0) {
    return Math.min(...values)
  }
  if (functional[1] === 'max' && values.length > 0) {
    return Math.max(...values)
  }
  if (functional[1] === 'clamp' && values.length === 3) {
    return Math.max(values[0], Math.min(values[1], values[2]))
  }
  return null
}

function isValidSuppressionDeclaration (property, value) {
  if (property === 'display') {
    return /^(?:none|inline|block|inline-block|flow-root|flex|inline-flex|grid|inline-grid|table|list-item|contents)$/.test(value)
  }
  if (property === 'visibility') {
    return /^(?:visible|hidden|collapse)$/.test(value)
  }
  if (property === 'content-visibility') {
    return /^(?:visible|hidden|auto)$/.test(value)
  }
  if (property === 'opacity') {
    return parseOpacityValue(value) !== null
  }
  return true
}

function stripCssComments (value) {
  let outputValue = ''
  let quote = null
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (character === '\\' && index + 1 < value.length) {
      outputValue += character + value[index + 1]
      index += 1
      continue
    }
    if (quote) {
      outputValue += character
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      outputValue += character
      continue
    }
    if (character === '/' && value[index + 1] === '*') {
      const end = value.indexOf('*/', index + 2)
      index = end < 0 ? value.length : end + 1
      continue
    }
    outputValue += character
  }
  return outputValue
}

function hasHiddenAttributes (attributes) {
  const parsedAttributes = new Map()
  const attributePattern = /(?:^|\s)([^\s"'=<>`/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g
  for (const match of attributes.matchAll(attributePattern)) {
    const name = match[1].toLowerCase()
    if (!parsedAttributes.has(name)) {
      parsedAttributes.set(name, match[2] ?? match[3] ?? match[4] ?? null)
    }
  }
  const styleValue = stripCssComments(
    decodeHtmlAttributeEntities(parsedAttributes.get('style') || '')
  )
  const declarations = new Map()
  for (const encodedDeclaration of splitCssDeclarations(styleValue)) {
    const declaration = decodeCssEscapes(encodedDeclaration)
    const separator = declaration.indexOf(':')
    if (separator < 0) {
      continue
    }
    const property = declaration.slice(0, separator).trim().toLowerCase()
    let value = declaration.slice(separator + 1).trim().toLowerCase()
    const important = /!\s*important\s*$/i.test(value)
    value = value.replace(/!\s*important\s*$/i, '').trim()
    if (!isValidSuppressionDeclaration(property, value)) {
      continue
    }
    const current = declarations.get(property)
    if (!current || important || !current.important) {
      declarations.set(property, { value, important })
    }
  }
  return {
    irreversible: (
      parsedAttributes.has('hidden') ||
      (parsedAttributes.get('aria-hidden') || '').toLowerCase() === 'true' ||
      declarations.get('display')?.value === 'none' ||
      declarations.get('content-visibility')?.value === 'hidden' ||
      (parseOpacityValue(declarations.get('opacity')?.value || '') ?? 1) <= 0
    ),
    visibility: declarations.get('visibility')?.value || null
  }
}

function decodeHtmlAttributeEntities (value) {
  const numericDecoded = value.replace(
    /&#(?:x([0-9A-Fa-f]+)|([0-9]+));?/g,
    (_, hexadecimal, decimal) => {
      const codePoint = Number.parseInt(hexadecimal || decimal, hexadecimal ? 16 : 10)
      return String.fromCodePoint(
        codePoint === 0 || codePoint > 0x10FFFF ? 0xFFFD : codePoint
      )
    }
  )
  return numericDecoded.replace(
    /&[A-Za-z][A-Za-z0-9]+;?/g,
    entity => markdown.utils.unescapeAll(entity)
  )
}

function splitCssDeclarations (value) {
  const declarations = []
  let current = ''
  let quote = null
  let parenthesisDepth = 0
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (character === '\\' && index + 1 < value.length) {
      current += character + value[index + 1]
      index += 1
      continue
    }
    if (quote) {
      current += character
      if (character === quote) {
        quote = null
      }
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      current += character
    } else if (character === '(') {
      parenthesisDepth += 1
      current += character
    } else if (character === ')') {
      parenthesisDepth = Math.max(0, parenthesisDepth - 1)
      current += character
    } else if (character === ';' && parenthesisDepth === 0) {
      declarations.push(current)
      current = ''
    } else {
      current += character
    }
  }
  declarations.push(current)
  return declarations
}

function decodeCssEscapes (value) {
  return value.replace(
    /\\(?:([0-9A-Fa-f]{1,6})(?:\r\n|[ \t\r\n\f])?|([^\r\n\f]))/g,
    (_, hexadecimal, escapedCharacter) => {
      if (!hexadecimal) {
        return escapedCharacter
      }
      const codePoint = Number.parseInt(hexadecimal, 16)
      return String.fromCodePoint(
        codePoint === 0 || codePoint > 0x10FFFF ? 0xFFFD : codePoint
      )
    }
  )
}

function isHtmlSuppressed () {
  if (htmlStack.some(entry => entry.irreversible)) {
    return true
  }
  for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
    if (htmlStack[index].visibility) {
      return ['hidden', 'collapse'].includes(htmlStack[index].visibility)
    }
  }
  return false
}

function updateHtmlSuppression (content, inlineContext = false) {
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
    const suppression = hasHiddenAttributes(attributes)
    if (!match.groups.selfClosing || !voidTags.has(tag)) {
      htmlStack.push({
        tag,
        irreversible: suppressedTags.has(tag) || suppression.irreversible,
        visibility: suppression.visibility,
        inline: inlineContext
      })
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
      output.push(markdown.utils.unescapeAll(content.slice(cursor, match.index)))
    }
    if (/^<\/?[A-Za-z]/.test(match[0])) {
      updateHtmlSuppression(match[0])
    }
    cursor = match.index + match[0].length
  }
  if (!blockquoteDepth && !isHtmlSuppressed()) {
    output.push(markdown.utils.unescapeAll(content.slice(cursor)))
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
      updateHtmlSuppression(token.content, true)
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
  } else if (token.type === 'paragraph_close') {
    for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
      if (htmlStack[index].inline) {
        htmlStack.splice(index, 1)
      }
    }
  } else if (token.type === 'html_block') {
    processHtmlBlock(token.content)
  }
}

process.stdout.write(output.join(''))
