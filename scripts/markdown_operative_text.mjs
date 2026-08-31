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
let headingPrefix = ''
const htmlStack = []

const suppressedTags = new Set(['datalist', 'del', 's', 'strike', 'iframe', 'noscript', 'script', 'style', 'pre', 'textarea', 'template', 'title'])
const voidTags = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'])
const rawTextTags = new Set(['iframe', 'script', 'style', 'textarea', 'title'])
const formattingTags = new Set([
  'a', 'b', 'big', 'code', 'em', 'font', 'i', 'nobr', 's', 'small',
  'strike', 'strong', 'tt', 'u'
])
const svgHtmlIntegrationTags = new Set(['desc', 'foreignobject', 'title'])
const optionalEndTagClosures = new Map([
  ['p', new Set(['p'])],
  ['li', new Set(['li'])],
  ['dt', new Set(['dt', 'dd'])],
  ['dd', new Set(['dt', 'dd'])],
  ['rt', new Set(['rt', 'rp'])],
  ['rp', new Set(['rt', 'rp'])],
  ['option', new Set(['option'])],
  ['optgroup', new Set(['option', 'optgroup'])],
  ['tr', new Set(['tr'])],
  ['th', new Set(['th', 'td'])],
  ['td', new Set(['th', 'td'])],
  ['thead', new Set(['thead', 'tbody', 'tfoot'])],
  ['tbody', new Set(['thead', 'tbody', 'tfoot'])],
  ['tfoot', new Set(['thead', 'tbody'])]
])
const paragraphClosingTags = new Set([
  'address', 'article', 'aside', 'blockquote', 'details', 'div', 'dl',
  'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3',
  'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'main', 'menu', 'nav', 'ol',
  'p', 'pre', 'search', 'section', 'table', 'ul'
])

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
    const numeric = value.slice(index).match(
      /^(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?/
    )
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
      const whitespaceStart = index
      skipWhitespace()
      const operator = value[index]
      if (operator !== '*' && operator !== '/') {
        index = whitespaceStart
        break
      }
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
      const whitespaceStart = index
      skipWhitespace()
      const hasLeadingWhitespace = index > whitespaceStart
      const operator = value[index]
      if (operator !== '+' && operator !== '-') break
      index += 1
      const rightWhitespaceStart = index
      skipWhitespace()
      if (!hasLeadingWhitespace || index === rightWhitespaceStart) return null
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
  const numeric = value.match(
    /^([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)(%)?$/
  )
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
  if (/^(?:initial|inherit|unset|revert|revert-layer)$/.test(value)) {
    return true
  }
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
  if (property === 'color') {
    return /^(?:transparent|currentcolor|black|silver|gray|white|maroon|red|purple|fuchsia|green|lime|olive|yellow|navy|blue|teal|aqua|orange|rebeccapurple)$/.test(value) ||
      /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/.test(value) ||
      isValidFunctionalColor(value)
  }
  return true
}

function isValidFunctionalColor (value) {
  const functional = value.match(
    /^(rgb|rgba|hsl|hsla|hwb|lab|lch|oklab|oklch|color|color-mix|light-dark)\((.+)\)$/
  )
  if (!functional) return false
  if (!/^(?:rgb|rgba|hsl|hsla|hwb|lab|lch|oklab|oklch)$/.test(functional[1])) {
    return true
  }
  const allowedIdentifiers = new Set([
    'a', 'alpha', 'b', 'calc', 'clamp', 'deg', 'e', 'from', 'g', 'grad',
    'h', 'l', 'max', 'min', 'none', 'r', 'rad', 's', 'turn', 'w', 'x', 'y', 'z'
  ])
  const identifiers = functional[2].match(/[a-z]+/g) || []
  return identifiers.every(identifier => allowedIdentifiers.has(identifier)) && (
    /\d/.test(functional[2]) || identifiers.includes('from')
  )
}

function isTransparentColor (value) {
  if (value === 'transparent') return true
  const hexadecimal = value.match(/^#(?:[0-9a-f]{3}([0-9a-f])|[0-9a-f]{6}([0-9a-f]{2}))$/)
  if (hexadecimal) {
    return Number.parseInt(hexadecimal[1] || hexadecimal[2], 16) === 0
  }
  const alpha = value.match(
    /(?:,|\/)\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)(%?)\s*\)$/i
  )
  if (!alpha) return false
  const numericAlpha = Number.parseFloat(alpha[1])
  return numericAlpha <= 0
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

function findCssDeclarationSeparator (value) {
  let quote = null
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (character === '\\' && index + 1 < value.length) {
      index += 1
      continue
    }
    if (quote) {
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
    } else if (character === ':') {
      return index
    }
  }
  return -1
}

function extractCssImportant (value) {
  for (let index = value.length - 1; index >= 0; index -= 1) {
    if (value[index] !== '!') continue
    let precedingBackslashes = 0
    for (let cursor = index - 1; cursor >= 0 && value[cursor] === '\\'; cursor -= 1) {
      precedingBackslashes += 1
    }
    if (precedingBackslashes % 2 !== 0) continue
    if (decodeCssEscapes(value.slice(index + 1)).trim().toLowerCase() === 'important') {
      return { value: value.slice(0, index).trimEnd(), important: true }
    }
  }
  return { value, important: false }
}

function resolveCssVariables (value, customProperties, seen = new Set()) {
  let resolved = ''
  let cursor = 0
  while (cursor < value.length) {
    const relativeStart = value.slice(cursor).search(/var\(/i)
    if (relativeStart < 0) return resolved + value.slice(cursor)
    const start = cursor + relativeStart
    resolved += value.slice(cursor, start)
    let depth = 1
    let end = start + 4
    for (; end < value.length && depth > 0; end += 1) {
      if (value[end] === '(') depth += 1
      if (value[end] === ')') depth -= 1
    }
    if (depth !== 0) return null
    const argumentsList = splitCssFunctionArguments(value.slice(start + 4, end - 1))
    const name = argumentsList.shift()?.trim()
    if (!name?.startsWith('--')) return null
    const fallback = argumentsList.length ? argumentsList.join(',').trim() : null
    let replacement = customProperties.get(name)?.value
    if (replacement === undefined || seen.has(name)) {
      replacement = fallback
    }
    if (replacement === null) return null
    let replacementResolved = resolveCssVariables(
      replacement,
      customProperties,
      new Set([...seen, name])
    )
    if (replacementResolved === null && fallback !== null && replacement !== fallback) {
      replacementResolved = resolveCssVariables(fallback, customProperties, seen)
    }
    if (replacementResolved === null) return null
    resolved += replacementResolved
    cursor = end
  }
  return resolved
}

function hasCssVariable (value) {
  return /var\(/i.test(value)
}

function hasHiddenAttributes (attributes, inheritedCustomProperties = new Map(), tag = '') {
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
    const separator = findCssDeclarationSeparator(encodedDeclaration)
    if (separator < 0) {
      continue
    }
    const decodedProperty = decodeCssEscapes(encodedDeclaration.slice(0, separator))
      .trim()
    const property = decodedProperty.startsWith('--')
      ? decodedProperty
      : decodedProperty.toLowerCase()
    const encodedImportance = extractCssImportant(
      encodedDeclaration.slice(separator + 1).trim()
    )
    let value = decodeCssEscapes(encodedImportance.value).trim()
    if (!property.startsWith('--') && !hasCssVariable(value)) {
      value = value.toLowerCase()
    }
    const important = encodedImportance.important
    if (
      !property.startsWith('--') &&
      !isValidSuppressionDeclaration(property, value) &&
      !hasCssVariable(value)
    ) {
      continue
    }
    const current = declarations.get(property)
    if (!current || important || !current.important) {
      declarations.set(property, { value, important })
    }
  }
  const customProperties = new Map(inheritedCustomProperties)
  for (const [property, declaration] of declarations) {
    if (!property.startsWith('--')) continue
    const cssWideValue = declaration.value.toLowerCase()
    if (cssWideValue === 'initial') {
      customProperties.delete(property)
    } else if (!/^(?:inherit|unset|revert|revert-layer)$/.test(cssWideValue)) {
      customProperties.set(property, declaration)
    }
  }
  for (const property of ['display', 'visibility', 'content-visibility', 'opacity', 'color']) {
    const declaration = declarations.get(property)
    if (!declaration || !hasCssVariable(declaration.value)) continue
    const resolved = resolveCssVariables(declaration.value, customProperties)
    const normalizedResolved = resolved?.toLowerCase() ?? null
    declaration.value = normalizedResolved !== null && isValidSuppressionDeclaration(property, normalizedResolved)
      ? normalizedResolved
      : 'unset'
  }
  return {
    irreversible: (
      parsedAttributes.has('hidden') ||
      parsedAttributes.has('inert') ||
      (tag === 'dialog' && !parsedAttributes.has('open')) ||
      decodeHtmlAttributeEntities(parsedAttributes.get('aria-hidden') || '')
        .toLowerCase() === 'true' ||
      declarations.get('display')?.value === 'none' ||
      declarations.get('content-visibility')?.value === 'hidden' ||
      (parseOpacityValue(declarations.get('opacity')?.value || '') ?? 1) <= 0
    ),
    visibility: declarations.get('visibility')?.value || null,
    color: declarations.get('color')?.value || null,
    customProperties,
    parsedAttributes
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
  for (const entry of htmlStack) {
    if (
      entry.closedDetails &&
      !htmlStack.some(candidate => candidate.summaryOwner === entry)
    ) {
      return true
    }
  }
  let visibilityHidden = false
  for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
    if (htmlStack[index].visibility) {
      if (/^(?:inherit|unset|revert|revert-layer)$/.test(htmlStack[index].visibility)) {
        continue
      }
      visibilityHidden = ['hidden', 'collapse'].includes(htmlStack[index].visibility)
      break
    }
  }
  if (visibilityHidden) return true
  for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
    if (htmlStack[index].color) {
      if (/^(?:inherit|unset|revert|revert-layer|currentcolor)$/.test(htmlStack[index].color)) {
        continue
      }
      return isTransparentColor(htmlStack[index].color)
    }
  }
  return false
}

function updateHtmlSuppression (content, inlineContext = false) {
  const tagPattern = /<(?<closing>\/)?(?<tag>[A-Za-z][A-Za-z0-9-]*)\b(?<attributes>(?:[^<>"']|"[^"]*"|'[^']*')*?)(?<selfClosing>\/)?\s*>/g
  const parseableContent = content.replace(/<!--[\s\S]*?(?:-->|$)/g, '')
  for (const match of parseableContent.matchAll(tagPattern)) {
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
          if (paragraphClosingTags.has(tag)) {
            htmlStack.splice(index)
          } else {
            htmlStack.splice(index, 1)
          }
          break
        }
      }
      continue
    }
    if (paragraphClosingTags.has(tag)) {
      for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
        if (htmlStack[index].tag === 'p') {
          htmlStack.splice(index)
          break
        }
      }
    }
    const optionalClosures = optionalEndTagClosures.get(tag)
    if (optionalClosures) {
      for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
        if (optionalClosures.has(htmlStack[index].tag)) {
          htmlStack.splice(index)
          break
        }
      }
    }
    let attributes = match.groups.attributes
    let selfClosing = Boolean(match.groups.selfClosing)
    if (selfClosing && /=\s*[^\s"'=<>`]*$/.test(attributes)) {
      attributes += '/'
      selfClosing = false
    }
    const inheritedCustomProperties = htmlStack.length
      ? htmlStack[htmlStack.length - 1].customProperties
      : new Map()
    const parent = htmlStack.length ? htmlStack[htmlStack.length - 1] : null
    let summaryOwner = null
    if (tag === 'summary' && parent?.closedDetails && !parent.summarySeen) {
      parent.summarySeen = true
      summaryOwner = parent
    }
    const parentForeign = Boolean(parent?.foreign)
    const foreign = tag === 'svg' || tag === 'math' || (
      parentForeign && !svgHtmlIntegrationTags.has(parent.tag)
    )
    const suppression = hasHiddenAttributes(attributes, inheritedCustomProperties, tag)
    const presentationDisplay = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('display') || ''
    ).trim().toLowerCase()
    if (!selfClosing || (!voidTags.has(tag) && !foreign)) {
      const entry = {
        tag,
        irreversible: suppressedTags.has(tag) || suppression.irreversible || (
          foreign && presentationDisplay === 'none'
        ),
        closedDetails: tag === 'details' && !suppression.parsedAttributes.has('open'),
        summarySeen: false,
        summaryOwner,
        visibility: suppression.visibility,
        color: suppression.color,
        inline: inlineContext,
        foreign,
        customProperties: suppression.customProperties
      }
      htmlStack.push(entry)
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
    if (token.type === 'text' || token.type === 'code_inline') {
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
  if (token.type === 'heading_open') {
    headingPrefix = `${'#'.repeat(Number.parseInt(token.tag.slice(1), 10))} `
    continue
  }
  if (token.type === 'inline') {
    if (!blockquoteDepth && headingPrefix) output.push(headingPrefix)
    processInline(token.children)
    output.push('\n')
    headingPrefix = ''
  } else if (token.type === 'paragraph_close') {
    for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
      if (htmlStack[index].inline && !formattingTags.has(htmlStack[index].tag)) {
        htmlStack.splice(index, 1)
      }
    }
  } else if (token.type === 'html_block') {
    processHtmlBlock(token.content)
  }
}

process.stdout.write(output.join(''))
