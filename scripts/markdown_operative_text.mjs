#!/usr/bin/env node
/** Render Markdown into visible policy prose while excluding quoted or retired text. */

import fs from 'node:fs'

const payload = JSON.parse(fs.readFileSync(0, 'utf8'))
const tokens = payload.tokens
const entityDecodings = payload.entities
const output = []
let blockquoteDepth = 0
let deletionDepth = 0
let headingPrefix = ''
let embeddedStylePresent = false
const htmlStack = []

const suppressedTags = new Set(['audio', 'canvas', 'datalist', 'del', 's', 'strike', 'iframe', 'noscript', 'script', 'style', 'pre', 'textarea', 'template', 'title', 'video'])
const voidTags = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'])
const rawTextTags = new Set(['iframe', 'script', 'style', 'textarea', 'title'])
const formattingTags = new Set([
  'a', 'b', 'big', 'code', 'em', 'font', 'i', 'nobr', 's', 'small',
  'strike', 'strong', 'tt', 'u'
])
const svgHtmlIntegrationTags = new Set(['desc', 'foreignobject', 'title'])
const mathHtmlIntegrationTags = new Set(['mi', 'mn', 'mo', 'ms', 'mtext'])
const mathHtmlIntegrationExceptions = new Set(['malignmark', 'mglyph'])
const transformFunctions = new Set([
  'matrix', 'matrix3d', 'perspective', 'rotate', 'rotate3d', 'rotatex', 'rotatey',
  'rotatez', 'scale', 'scale3d', 'scalex', 'scaley', 'scalez', 'skew', 'skewx',
  'skewy', 'translate', 'translate3d', 'translatex', 'translatey', 'translatez'
])
const filterFunctions = new Set([
  'blur', 'brightness', 'contrast', 'drop-shadow', 'grayscale', 'hue-rotate',
  'invert', 'opacity', 'saturate', 'sepia', 'url'
])
const fontSizeUnits = new Set([
  'cap', 'ch', 'cm', 'cqb', 'cqh', 'cqi', 'cqmax', 'cqmin', 'cqw', 'dvb', 'dvh',
  'dvi', 'dvmax', 'dvmin', 'dvw', 'em', 'ex', 'ic', 'in', 'lh', 'lvb', 'lvh',
  'lvi', 'lvmax', 'lvmin', 'lvw', 'mm', 'pc', 'pt', 'px', 'q', 'rem', 'rlh',
  'svb', 'svh', 'svi', 'svmax', 'svmin', 'svw', 'vb', 'vh', 'vi', 'vmax',
  'vmin', 'vw'
])
const tableContextChildren = new Map([
  ['table', new Set(['caption', 'colgroup', 'script', 'style', 'tbody', 'template', 'tfoot', 'thead'])],
  ['colgroup', new Set(['col', 'template'])],
  ['tbody', new Set(['script', 'style', 'template', 'tr'])],
  ['tfoot', new Set(['script', 'style', 'template', 'tr'])],
  ['thead', new Set(['script', 'style', 'template', 'tr'])],
  ['tr', new Set(['script', 'style', 'td', 'template', 'th'])]
])

function unescapeAll (value) {
  return value
    .replace(/\\([!"#$%&'()*+,\-./:;<=>?@[\]^_`{|}~])/g, '$1')
    .replace(
      /&(?:#[xX][0-9A-Fa-f]+|#[0-9]+|[A-Za-z][A-Za-z0-9]+);?/g,
      entity => entityDecodings[entity] ?? entity
    )
}
const cssNamedColors = new Set([
  'aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque',
  'black', 'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood',
  'cadetblue', 'chartreuse', 'chocolate', 'coral', 'cornflowerblue', 'cornsilk',
  'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod', 'darkgray',
  'darkgreen', 'darkgrey', 'darkkhaki', 'darkmagenta', 'darkolivegreen',
  'darkorange', 'darkorchid', 'darkred', 'darksalmon', 'darkseagreen',
  'darkslateblue', 'darkslategray', 'darkslategrey', 'darkturquoise', 'darkviolet',
  'deeppink', 'deepskyblue', 'dimgray', 'dimgrey', 'dodgerblue', 'firebrick',
  'floralwhite', 'forestgreen', 'fuchsia', 'gainsboro', 'ghostwhite', 'gold',
  'goldenrod', 'gray', 'green', 'greenyellow', 'grey', 'honeydew', 'hotpink',
  'indianred', 'indigo', 'ivory', 'khaki', 'lavender', 'lavenderblush',
  'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan',
  'lightgoldenrodyellow', 'lightgray', 'lightgreen', 'lightgrey', 'lightpink',
  'lightsalmon', 'lightseagreen', 'lightskyblue', 'lightslategray',
  'lightslategrey', 'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen',
  'magenta', 'maroon', 'mediumaquamarine', 'mediumblue', 'mediumorchid',
  'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen',
  'mediumturquoise', 'mediumvioletred', 'midnightblue', 'mintcream', 'mistyrose',
  'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab', 'orange',
  'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise',
  'palevioletred', 'papayawhip', 'peachpuff', 'peru', 'pink', 'plum',
  'powderblue', 'purple', 'rebeccapurple', 'red', 'rosybrown', 'royalblue',
  'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna',
  'silver', 'skyblue', 'slateblue', 'slategray', 'slategrey', 'snow',
  'springgreen', 'steelblue', 'tan', 'teal', 'thistle', 'tomato', 'turquoise',
  'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen'
])
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
    return isValidDisplayValue(value)
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
  if (property === 'fill-opacity' || property === 'stroke-opacity') {
    return parseOpacityValue(value) !== null
  }
  if (property === 'fill' || property === 'stroke') {
    return value === 'none' || value === 'context-fill' || value === 'context-stroke' ||
      isValidColorValue(value) || /^url\(.+\)(?:\s+.+)?$/.test(value)
  }
  if (property === 'filter') {
    const functions = parseCssFunctions(value)
    return value === 'none' || Boolean(
      functions && functions.every(isValidFilterFunction)
    )
  }
  if (property === 'font-size') {
    return isValidFontSize(value)
  }
  if (property === 'transform') {
    const functions = parseCssFunctions(value)
    return value === 'none' || Boolean(
      functions && functions.every(isValidTransformFunction)
    )
  }
  if (property === 'clip-path') {
    return value === 'none' || /^(?:url|inset|circle|ellipse|polygon|path|rect|xywh)\(.+\)$/.test(value)
  }
  if (property === 'color') {
    return value === 'transparent' || value === 'currentcolor' ||
      cssNamedColors.has(value) ||
      /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/.test(value) ||
      isValidFunctionalColor(value)
  }
  return true
}

function isValidDisplayValue (value) {
  const singleValues = new Set([
    'none', 'contents', 'block', 'inline', 'run-in', 'flow', 'flow-root', 'flex',
    'grid', 'ruby', 'list-item', 'inline-block', 'inline-table', 'inline-flex',
    'inline-grid', 'table', 'table-row-group', 'table-header-group',
    'table-footer-group', 'table-row', 'table-cell', 'table-column-group',
    'table-column', 'table-caption', 'ruby-base', 'ruby-text',
    'ruby-base-container', 'ruby-text-container'
  ])
  if (singleValues.has(value)) return true
  const tokens = value.split(/\s+/)
  const outside = tokens.filter(token => ['block', 'inline', 'run-in'].includes(token))
  const inside = tokens.filter(token => ['flow', 'flow-root', 'table', 'flex', 'grid', 'ruby'].includes(token))
  const listItems = tokens.filter(token => token === 'list-item')
  if (outside.length > 1 || inside.length !== 1 || listItems.length > 1) return false
  if (outside.length + inside.length + listItems.length !== tokens.length) return false
  return listItems.length === 0 || ['flow', 'flow-root'].includes(inside[0])
}

function isValidFontSize (value) {
  if (/^(?:xx-small|x-small|small|medium|large|x-large|xx-large|xxx-large|larger|smaller|math)$/.test(value)) {
    return true
  }
  const numeric = value.match(
    /^([+]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)(%|[a-z]+)?$/
  )
  if (numeric) {
    if (numeric[2] === '%') return true
    if (!numeric[2]) return Number.parseFloat(numeric[1]) === 0
    return fontSizeUnits.has(numeric[2])
  }
  const normalized = normalizeFontSizeCalculation(value)
  return normalized !== null && parseOpacityValue(normalized.value) !== null
}

function normalizeFontSizeCalculation (value) {
  if (!/^(?:calc|min|max|clamp)\(.+\)$/.test(value)) return null
  const units = new Set()
  let invalidUnit = false
  const normalized = value.replace(
    /([+]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)(%|[a-z]+)\b/gi,
    (match, amount, unit) => {
      const normalizedUnit = unit.toLowerCase()
      if (normalizedUnit !== '%' && !fontSizeUnits.has(normalizedUnit)) {
        invalidUnit = true
        return match
      }
      if (Number.parseFloat(amount) !== 0) units.add(normalizedUnit)
      return amount
    }
  )
  if (invalidUnit) return null
  const identifiers = normalized.match(/[a-z][a-z0-9-]*/g) || []
  if (!identifiers.every(identifier => ['calc', 'clamp', 'max', 'min'].includes(identifier))) {
    return null
  }
  return { value: normalized, units }
}

function splitCssShorthandTokens (value) {
  const tokens = []
  let current = ''
  let depth = 0
  let quote = null
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]
    if (quote) {
      current += character
      if (character === '\\' && index + 1 < value.length) {
        current += value[index + 1]
        index += 1
      } else if (character === quote) {
        quote = null
      }
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      current += character
      continue
    }
    if (character === '(') depth += 1
    if (character === ')') depth = Math.max(0, depth - 1)
    if (depth === 0 && (character === '/' || /\s/.test(character))) {
      if (current.trim()) tokens.push(current.trim())
      current = ''
      if (character === '/') tokens.push('/')
    } else {
      current += character
    }
  }
  if (quote || depth !== 0) return null
  if (current.trim()) tokens.push(current.trim())
  return tokens
}

function fontShorthandSize (value) {
  if (/^(?:initial|inherit|unset|revert|revert-layer)$/.test(value)) return value
  if (/^(?:caption|icon|menu|message-box|small-caption|status-bar)$/.test(value)) {
    return 'medium'
  }
  const tokens = splitCssShorthandTokens(value)
  if (!tokens) return null
  for (let index = 0; index < tokens.length; index += 1) {
    if (!isValidFontSize(tokens[index])) continue
    let familyStart = index + 1
    if (tokens[familyStart] === '/') {
      if (!isValidLineHeight(tokens[familyStart + 1])) return null
      familyStart += 2
    }
    return familyStart < tokens.length ? tokens[index] : null
  }
  return null
}

function isValidLineHeight (value) {
  if (!value) return false
  if (value === 'normal') return true
  const numeric = parseOpacityValue(value)
  if (numeric !== null) return numeric >= 0
  if (!isValidTransformLength(value)) return false
  return !/^-/.test(value)
}

function isValidTransformCalculation (value, allowedUnits) {
  if (!/^(?:calc|min|max|clamp)\(.+\)$/.test(value) || !/\d/.test(value)) return false
  const identifiers = value.match(/[a-z][a-z0-9-]*/g) || []
  return identifiers.every(identifier => (
    ['calc', 'clamp', 'max', 'min'].includes(identifier) ||
    allowedUnits.has(identifier)
  ))
}

function isValidTransformNumber (value, allowPercentage = false) {
  if (!allowPercentage && value.includes('%')) return false
  return parseOpacityValue(value) !== null
}

function isValidTransformLength (value, allowPercentage = true) {
  if (!allowPercentage && value.includes('%')) return false
  const numeric = value.match(
    /^([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)(%|[a-z]+)?$/
  )
  if (numeric) {
    if (numeric[2] === '%') return allowPercentage
    if (!numeric[2]) return Number.parseFloat(numeric[1]) === 0
    return fontSizeUnits.has(numeric[2])
  }
  const units = new Set(fontSizeUnits)
  if (allowPercentage) units.add('%')
  return isValidTransformCalculation(value, units)
}

function isValidTransformAngle (value) {
  if (/^[+-]?0(?:\.0+)?(?:e[+-]?\d+)?$/.test(value)) return true
  if (/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?(?:deg|grad|rad|turn)$/.test(value)) {
    return true
  }
  return isValidTransformCalculation(value, new Set(['deg', 'grad', 'rad', 'turn']))
}

function isValidTransformFunction (item) {
  if (!transformFunctions.has(item.name)) return false
  const values = splitCssComponentValues(item.body)
  const allNumbers = expected => (
    values.length === expected && values.every(value => isValidTransformNumber(value))
  )
  if (item.name === 'matrix') return allNumbers(6)
  if (item.name === 'matrix3d') return allNumbers(16)
  if (item.name === 'perspective') {
    return values.length === 1 && isValidTransformLength(values[0], false)
  }
  if (['rotate', 'rotatex', 'rotatey', 'rotatez'].includes(item.name)) {
    return values.length === 1 && isValidTransformAngle(values[0])
  }
  if (item.name === 'rotate3d') {
    return values.length === 4 &&
      values.slice(0, 3).every(value => isValidTransformNumber(value)) &&
      isValidTransformAngle(values[3])
  }
  if (item.name === 'scale') {
    return values.length >= 1 && values.length <= 2 &&
      values.every(value => isValidTransformNumber(value, true))
  }
  if (item.name === 'scale3d') {
    return values.length === 3 &&
      values.every(value => isValidTransformNumber(value, true))
  }
  if (['scalex', 'scaley', 'scalez'].includes(item.name)) {
    return values.length === 1 && isValidTransformNumber(values[0], true)
  }
  if (item.name === 'skew') {
    return values.length >= 1 && values.length <= 2 && values.every(isValidTransformAngle)
  }
  if (['skewx', 'skewy'].includes(item.name)) {
    return values.length === 1 && isValidTransformAngle(values[0])
  }
  if (item.name === 'translate') {
    return values.length >= 1 && values.length <= 2 &&
      values.every(value => isValidTransformLength(value))
  }
  if (item.name === 'translate3d') {
    return values.length === 3 &&
      values.slice(0, 2).every(value => isValidTransformLength(value)) &&
      isValidTransformLength(values[2], false)
  }
  if (['translatex', 'translatey'].includes(item.name)) {
    return values.length === 1 && isValidTransformLength(values[0])
  }
  return values.length === 1 && isValidTransformLength(values[0], false)
}

function isValidFilterFunction (item) {
  if (!filterFunctions.has(item.name)) return false
  const values = splitCssComponentValues(item.body)
  if (item.name === 'url') return item.body.trim().length > 0
  if (item.name === 'blur') {
    return values.length === 1 && isValidTransformLength(values[0], false)
  }
  if (item.name === 'hue-rotate') {
    return values.length === 1 && isValidTransformAngle(values[0])
  }
  if (item.name === 'drop-shadow') {
    const lengths = values.filter(value => !isValidColorValue(value))
    const colors = values.filter(isValidColorValue)
    return colors.length <= 1 && lengths.length >= 2 && lengths.length <= 3 &&
      lengths.every(value => isValidTransformLength(value, false))
  }
  return values.length === 1 && isValidTransformNumber(values[0], true)
}

function isValidFunctionalColor (value) {
  const functional = value.match(
    /^(rgb|rgba|hsl|hsla|hwb|lab|lch|oklab|oklch|color|color-mix|light-dark)\((.+)\)$/
  )
  if (!functional) return false
  if (functional[1] === 'color') {
    const components = splitCssComponentValues(functional[2])
    const colorSpaces = new Set([
      'a98-rgb', 'display-p3', 'prophoto-rgb', 'rec2020', 'srgb', 'srgb-linear',
      'xyz', 'xyz-d50', 'xyz-d65'
    ])
    if (!colorSpaces.has(components[0]) || components.length < 4) return false
    return components.slice(1).every(component => (
      component === '/' || component === 'none' ||
      parseOpacityValue(component) !== null
    ))
  }
  if (functional[1] === 'light-dark') {
    const colors = splitCssFunctionArguments(functional[2])
    return colors.length === 2 && colors.every(isValidColorValue)
  }
  if (functional[1] === 'color-mix') {
    const components = splitCssFunctionArguments(functional[2])
    if (components.length !== 3 || !/^in\s+[a-z0-9-]+(?:\s+(?:shorter|longer|increasing|decreasing)\s+hue)?$/.test(components[0])) {
      return false
    }
    return components.slice(1).every(component => (
      isValidColorValue(component.replace(/\s+[+]?(?:\d+(?:\.\d*)?|\.\d+)%$/, ''))
    ))
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

function isValidColorValue (value) {
  return value === 'transparent' || value === 'currentcolor' ||
    cssNamedColors.has(value) ||
    /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/.test(value) ||
    isValidFunctionalColor(value)
}

function isTransparentColor (value) {
  if (value === 'transparent') return true
  const hexadecimal = value.match(/^#(?:[0-9a-f]{3}([0-9a-f])|[0-9a-f]{6}([0-9a-f]{2}))$/)
  if (hexadecimal) {
    return Number.parseInt(hexadecimal[1] || hexadecimal[2], 16) === 0
  }
  const openingParenthesis = value.indexOf('(')
  if (openingParenthesis < 0 || !value.endsWith(')')) return false
  const body = value.slice(openingParenthesis + 1, -1)
  const functionName = value.slice(0, openingParenthesis)
  if (functionName === 'light-dark') {
    const colors = splitCssFunctionArguments(body)
    return colors.length === 2 && colors.every(isTransparentColor)
  }
  if (functionName === 'color-mix') {
    const components = splitCssFunctionArguments(body)
    return components.length === 3 && components.slice(1).every(component => (
      isTransparentColor(
        component.replace(/\s+[+]?(?:\d+(?:\.\d*)?|\.\d+)%$/, '')
      )
    ))
  }
  let depth = 0
  let slash = -1
  const commas = []
  for (let index = 0; index < body.length; index += 1) {
    if (body[index] === '(') depth += 1
    if (body[index] === ')') depth = Math.max(0, depth - 1)
    if (depth === 0 && body[index] === '/') slash = index
    if (depth === 0 && body[index] === ',') commas.push(index)
  }
  let alphaValue = slash >= 0 ? body.slice(slash + 1).trim() : null
  if (alphaValue === null && commas.length === 3) {
    alphaValue = body.slice(commas[2] + 1).trim()
  }
  if (alphaValue === null) return false
  return (parseOpacityValue(alphaValue) ?? 1) <= 0
}

function classifyFontSize (value) {
  if (/^(?:initial|revert|revert-layer)$/.test(value)) return 'visible'
  if (/^(?:inherit|unset)$/.test(value)) return 'inherit'
  if (/^(?:larger|smaller)$/.test(value)) return 'relative'
  if (/^(?:xx-small|x-small|small|medium|large|x-large|xx-large|xxx-large|math)$/.test(value)) {
    return 'visible'
  }
  const numeric = value.match(
    /^([+]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)(?:([a-z]+)|(%))?$/
  )
  if (numeric) {
    const amount = Number.parseFloat(numeric[1])
    if (amount === 0) return 'zero'
    if (numeric[3] || ['em', 'ex', 'ch', 'cap', 'ic', 'lh'].includes(numeric[2])) {
      return 'relative'
    }
    return 'visible'
  }
  const normalizedCalculation = normalizeFontSizeCalculation(value)
  if (normalizedCalculation === null) return 'inherit'
  if (normalizedCalculation.units.size > 1) {
    return 'inherit'
  }
  const calculated = parseOpacityValue(normalizedCalculation.value)
  if (calculated === null) return 'inherit'
  return calculated === 0 ? 'zero' : 'visible'
}

function hasZeroScaleTransform (value) {
  if (!value || value === 'none') return false
  const functions = parseCssFunctions(value) || []
  for (const item of functions) {
    if (item.name === 'matrix') {
      const values = splitCssComponentValues(item.body).map(parseOpacityValue)
      if (values.length === 6 && values.every(value => value !== null)) {
        if (values[0] * values[3] - values[1] * values[2] === 0) return true
      }
      continue
    }
    if (item.name === 'matrix3d') {
      const values = splitCssComponentValues(item.body).map(parseOpacityValue)
      if (values.length !== 16 || values.some(value => value === null)) continue
      if (values.every(value => value === 0)) return true
      const originW = values[15]
      const xW = values[3] + originW
      const yW = values[7] + originW
      if (originW === 0 || xW === 0 || yW === 0) continue
      const originX = values[12] / originW
      const originY = values[13] / originW
      const xX = (values[0] + values[12]) / xW
      const xY = (values[1] + values[13]) / xW
      const yX = (values[4] + values[12]) / yW
      const yY = (values[5] + values[13]) / yW
      if ((xX - originX) * (yY - originY) -
          (xY - originY) * (yX - originX) === 0) return true
      continue
    }
    if (!['scale', 'scale3d', 'scalex', 'scaley'].includes(item.name)) continue
    const argumentsList = splitCssComponentValues(item.body)
    const values = argumentsList.map(parseOpacityValue)
    if (values.some(item => item === null)) continue
    if (item.name === 'scale') {
      if (values[0] === 0 || values[1] === 0) return true
    } else if (item.name === 'scale3d') {
      if (values[0] === 0 || values[1] === 0) return true
    } else if (values[0] === 0) {
      return true
    }
  }
  return false
}

function hasZeroOpacityFilter (value) {
  if (!value || value === 'none') return false
  const functions = parseCssFunctions(value) || []
  return functions.some(item => (
    item.name === 'opacity' &&
    (parseOpacityValue(item.body.trim()) ?? 1) <= 0
  ))
}

function hasFullyClippingPath (value) {
  const radial = value.match(/^(circle|ellipse)\((.*)\)$/)
  if (radial) {
    const components = splitCssComponentValues(radial[2])
    const positionStart = components.indexOf('at')
    const radii = positionStart >= 0 ? components.slice(0, positionStart) : components
    if (radial[1] === 'circle' && radii.length === 1) {
      return classifyFontSize(radii[0]) === 'zero'
    }
    if (radial[1] === 'ellipse' && radii.length === 2) {
      return radii.some(radius => classifyFontSize(radius) === 'zero')
    }
    return false
  }
  const inset = value.match(/^inset\((.*)\)$/)
  if (!inset) return false
  const offsets = splitCssComponentValues(inset[1].split(/\bround\b/i, 1)[0])
  if (offsets.length < 1 || offsets.length > 4) return false
  const percentages = offsets.map(item => {
    const match = item.match(/^([+-]?(?:\d+(?:\.\d*)?|\.\d+))%$/)
    return match ? Number.parseFloat(match[1]) : null
  })
  if (percentages.some(item => item === null)) return false
  const [top, right = top, bottom = top, left = right] = percentages
  return top + bottom >= 100 || left + right >= 100
}

function parseCssFunctions (value) {
  const functions = []
  let cursor = 0
  while (cursor < value.length) {
    while (/\s/.test(value[cursor] || '')) cursor += 1
    if (cursor >= value.length) break
    const functionStart = value.slice(cursor).match(/^([a-z][a-z0-9-]*)\s*\(/i)
    if (!functionStart) return null
    const openingParenthesis = cursor + functionStart[0].lastIndexOf('(')
    let depth = 1
    let end = openingParenthesis + 1
    for (; end < value.length && depth > 0; end += 1) {
      if (value[end] === '(') depth += 1
      if (value[end] === ')') depth -= 1
    }
    if (depth !== 0) return null
    functions.push({
      name: functionStart[1].toLowerCase(),
      body: value.slice(openingParenthesis + 1, end - 1)
    })
    cursor = end
  }
  return functions.length ? functions : null
}

function splitCssComponentValues (value) {
  const values = []
  let current = ''
  let depth = 0
  for (const character of value) {
    if (character === '(') depth += 1
    if (character === ')') depth = Math.max(0, depth - 1)
    if (depth === 0 && (character === ',' || /\s/.test(character))) {
      if (current.trim()) values.push(current.trim())
      current = ''
    } else {
      current += character
    }
  }
  if (current.trim()) values.push(current.trim())
  return values
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
      outputValue += ' '
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
    let property = decodedProperty.startsWith('--')
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
    if (property === 'font' && !hasCssVariable(value)) {
      const shorthandSize = fontShorthandSize(value)
      if (shorthandSize === null) continue
      property = 'font-size'
      value = shorthandSize
    }
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
  for (const property of ['display', 'visibility', 'content-visibility', 'opacity', 'filter', 'font-size', 'transform', 'clip-path', 'color', 'fill', 'fill-opacity', 'stroke', 'stroke-opacity']) {
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
      parsedAttributes.has('popover') ||
      (tag === 'dialog' && !parsedAttributes.has('open')) ||
      decodeHtmlAttributeEntities(parsedAttributes.get('aria-hidden') || '')
        .toLowerCase() === 'true' ||
      declarations.get('display')?.value === 'none' ||
      declarations.get('content-visibility')?.value === 'hidden' ||
      (parseOpacityValue(declarations.get('opacity')?.value || '') ?? 1) <= 0 ||
      hasZeroOpacityFilter(declarations.get('filter')?.value || '') ||
      hasZeroScaleTransform(declarations.get('transform')?.value || '') ||
      hasFullyClippingPath(declarations.get('clip-path')?.value || '')
    ),
    display: declarations.get('display')?.value || null,
    visibility: declarations.get('visibility')?.value || null,
    opacity: declarations.get('opacity')?.value || null,
    fontSize: declarations.get('font-size')?.value || null,
    color: declarations.get('color')?.value || null,
    fill: declarations.get('fill')?.value || null,
    fillOpacity: declarations.get('fill-opacity')?.value || null,
    stroke: declarations.get('stroke')?.value || null,
    strokeOpacity: declarations.get('stroke-opacity')?.value || null,
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
    entity => unescapeAll(entity)
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
  let effectiveStack = htmlStack
  for (let index = htmlStack.length - 1; index >= 0; index -= 1) {
    if (htmlStack[index].fostered) {
      effectiveStack = htmlStack.slice(index)
      break
    }
  }
  if (effectiveStack.some(entry => entry.irreversible)) {
    return true
  }
  for (const entry of effectiveStack) {
    if (
      entry.closedDetails &&
      !effectiveStack.some(candidate => candidate.summaryOwner === entry)
    ) {
      return true
    }
  }
  let visibilityHidden = false
  for (let index = effectiveStack.length - 1; index >= 0; index -= 1) {
    if (effectiveStack[index].visibility) {
      if (/^(?:inherit|unset|revert|revert-layer)$/.test(effectiveStack[index].visibility)) {
        continue
      }
      visibilityHidden = ['hidden', 'collapse'].includes(effectiveStack[index].visibility)
      break
    }
  }
  if (visibilityHidden) return true
  for (let index = effectiveStack.length - 1; index >= 0; index -= 1) {
    if (!effectiveStack[index].fontSize) continue
    const state = classifyFontSize(effectiveStack[index].fontSize)
    if (state === 'zero') return true
    if (state === 'visible') break
  }
  for (let index = effectiveStack.length - 1; index >= 0; index -= 1) {
    if (effectiveStack[index].color) {
      if (/^(?:inherit|unset|revert|revert-layer|currentcolor)$/.test(effectiveStack[index].color)) {
        continue
      }
      return isTransparentColor(effectiveStack[index].color)
    }
  }
  const activeEntry = effectiveStack[effectiveStack.length - 1]
  if (activeEntry?.svgTextContext) {
    const fillVisible = activeEntry.fill !== 'none' &&
      (parseOpacityValue(activeEntry.fillOpacity) ?? 1) > 0 &&
      !isTransparentColor(activeEntry.fill)
    const strokeVisible = activeEntry.stroke !== 'none' &&
      (parseOpacityValue(activeEntry.strokeOpacity) ?? 1) > 0 &&
      !isTransparentColor(activeEntry.stroke)
    if (!fillVisible && !strokeVisible) return true
  }
  return false
}

function resolveSvgPresentationValue (
  inlineValue,
  presentationValue,
  property,
  inheritedValue,
  initialValue
) {
  let value = inlineValue
  if (value === null && isValidSuppressionDeclaration(property, presentationValue)) {
    value = presentationValue
  }
  if (value === null || /^(?:inherit|unset)$/.test(value)) return inheritedValue
  if (/^(?:initial|revert|revert-layer)$/.test(value)) return initialValue
  return value
}

function isTableFosteredText (content) {
  if (!content.trim() || !htmlStack.length) return false
  return tableContextChildren.has(htmlStack[htmlStack.length - 1].tag)
}

function updateHtmlSuppression (content, inlineContext = false) {
  const tagPattern = /<(?<closing>\/)?(?<tag>[A-Za-z][A-Za-z0-9-]*)\b(?<attributes>(?:[^<>"']|"[^"]*"|'[^']*')*?)(?<selfClosing>\/)?\s*>/g
  const parseableContent = content.replace(/<!--[\s\S]*?(?:-->|$)/g, '')
  let renderedBreak = false
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
          const hasNonFormattingDescendant = htmlStack
            .slice(index + 1)
            .some(entry => !formattingTags.has(entry.tag))
          if (paragraphClosingTags.has(tag) || hasNonFormattingDescendant) {
            htmlStack.splice(index)
          } else {
            htmlStack.splice(index, 1)
          }
          break
        }
      }
      continue
    }
    if (tag === 'style') embeddedStylePresent = true
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
    const fostered = Boolean(
      parent && tableContextChildren.has(parent.tag) &&
      !tableContextChildren.get(parent.tag).has(tag)
    )
    let summaryOwner = null
    if (tag === 'summary' && parent?.closedDetails && !parent.summarySeen) {
      parent.summarySeen = true
      summaryOwner = parent
    }
    const suppression = hasHiddenAttributes(attributes, inheritedCustomProperties, tag)
    if (tag === 'br' && !isHtmlSuppressed() && !suppression.irreversible) {
      renderedBreak = true
    }
    const parentNamespace = parent?.foreignNamespace || null
    const parentIsHtmlIntegration = (
      parentNamespace === 'svg' && svgHtmlIntegrationTags.has(parent.tag)
    ) || (
      parentNamespace === 'math' && (
        parent.annotationHtmlIntegration || (
          mathHtmlIntegrationTags.has(parent.tag) &&
          !mathHtmlIntegrationExceptions.has(tag)
        )
      )
    )
    let foreignNamespace = null
    if (tag === 'svg') foreignNamespace = 'svg'
    else if (tag === 'math') foreignNamespace = 'math'
    else if (parentNamespace && !parentIsHtmlIntegration) {
      foreignNamespace = parentNamespace
    }
    const foreign = foreignNamespace !== null
    const encoding = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('encoding') || ''
    ).trim().toLowerCase()
    const presentationDisplay = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('display') || ''
    ).trim().toLowerCase()
    const presentationVisibility = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('visibility') || ''
    ).trim().toLowerCase()
    const presentationOpacity = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('opacity') || ''
    ).trim().toLowerCase()
    const presentationFill = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('fill') || ''
    ).trim().toLowerCase()
    const presentationFillOpacity = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('fill-opacity') || ''
    ).trim().toLowerCase()
    const presentationStroke = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('stroke') || ''
    ).trim().toLowerCase()
    const presentationStrokeOpacity = decodeHtmlAttributeEntities(
      suppression.parsedAttributes.get('stroke-opacity') || ''
    ).trim().toLowerCase()
    const svgPaintContext = foreignNamespace === 'svg'
    const fill = svgPaintContext
      ? resolveSvgPresentationValue(
          suppression.fill,
          presentationFill,
          'fill',
          parent?.fill ?? 'black',
          'black'
        )
      : null
    const fillOpacity = svgPaintContext
      ? resolveSvgPresentationValue(
          suppression.fillOpacity,
          presentationFillOpacity,
          'fill-opacity',
          parent?.fillOpacity ?? '1',
          '1'
        )
      : null
    const stroke = svgPaintContext
      ? resolveSvgPresentationValue(
          suppression.stroke,
          presentationStroke,
          'stroke',
          parent?.stroke ?? 'none',
          'none'
        )
      : null
    const strokeOpacity = svgPaintContext
      ? resolveSvgPresentationValue(
          suppression.strokeOpacity,
          presentationStrokeOpacity,
          'stroke-opacity',
          parent?.strokeOpacity ?? '1',
          '1'
        )
      : null
    if (!selfClosing || (!voidTags.has(tag) && !foreign)) {
      const entry = {
        tag,
        irreversible: suppressedTags.has(tag) || suppression.irreversible || (
          foreign && (suppression.display ?? presentationDisplay) === 'none'
        ) || (
          foreign &&
          (parseOpacityValue(suppression.opacity ?? presentationOpacity) ?? 1) <= 0
        ),
        closedDetails: tag === 'details' && !suppression.parsedAttributes.has('open'),
        summarySeen: false,
        summaryOwner,
        visibility: suppression.visibility || (
          foreign && /^(?:visible|hidden|collapse)$/.test(presentationVisibility)
            ? presentationVisibility
            : null
        ),
        fontSize: suppression.fontSize,
        color: suppression.color,
        fill,
        fillOpacity,
        stroke,
        strokeOpacity,
        svgTextContext: foreignNamespace === 'svg' && (
          tag === 'text' || parent?.svgTextContext
        ),
        inline: inlineContext,
        foreign,
        foreignNamespace,
        annotationHtmlIntegration: (
          foreignNamespace === 'math' && tag === 'annotation-xml' &&
          ['text/html', 'application/xhtml+xml'].includes(encoding)
        ),
        fostered,
        customProperties: suppression.customProperties
      }
      htmlStack.push(entry)
    }
  }
  return renderedBreak
}

function processHtmlBlock (content) {
  if (/^\s*<(?:!--|!|\?)/.test(content)) {
    return
  }
  const tagPattern = /<!--[\s\S]*?(?:-->|$)|<![^>]*>|<\?[\s\S]*?(?:\?>|$)|<\/?[A-Za-z][A-Za-z0-9-]*\b(?:[^<>"']|"[^"]*"|'[^']*')*?\/?\s*>/g
  let cursor = 0
  for (const match of content.matchAll(tagPattern)) {
    const textContent = content.slice(cursor, match.index)
    if (
      !blockquoteDepth &&
      (!isHtmlSuppressed() || isTableFosteredText(textContent))
    ) {
      output.push(unescapeAll(textContent))
    }
    if (/^<\/?[A-Za-z]/.test(match[0])) {
      if (updateHtmlSuppression(match[0]) && !blockquoteDepth) {
        output.push('\n')
      }
    }
    cursor = match.index + match[0].length
  }
  const trailingContent = content.slice(cursor)
  if (
    !blockquoteDepth &&
    (!isHtmlSuppressed() || isTableFosteredText(trailingContent))
  ) {
    output.push(unescapeAll(trailingContent))
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
      if (updateHtmlSuppression(token.content, true) && !blockquoteDepth && !deletionDepth) {
        output.push('\n')
      }
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

process.stdout.write(embeddedStylePresent ? '' : output.join(''))
