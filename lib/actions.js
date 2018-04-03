'use strict'

const messages = require('./messages')
const Resources = require('./resources')

class Actions extends Resources {
  constructor (client) {
    super(client)
    this.resource = 'actions'
    this.identifiers.push('actionName')
    this.qs_options.invoke = ['blocking']
  }

  list (options) {
    options = options || {}
    options.qs = this.qs(options, ['skip', 'limit', 'count'])

    return super.list(options)
  }

  invoke (options) {
    options = options || {}
    if (options.blocking && options.result) {
      return super.invoke(options).then(result => result.response.result)
    }

    return super.invoke(options)
  }

  create (options) {
    options.qs = this.qs(options, ['overwrite'])
    options.body = this.action_body(options)

    return super.create(options)
  }

  action_body (options) {
    if (!options.hasOwnProperty('action')) {
      throw new Error(messages.MISSING_ACTION_BODY_ERROR)
    }
    const body = { exec: { kind: options.kind || 'nodejs:default', code: options.action } }

    if (options.action instanceof Buffer) {
      body.exec.code = options.action.toString('base64')
    } else if (typeof options.action === 'object') {
      return options.action
    }

    if (typeof options.params === 'object') {
      body.parameters = Object.keys(options.params).map(key => ({ key, value: options.params[key] }))
    }

    return body
  }
}

module.exports = Actions
