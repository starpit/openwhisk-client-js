'use strict'

const BaseOperation = require('./base_operation')

class Namespaces extends BaseOperation {
  list (options) {
    return this.client.request('GET', `namespaces`, options)
  }

  get (options) {
    if (typeof options === 'string') {
      return this.client.request('GET', `namespaces/${options}`)
    }

    options = options || {}
    const id = options.name || options.namespace 

    if (!id) {
      throw new Error('Missing mandatory parameter: id or namespace.')
    }

    return this.client.request('GET', `namespaces/${id}`)
  }
}

module.exports = Namespaces
