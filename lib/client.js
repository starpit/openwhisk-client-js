// Licensed to the Apache Software Foundation (ASF) under one or more contributor
// license agreements; and to You under the Apache License, Version 2.0.

'use strict'

const messages = require('./messages')
const OpenWhiskError = require('./openwhisk_error')
const needle = require('needle')
const withRetry = require('promise-retry')
const url = require('url')
const http = require('http')

/**
 * This implements a request-promise-like facade over the needle
 * library. There are two gaps between needle and rp that need to be
 * bridged: 1) convert `qs` into a query string; and 2) convert
 * needle's non-excepting >=400 statusCode responses into exceptions
 *
 */
const rp = opts => {
  if (opts.qs) {
    // we turn the qs struct into a query string over the url
    let first = true
    for (let key in opts.qs) {
      const str = `${encodeURIComponent(key)}=${encodeURIComponent(opts.qs[key])}`
      if (first) {
        opts.url += `?${str}`
        first = false
      } else {
        opts.url += `&${str}`
      }
    }
  }

  // it appears that certain call paths from our code do not set the
  // opts.json field to true; rp is apparently more resilient to
  // this situation than needle
  opts.json = true

  return needle(opts.method.toLowerCase(), // needle takes e.g. 'put' not 'PUT'
    opts.url,
    opts.body || opts.params,
    opts)
    .then(resp => {
      if (resp.statusCode >= 400) {
        // we turn >=400 statusCode responses into exceptions
        const error = new Error(resp.body.error || resp.statusMessage)
        error.statusCode = resp.statusCode // the http status code
        error.options = opts // the code below requires access to the input opts
        error.error = resp.body // the error body
        throw error
      } else {
        // otherwise, the response body is the expected return value
        return resp.body
      }
    })
}

class Client {
  /**
   * @constructor
   * @param {Object} options - options of the Client
   * @param {string} [options.api]
   * @param {string} [options.api_key]
   * @param {string} [options.apihost]
   * @param {string} [options.namespace]
   * @param {boolean} [options.ignore_certs]
   * @param {string} [options.apigw_token]
   * @param {string} [options.apigw_space_guid]
   */
  constructor (options) {
    this.options = this.parseOptions(options || {})
  }

  parseOptions (options) {
    const apiKey = options.api_key || process.env['__OW_API_KEY']
    const ignoreCerts = options.ignore_certs ||
      (process.env['__OW_IGNORE_CERTS']
        ? process.env['__OW_IGNORE_CERTS'].toLowerCase() === 'true'
        : false)

    // if apihost is available, parse this into full API url
    const api = options.api ||
      this.urlFromApihost(options.apihost || process.env['__OW_API_HOST'])

    // optional tokens for API GW service
    const apigwToken = options.apigw_token || process.env['__OW_APIGW_TOKEN']
    let apigwSpaceGuid = options.apigw_space_guid || process.env['__OW_APIGW_SPACE_GUID']

    // unless space is explicitly passed, default to using auth uuid.
    if (apigwToken && !apigwSpaceGuid) {
      apigwSpaceGuid = apiKey.split(':')[0]
    }

    if (!apiKey) {
      throw new Error(`${messages.INVALID_OPTIONS_ERROR} Missing api_key parameter.`)
    } else if (!api) {
      throw new Error(`${messages.INVALID_OPTIONS_ERROR} Missing either api or apihost parameters.`)
    }

    return {apiKey: apiKey, api, ignoreCerts: ignoreCerts, namespace: options.namespace, apigwToken: apigwToken, apigwSpaceGuid: apigwSpaceGuid}
  }

  urlFromApihost (apihost) {
    if (!apihost) return apihost
    let url = `${apihost}/api/v1/`

    // if apihost does not the protocol, assume HTTPS
    if (!url.match(/http(s)?:\/\//)) {
      url = `https://${url}`
    }

    return url
  }

  /** extract a possible statusCode from an openwhisk "application error" 502 response */
  openwhiskCode (err) {
    const body = err.error &&
            err.error.response && err.error.response.result &&
            err.error.response.result.error

    return body && (body.code || body.statusCode)
  }

  /** don't retry on certain error codes */
  noRetry (statusCode) {
    return !statusCode || statusCode === 400 || statusCode === 401 ||
          statusCode === 404 || statusCode === 409 || statusCode === 410 || statusCode === 500
  }

  request (method, path, options) {
    const req = this.params(method, path, options)

    if (options && options.timeout) {
      // client asked us to retry in the case of failures
      const retryCount = options.retryCount || 10

      req.timeout = options.timeout
      req.open_timeout = options.timeout
      req.agent = options.agent

      return withRetry((retry, iter) => {
        return rp(req).catch(err => {
          // the error code; this isn't the http status code, it's
          // the error code coming from the underlying nodejs
          // socket layer
          const code = err && (err.code || (err.error && err.error.code))

          // was this error related to the inability to connect to OpenWhisk?
          const isConnectionRelated = code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT' || code === 'ECONNRESET'

          const isNormalError = err && (this.noRetry(err.statusCode) ||
                                            (err.statusCode === 502 && this.noRetry(this.openwhiskCode(err)))) // openwhisk "activation error"

          const needsRetry = !!(isConnectionRelated || !isNormalError)

          if (needsRetry && iter < retryCount &&
              (method === 'GET' || method === 'PUT')) {
            console.error('Retrying on ' + method + ' ' + path)
            retry()
          } else {
            this.handleErrors(err)
          }
        })
      })
    }

    return rp(req).catch(err => this.handleErrors(err))
  }

  params (method, path, options) {
    return Object.assign({
      json: true,
      method: method,
      url: this.pathUrl(path),
      rejectUnauthorized: !this.options.ignoreCerts,
      headers: {
        'User-Agent': (options && options['User-Agent']) || 'openwhisk-client-js',
        Authorization: this.authHeader()
      }
    }, options)
  }

  pathUrl (urlPath) {
    const endpoint = this.apiUrl()
    endpoint.pathname = url.resolve(endpoint.pathname, urlPath)
    return url.format(endpoint)
  }

  apiUrl () {
    return url.parse(
      this.options.api.endsWith('/') ? this.options.api : this.options.api + '/'
    )
  }

  authHeader () {
    const apiKeyBase64 = Buffer.from(this.options.apiKey).toString('base64')
    return `Basic ${apiKeyBase64}`
  }

  handleErrors (reason) {
    let message = `Unknown Error From API: ${reason.message}`
    if (reason.hasOwnProperty('statusCode')) {
      const responseError = this.errMessage(reason.error)
      message = `${reason.options.method} ${reason.options.url} Returned HTTP ${reason.statusCode} (${http.STATUS_CODES[reason.statusCode]}) --> "${responseError}"`
    }

    throw new OpenWhiskError(message, reason.error, reason.statusCode)
  }

  // Error messages might be returned from platform or using custom
  // invocation result response from action.
  errMessage (error) {
    if (!error) return 'Response Missing Error Message.'

    if (typeof error.error === 'string') {
      return error.error
    } else if (error.response && error.response.result) {
      const result = error.response.result
      if (result.error) {
        if (typeof result.error === 'string') {
          return result.error
        } else if (typeof result.error.error === 'string') {
          return result.error.error
        } else if (result.error.statusCode) {
          return `application error, status code: ${result.error.statusCode}`
        }
      }
    }

    return 'Response Missing Error Message.'
  }
}

module.exports = Client
