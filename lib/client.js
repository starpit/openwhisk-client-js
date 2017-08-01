'use strict'

const messages = require('./messages')
const OpenWhiskError = require('./openwhisk_error')
const rp = require('request-promise')
const withRetry = require('promise-retry')
const url = require('url')
const http = require('http')

class Client {
  constructor (options) {
    this.options = this.parse_options(options || {})
  }

  parse_options (options) {
    const api_key = options.api_key || process.env['__OW_API_KEY']
    const ignore_certs = options.ignore_certs || false
    // if apihost is available, parse this into full API url
    const api = options.api ||
      this.url_from_apihost(options.apihost || process.env['__OW_API_HOST'])

    // optional tokens for API GW service
    const apigw_token = options.apigw_token || process.env['__OW_APIGW_TOKEN']
    let apigw_space_guid = options.apigw_space_guid || process.env['__OW_APIGW_SPACE_GUID']

    // unless space is explicitly passed, default to using auth uuid.
    if (apigw_token && !apigw_space_guid) {
      apigw_space_guid = api_key.split(':')[0]
    }

    if (!api_key) {
      throw new Error(`${messages.INVALID_OPTIONS_ERROR} Missing api_key parameter.`)
    } else if (!api) {
      throw new Error(`${messages.INVALID_OPTIONS_ERROR} Missing either api or apihost parameters.`)
    }

    return {api_key, api, ignore_certs, namespace: options.namespace, apigw_token, apigw_space_guid}
  }

  url_from_apihost (apihost) {
    if (!apihost) return apihost
    let url = `${apihost}/api/v1/`

    // if apihost does not the protocol, assume HTTPS
    if (!url.match(/http(s)?:\/\//)) {
      url = `https://${url}`
    }

    return url
  }

  request (method, path, options) {
    const req = this.params(method, path, options)

      if (options && options.timeout) {
        console.log(`Using timeout=${options.timeout} and retryCount=${options.retryCount}`)
        req.timeout = options.timeout
        return withRetry((retry, iter) => {
            return rp(req).catch(err => {
                const isNormalError = err && (err.statusCode === 400 || err.statusCode === 404 || err.statusCode === 409)
		console.error(err.statusCode)
		console.error(err)
		console.error(err.stack)
                if (!isNormalError && (iter < (req.retryCount || 10))) {
                    retry()
                } else {
                    this.handle_errors(err)
                }
            })
        })
    } else {
        return rp(req).catch(err => this.handle_errors(err))
    }
  }

  params (method, path, options) {
    return Object.assign({
      json: true,
      method: method,
      url: this.path_url(path),
      rejectUnauthorized: !this.options.ignore_certs,
      headers: {
        Authorization: this.auth_header()
      }
    }, options)
  }

  path_url (url_path) {
    const endpoint = this.api_url()
    endpoint.pathname = url.resolve(endpoint.pathname, url_path)
    return url.format(endpoint)
  }

  api_url () {
    return url.parse(
      this.options.api.endsWith('/') ? this.options.api : this.options.api + '/'
    )
  }

  auth_header () {
    const api_key_base64 = Buffer.from(this.options.api_key).toString('base64')
    return `Basic ${api_key_base64}`
  }

  handle_errors (reason) {
    let message = `Unknown Error From API: ${reason.message}`
    if (reason.hasOwnProperty('statusCode')) {
      const responseError = this.err_message(reason.error)
      message = `${reason.options.method} ${reason.options.url} Returned HTTP ${reason.statusCode} (${http.STATUS_CODES[reason.statusCode]}) --> "${responseError}"`
    }

    throw new OpenWhiskError(message, reason.error, reason.statusCode)
  }

  // Error messages might be returned from platform or using custom
  // invocation result response from action.
  err_message (error) {
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
