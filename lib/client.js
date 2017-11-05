'use strict'

const messages = require('./messages')
const OpenWhiskError = require('./openwhisk_error')
const needle = require('needle')
const withRetry = require('promise-retry')
const url = require('url')
const http = require('http')

const rp = opts => {
    opts.json = true

    if (opts.qs) {
        // needle isn't as fancy as request, here. we need to turn qs into a query string                                                    
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

	opts.qs = {}
    }

    return needle(opts.method.toLowerCase(), // needle takes e.g. 'put' not 'PUT'
                  opts.url,
                  opts.body || opts.params,
                  opts)
    .then(resp => {
            if (resp.statusCode >= 400) {
                const error = new Error(resp.body.error || resp.statusMessage)
                error.statusCode = resp.statusCode
                error.options = opts
                error.error = resp.body
                throw error
            } else {
                return resp.body
            }
        })
}

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

  /** extract a possible statusCode from an openwhisk "application error" 502 response */
  openwhiskCode (err) {
      const body = err.error
            && err.error.response && err.error.response.result
            && err.error.response.result.error

      return body && (body.code || body.statusCode)
  }
    
  /** don't retry on certain error codes */
  noRetry (statusCode) {
    return !statusCode || statusCode === 400 || statusCode === 401 || statusCode === 404 || statusCode === 409 || statusCode === 410 || statusCode === 500
  }

  request (method, path, options) {
    const req = this.params(method, path, options)

      if (options && options.timeout || options && options.useRetry) {
	  const retryCount = options.retryCount || 10
          // console.log(`Using timeout=${options.timeout} and retryCount=${retryCount}`)
        if (options.timeout) {
            req.timeout = options.timeout
            req.open_timeout = options.timeout
            //req.read_timeout = options.timeout
        }
        if (options.agent) {
            req.agent = options.agent
        }
        return withRetry((retry, iter) => {
            return rp(req).catch(err => {
                const code = err && err.code || (err.error && err.error.code)
		const is_ETIMEOUT = code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT' || code === 'ECONNRESET'
                const isNormalError = err && (this.noRetry(err.statusCode)
                                              || (err.statusCode === 502 && this.noRetry(this.openwhiskCode(err)))) // openwhisk "activation error"
		const needsRetry = !! (is_ETIMEOUT || !isNormalError)

                if (needsRetry) {
		    console.error('ETIMEOUT?=' + !!is_ETIMEOUT + ' isNormal=' + !!isNormalError + ' retryIter=' + iter)
		    console.error('statusCode=' + err.statusCode)
		    console.error('code=' + code)
		    console.error('message=' + err.message)
		    console.error(JSON.stringify(err.error))
		    console.error(err.cause)
                }
                if (needsRetry && iter < retryCount) {
		    console.error('Retrying')
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
        'User-Agent': options && options['User-Agent'] || 'openwhisk-client-js',
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
