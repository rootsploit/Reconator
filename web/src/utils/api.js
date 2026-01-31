// API utility for making requests to the Reconator backend

const API_BASE = '/api/v1'

// Token management
const getAccessToken = () => localStorage.getItem('reconator_access_token') || ''
const getRefreshToken = () => localStorage.getItem('reconator_refresh_token') || ''
const getApiKey = () => localStorage.getItem('reconator_api_key') || ''

const setTokens = (accessToken, refreshToken, expiresAt) => {
  if (accessToken) localStorage.setItem('reconator_access_token', accessToken)
  if (refreshToken) localStorage.setItem('reconator_refresh_token', refreshToken)
  if (expiresAt) localStorage.setItem('reconator_token_expires', expiresAt)
}

const clearTokens = () => {
  localStorage.removeItem('reconator_access_token')
  localStorage.removeItem('reconator_refresh_token')
  localStorage.removeItem('reconator_token_expires')
}

// Get auth headers (JWT or API key)
const getAuthHeaders = () => {
  const token = getAccessToken()
  const apiKey = getApiKey()

  const headers = {
    'Content-Type': 'application/json',
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  } else if (apiKey) {
    headers['X-API-Key'] = apiKey
  }

  return headers
}

// Refresh access token if needed
const refreshAccessToken = async () => {
  const refreshToken = getRefreshToken()
  if (!refreshToken) return false

  try {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })

    if (!response.ok) return false

    const data = await response.json()
    setTokens(data.access_token, data.refresh_token, data.expires_at)
    return true
  } catch {
    return false
  }
}

export const api = {
  async get(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: getAuthHeaders(),
    })

    // Try to refresh token if unauthorized
    if (response.status === 401) {
      const refreshed = await refreshAccessToken()
      if (refreshed) {
        // Retry with new token
        const retryResponse = await fetch(`${API_BASE}${endpoint}`, {
          headers: getAuthHeaders(),
        })
        if (retryResponse.ok) {
          return retryResponse.json()
        }
      }
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }))
      throw new Error(error.error || 'Request failed')
    }
    return response.json()
  },

  async post(endpoint, data) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    })

    // Try to refresh token if unauthorized
    if (response.status === 401 && !endpoint.includes('/auth/')) {
      const refreshed = await refreshAccessToken()
      if (refreshed) {
        const retryResponse = await fetch(`${API_BASE}${endpoint}`, {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify(data),
        })
        if (retryResponse.ok) {
          return retryResponse.json()
        }
      }
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }))
      throw new Error(error.error || 'Request failed')
    }
    return response.json()
  },

  async delete(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    })

    // Try to refresh token if unauthorized
    if (response.status === 401) {
      const refreshed = await refreshAccessToken()
      if (refreshed) {
        const retryResponse = await fetch(`${API_BASE}${endpoint}`, {
          method: 'DELETE',
          headers: getAuthHeaders(),
        })
        if (retryResponse.ok) {
          return retryResponse.json()
        }
      }
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }))
      throw new Error(error.error || 'Request failed')
    }
    return response.json()
  },

  async download(endpoint, filename) {
    const headers = { ...getAuthHeaders() }
    delete headers['Content-Type'] // Remove for downloads

    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers,
    })
    if (!response.ok) {
      throw new Error('Download failed')
    }
    const blob = await response.blob()
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
  },

  // Login with username and password (returns JWT)
  async login(username, password) {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Login failed' }))
      throw new Error(error.error || 'Login failed')
    }

    const data = await response.json()
    setTokens(data.access_token, data.refresh_token, data.expires_at)
    return data
  },

  // Logout (clear tokens)
  async logout() {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: getAuthHeaders(),
      })
    } catch {
      // Ignore errors
    }
    clearTokens()
    this.setApiKey(null)
  },

  // Legacy API key support
  setApiKey(key) {
    if (key) {
      localStorage.setItem('reconator_api_key', key)
    } else {
      localStorage.removeItem('reconator_api_key')
    }
  },

  // Check if authenticated
  isAuthenticated() {
    return !!(getAccessToken() || getApiKey())
  },
}
