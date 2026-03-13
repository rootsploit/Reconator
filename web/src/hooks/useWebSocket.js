import { useState, useEffect, useRef, useCallback } from 'react'

export function useWebSocket(scanId = null) {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState(null)
  const wsRef = useRef(null)
  const reconnectTimeoutRef = useRef(null)

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    let url = `${protocol}//${host}/ws`
    if (scanId) {
      url += `?scan_id=${scanId}`
    }

    try {
      wsRef.current = new WebSocket(url)

      wsRef.current.onopen = () => {
        console.log('[WebSocket] Connected')
        setIsConnected(true)
      }

      wsRef.current.onclose = () => {
        console.log('[WebSocket] Disconnected')
        setIsConnected(false)
        // Reconnect after 3 seconds
        reconnectTimeoutRef.current = setTimeout(connect, 3000)
      }

      wsRef.current.onerror = (error) => {
        console.error('[WebSocket] Error:', error)
      }

      wsRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setLastMessage(data)
        } catch (e) {
          console.error('[WebSocket] Parse error:', e)
        }
      }
    } catch (error) {
      console.error('[WebSocket] Connection error:', error)
      reconnectTimeoutRef.current = setTimeout(connect, 3000)
    }
  }, [scanId])

  useEffect(() => {
    connect()

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [connect])

  const sendMessage = useCallback((message) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message))
    }
  }, [])

  const subscribe = useCallback((newScanId) => {
    sendMessage({ type: 'subscribe', scan_id: newScanId })
  }, [sendMessage])

  return { isConnected, lastMessage, sendMessage, subscribe }
}
