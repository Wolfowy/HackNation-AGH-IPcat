// Minimal SignalR server (JSON hub protocol over WebSocket) for /hubs/scans, so the real
// @microsoft/signalr client runs unchanged against the mocks.
import { http, HttpResponse, ws } from 'msw'
import type { ScanExecutionEvent } from '@/api/types'

const RS = '\u001e' // SignalR record separator
const MessageType = { Invocation: 1, Completion: 3, Ping: 6, Close: 7 } as const

const hub = ws.link('*/hubs/scans')
const clients = new Set<{ send: (data: string) => void }>()

const frame = (message: object) => JSON.stringify(message) + RS

/** Pushes a scan event to every connected client (`scanEvent` client method). */
export function broadcastScanEvent(event: ScanExecutionEvent) {
  const data = frame({ type: MessageType.Invocation, target: 'scanEvent', arguments: [event] })
  clients.forEach((c) => c.send(data))
}

export const hubHandlers = [
  http.post('*/hubs/scans/negotiate', () => {
    const connectionToken = crypto.randomUUID()
    return HttpResponse.json({
      negotiateVersion: 1,
      connectionId: crypto.randomUUID(),
      connectionToken,
      availableTransports: [{ transport: 'WebSockets', transferFormats: ['Text', 'Binary'] }],
    })
  }),
  hub.addEventListener('connection', ({ client }) => {
    let handshakeDone = false
    const ping = setInterval(() => client.send(frame({ type: MessageType.Ping })), 10_000)
    client.addEventListener('close', () => {
      clearInterval(ping)
      clients.delete(client)
    })
    client.addEventListener('message', (event) => {
      if (typeof event.data !== 'string') return
      for (const raw of event.data.split(RS).filter(Boolean)) {
        const message = JSON.parse(raw) as { type?: number; protocol?: string; invocationId?: string; target?: string }
        if (!handshakeDone) {
          handshakeDone = true
          client.send('{}' + RS) // handshake response
          clients.add(client)
          continue
        }
        if (message.type === MessageType.Invocation && message.invocationId) {
          // JoinRun / LeaveRun: every client already receives all events in the mock.
          client.send(frame({ type: MessageType.Completion, invocationId: message.invocationId, result: null }))
        }
      }
    })
  }),
]
