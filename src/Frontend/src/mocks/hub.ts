// Minimal SignalR server (JSON hub protocol over WebSocket) for /hubs/scans, so the real
// @microsoft/signalr client runs unchanged against the mocks.
import { http, HttpResponse, ws } from 'msw'
import type { ScanExecutionEvent } from '@/api/types'

const RS = '\u001e' // SignalR record separator
const MessageType = { Invocation: 1, Completion: 3, Ping: 6, Close: 7 } as const

const hub = ws.link('*/hubs/scans')
/** Connected clients → joined run ids (`run:{id}` groups). */
const clients = new Map<{ send: (data: string) => void }, Set<string>>()

const frame = (message: object) => JSON.stringify(message) + RS

/**
 * Pushes a scan event (`scanEvent` client method) like ScanEventPublisher: run-level `Run*` events and events without
 * a run go to every client, all other run events only to clients that invoked `JoinRun(runId)`.
 */
export function broadcastScanEvent(event: ScanExecutionEvent) {
  const data = frame({ type: MessageType.Invocation, target: 'scanEvent', arguments: [event] })
  const toAll = !event.scanRunId || event.type.startsWith('Run')
  clients.forEach((runs, c) => {
    if (toAll || runs.has(event.scanRunId!)) c.send(data)
  })
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
        const message = JSON.parse(raw) as { type?: number; protocol?: string; invocationId?: string; target?: string; arguments?: unknown[] }
        if (!handshakeDone) {
          handshakeDone = true
          client.send('{}' + RS) // handshake response
          clients.set(client, new Set())
          continue
        }
        if (message.type !== MessageType.Invocation) continue
        const runId = String(message.arguments?.[0] ?? '')
        if (message.target === 'JoinRun') clients.get(client)?.add(runId)
        if (message.target === 'LeaveRun') clients.get(client)?.delete(runId)
        if (message.invocationId) client.send(frame({ type: MessageType.Completion, invocationId: message.invocationId, result: null }))
      }
    })
  }),
]
