// Test double for @microsoft/signalr: lets tests push hub messages (`fakeHub.emit('scanEvent', evt)`).
type Handler = (...args: unknown[]) => void

class FakeHubConnection {
  state = 'Disconnected'
  readonly handlers = new Map<string, Handler[]>()

  on(method: string, handler: Handler) {
    this.handlers.set(method, [...(this.handlers.get(method) ?? []), handler])
  }
  onreconnecting() {}
  onreconnected() {}
  onclose() {}
  async start() {
    this.state = 'Connected'
    fakeHub.connections.add(this)
  }
  async stop() {
    this.state = 'Disconnected'
    fakeHub.connections.delete(this)
  }
  async invoke(method: string, ...args: unknown[]) {
    fakeHub.invocations.push({ method, args })
  }
}

export const fakeHub = {
  connections: new Set<FakeHubConnection>(),
  invocations: [] as { method: string; args: unknown[] }[],
  emit(method: string, ...args: unknown[]) {
    this.connections.forEach((c) => c.handlers.get(method)?.forEach((h) => h(...args)))
  },
  reset() {
    this.connections.clear()
    this.invocations = []
  },
}

export class HubConnectionBuilder {
  withUrl() {
    return this
  }
  withAutomaticReconnect() {
    return this
  }
  configureLogging() {
    return this
  }
  build() {
    return new FakeHubConnection()
  }
}

export const HubConnectionState = { Connected: 'Connected', Disconnected: 'Disconnected' }
export const LogLevel = { Warning: 3 }
