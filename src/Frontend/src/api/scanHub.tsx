import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { HubConnectionBuilder, HubConnectionState, LogLevel, type HubConnection } from '@microsoft/signalr'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { API_BASE_URL } from './client'
import { sessionStore } from './session'
import { ACTIVE_RUN_STATUSES, type ScanExecutionEvent, type ScanRun } from './types'

// Mirrors Contracts/ScanExecutionEvent.cs → ScanHub.
export const SCAN_HUB_PATH = '/hubs/scans'
const EVENT_METHOD = 'scanEvent'
const JOIN_RUN = 'JoinRun'
const LEAVE_RUN = 'LeaveRun'

export type HubStatus = 'connecting' | 'connected' | 'reconnecting' | 'disconnected'
type Listener = (event: ScanExecutionEvent) => void

interface ScanHubContextValue {
  status: HubStatus
  subscribe: (listener: Listener) => () => void
  /** Subscribes to job-level events of one run; returns the matching leave function. */
  joinRun: (runId: string) => () => void
}

const ScanHubContext = createContext<ScanHubContextValue>({
  status: 'disconnected',
  subscribe: () => () => {},
  joinRun: () => () => {},
})

/** Query key prefixes refreshed when an event of the given type arrives. */
export function queryKeysForEvent(event: ScanExecutionEvent): string[] {
  const t = event.type
  if (t.startsWith('Agent')) return ['agents', 'dashboard']
  if (t === 'ChangeDetected') return ['changes', 'dashboard', 'hosts']
  if (t.startsWith('Run') && t !== 'RunCreated' && t !== 'RunStarted')
    return ['scans', 'jobs', 'dashboard', 'hosts', 'services', 'changes', 'findings', 'schedules']
  return ['scans', 'jobs', 'dashboard']
}

/** Batches cache invalidations so a burst of job events triggers one refetch per resource. */
function createInvalidator(qc: QueryClient, delayMs = 400) {
  const pending = new Set<string>()
  let timer: ReturnType<typeof setTimeout> | undefined
  return (event: ScanExecutionEvent) => {
    queryKeysForEvent(event).forEach((k) => pending.add(k))
    timer ??= setTimeout(() => {
      pending.forEach((k) => void qc.invalidateQueries({ queryKey: [k] }))
      pending.clear()
      timer = undefined
    }, delayMs)
  }
}

export function ScanHubProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [status, setStatus] = useState<HubStatus>('connecting')
  const listeners = useRef(new Set<Listener>())
  const joinedRuns = useRef(new Map<string, number>())
  const connectionRef = useRef<HubConnection | null>(null)

  useEffect(() => {
    const connection = new HubConnectionBuilder()
      .withUrl(`${API_BASE_URL}${SCAN_HUB_PATH}`, { accessTokenFactory: () => sessionStore.token() ?? '' })
      .withAutomaticReconnect({ nextRetryDelayInMilliseconds: (ctx) => Math.min(30_000, 1000 * 2 ** ctx.previousRetryCount) })
      .configureLogging(LogLevel.Warning)
      .build()
    connectionRef.current = connection
    const invalidate = createInvalidator(qc)
    const rejoin = () => joinedRuns.current.forEach((_, runId) => void connection.invoke(JOIN_RUN, runId).catch(() => {}))

    connection.on(EVENT_METHOD, (event: ScanExecutionEvent) => {
      listeners.current.forEach((l) => l(event))
      invalidate(event)
    })
    connection.onreconnecting(() => setStatus('reconnecting'))
    connection.onreconnected(() => {
      setStatus('connected')
      rejoin()
      void qc.invalidateQueries({ queryKey: ['scans'] }) // events may have been missed while offline
    })
    connection.onclose(() => setStatus('disconnected'))

    let stopped = false
    let retry: ReturnType<typeof setTimeout> | undefined
    const start = async () => {
      try {
        setStatus('connecting')
        await connection.start()
        if (stopped) return
        setStatus('connected')
        rejoin()
      } catch {
        if (stopped) return
        setStatus('disconnected')
        retry = setTimeout(start, 10_000)
      }
    }
    // Deferred so React StrictMode's mount/unmount/mount in dev does not start (and abort) a throwaway connection.
    retry = setTimeout(start, 0)
    return () => {
      stopped = true
      clearTimeout(retry)
      connectionRef.current = null
      void connection.stop()
    }
  }, [qc])

  const subscribe = useCallback((listener: Listener) => {
    listeners.current.add(listener)
    return () => void listeners.current.delete(listener)
  }, [])

  const joinRun = useCallback((runId: string) => {
    const runs = joinedRuns.current
    const count = runs.get(runId) ?? 0
    runs.set(runId, count + 1)
    const conn = connectionRef.current
    if (count === 0 && conn?.state === HubConnectionState.Connected) void conn.invoke(JOIN_RUN, runId).catch(() => {})
    return () => {
      const left = (runs.get(runId) ?? 1) - 1
      if (left > 0) return void runs.set(runId, left)
      runs.delete(runId)
      const c = connectionRef.current
      if (c?.state === HubConnectionState.Connected) void c.invoke(LEAVE_RUN, runId).catch(() => {})
    }
  }, [])

  const value = useMemo(() => ({ status, subscribe, joinRun }), [status, subscribe, joinRun])
  return <ScanHubContext.Provider value={value}>{children}</ScanHubContext.Provider>
}

export const useScanHubStatus = () => useContext(ScanHubContext).status

/** Calls `listener` for live scan events (only for `runId` when given; also joins that run's group). */
export function useScanEventListener(listener: Listener, runId?: string) {
  const hub = useContext(ScanHubContext)
  const latest = useRef(listener)
  useEffect(() => {
    latest.current = listener
  })
  useEffect(
    () =>
      hub.subscribe((event) => {
        if (!runId || event.scanRunId === runId) latest.current(event)
      }),
    [hub, runId],
  )
  useEffect(() => (runId ? hub.joinRun(runId) : undefined), [hub, runId])
}

/**
 * Joins the hub group of every shown Pending/Running run: the server sends job, step and ResultsReceived events only to
 * `run:{id}` groups. Leaves a run once it is no longer shown or active.
 */
export function useJoinActiveRuns(runs: Pick<ScanRun, 'id' | 'status'>[] | undefined) {
  const { joinRun } = useContext(ScanHubContext)
  const joined = useRef(new Map<string, () => void>())
  const key = [...new Set((runs ?? []).filter((r) => ACTIVE_RUN_STATUSES.includes(r.status)).map((r) => r.id))].sort().join(',')
  useEffect(() => {
    const map = joined.current
    const wanted = new Set(key ? key.split(',') : [])
    map.forEach((leave, id) => {
      if (wanted.has(id)) return
      leave()
      map.delete(id)
    })
    wanted.forEach((id) => {
      if (!map.has(id)) map.set(id, joinRun(id))
    })
  }, [joinRun, key])
  useEffect(() => {
    const map = joined.current
    return () => {
      map.forEach((leave) => leave())
      map.clear()
    }
  }, [])
}
