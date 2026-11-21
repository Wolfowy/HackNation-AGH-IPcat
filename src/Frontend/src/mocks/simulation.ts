// Drives mock scan runs forward (steps → jobs → completion) and pushes ScanExecutionEvents over the mock hub.
import type { ScanExecutionEvent, ScanProgress, ScanRun } from '@/api/types'
import { randomGuid, type MockDb, type MockRun } from './data'
import { broadcastScanEvent } from './hub'

let enabled = false
const timers = new Map<string, ReturnType<typeof setInterval>>()

const TERMINAL_STEP = new Set(['Completed', 'Skipped', 'Failed', 'Cancelled'])
const AGENTS = [
  { agentId: 'scanner-dmz-01', interfaceName: 'eth0' },
  { agentId: 'scanner-office-01', interfaceName: 'ens18' },
]
const TOOL_BY_OPERATION: Record<string, string> = {
  DiscoverHosts: 'nmap',
  ScanPorts: 'naabu',
  DetectService: 'nmap',
  HttpProbe: 'httpx',
  TlsProbe: 'httpx',
  ExecuteSignatures: 'nuclei',
}

export function progressOf(db: MockDb, run: ScanRun): ScanProgress {
  const jobs = db.jobs.filter((j) => j.scanRunId === run.id)
  const count = (status: string) => jobs.filter((j) => j.status === status).length
  const completed = count('Completed')
  const failed = count('Failed')
  const finished = completed + failed + count('Cancelled')
  const terminal = !['Pending', 'Running'].includes(run.status)
  return {
    jobsTotal: jobs.length,
    jobsQueued: count('Queued'),
    jobsRunning: count('Leased'),
    jobsCompleted: completed,
    jobsFailed: failed,
    percent: jobs.length ? Math.round((finished / jobs.length) * 1000) / 10 : terminal ? 100 : 0,
  }
}

export function emit(db: MockDb, event: Omit<ScanExecutionEvent, 'eventId' | 'occurredAt'>) {
  const full: ScanExecutionEvent = { eventId: randomGuid(), occurredAt: new Date().toISOString(), ...event }
  db.events.push(full)
  if (enabled) broadcastScanEvent(full)
}

function tick(db: MockDb, run: MockRun) {
  const now = new Date().toISOString()
  const definition = db.workflows.find((w) => w.key === run.workflowKey && w.version === run.workflowVersion)?.definition
  const deps = (stepId: string) => definition?.steps.find((s) => s.id === stepId)?.dependsOn ?? []
  const stepStatus = (stepId: string) => run.steps.find((s) => s.stepId === stepId)?.status

  if (run.status === 'Pending') {
    run.status = 'Running'
    run.startedAt = now
    emit(db, { type: 'RunStarted', scanRunId: run.id })
  }

  for (const step of run.steps) {
    if (step.status === 'Pending' && deps(step.stepId).every((d) => ['Completed', 'Skipped'].includes(stepStatus(d) ?? ''))) {
      step.status = 'Running'
      step.startedAt = now
      emit(db, { type: 'StepStarted', scanRunId: run.id, stepId: step.stepId })
      continue
    }
    if (step.status !== 'Running') continue
    const jobs = db.jobs.filter((j) => j.scanRunId === run.id && j.stepId === step.stepId)
    for (const job of jobs.filter((j) => j.status === 'Leased')) {
      job.status = 'Completed'
      job.finishedAt = now
      job.durationMs = Date.now() - Date.parse(job.startedAt ?? now) + Math.round(Math.random() * 20_000)
      job.progressPercent = 100
      step.jobsCompleted += 1
      emit(db, {
        type: 'JobCompleted',
        scanRunId: run.id,
        stepId: step.stepId,
        jobId: job.id,
        agentId: job.agentId,
        progress: progressOf(db, run).percent,
        message: `${job.targetCount} targets`,
      })
    }
    jobs
      .filter((j) => j.status === 'Queued')
      .slice(0, 2)
      .forEach((job, i) => {
        const agent = AGENTS[i % AGENTS.length]
        Object.assign(job, { status: 'Leased', ...agent, toolId: TOOL_BY_OPERATION[job.operation] ?? 'nmap', startedAt: now, progressPercent: 0 })
        emit(db, { type: 'JobAssigned', scanRunId: run.id, stepId: step.stepId, jobId: job.id, agentId: agent.agentId })
      })
    if (jobs.every((j) => j.status === 'Completed')) {
      step.status = 'Completed'
      step.finishedAt = now
      emit(db, { type: 'StepCompleted', scanRunId: run.id, stepId: step.stepId })
    }
  }

  if (run.steps.every((s) => TERMINAL_STEP.has(s.status))) {
    run.status = 'Completed'
    run.finishedAt = now
    run.coverageComplete = true
    const host = db.hosts[Math.floor(Math.random() * db.hosts.length)]
    db.changes.unshift({
      id: randomGuid(),
      detectedAt: now,
      scanRunId: run.id,
      type: 'NewPort',
      hostId: host.id,
      zone: host.zone,
      address: host.address,
      port: 8443,
      summary: 'New open port 8443/tcp',
      severity: 'medium',
    })
    emit(db, { type: 'ChangeDetected', scanRunId: run.id, message: `New open port 8443/tcp on ${host.address}` })
    emit(db, { type: 'RunCompleted', scanRunId: run.id, progress: 100 })
    stopRunSimulation(run.id)
  }
}

export function startRunSimulation(db: MockDb, run: MockRun, tickMs = 800) {
  if (!enabled || timers.has(run.id)) return
  timers.set(
    run.id,
    setInterval(() => tick(db, run), tickMs),
  )
}

export function stopRunSimulation(runId: string) {
  clearInterval(timers.get(runId))
  timers.delete(runId)
}

export function stopAllSimulations() {
  timers.forEach((t) => clearInterval(t))
  timers.clear()
}

/** Browser mock mode only: unit tests keep runs static. */
export function enableSimulation(db: MockDb) {
  enabled = true
  db.runs.filter((r) => r.status === 'Running' || r.status === 'Pending').forEach((r) => startRunSimulation(db, r, 1500))
}
