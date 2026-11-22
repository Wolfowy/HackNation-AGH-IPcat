import type { ReactNode } from 'react'
import { Link, useParams } from 'react-router'
import { useService } from '@/api/assets'
import type { HttpCookie, HttpDetails, ServiceArtifact, ServiceDetail } from '@/api/types'
import { EndpointLink } from '@/components/EndpointLink'
import { EmptyState, Loadable } from '@/components/feedback'
import { KeyValues, PageHeader } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDateTime, zoneLabel } from '@/lib/format'
import { FindingsTable } from '../findings/FindingsTable'
import { ConfidenceBar } from './ConfidenceBar'

/** Artifact tags that deserve attention (amber); the rest are hints. */
const WARN_TAGS = new Set(['debug', 'internal-ip-leak', 'insecure-cookie', 'permissive-cors', 'version-leak'])

export function ArtifactTags({ tags }: { tags?: string[] }) {
  if (!tags?.length) return <span className="text-muted-foreground">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map((tag) => (
        <Badge key={tag} variant={WARN_TAGS.has(tag) ? 'warning' : 'outline'} data-testid="artifact-tag">
          {tag}
        </Badge>
      ))}
    </div>
  )
}

function Section({ title, children, testId }: { title: string; children: ReactNode; testId?: string }) {
  return (
    <Card className="mt-6" data-testid={testId}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

function Redirects({ http }: { http: HttpDetails }) {
  if (http.redirectChain.length === 0) return <>—</>
  return (
    <ol className="space-y-0.5 font-mono text-xs" data-testid="redirect-chain">
      {http.redirectChain.map((url, i) => (
        <li key={`${i}-${url}`}>
          {i > 0 && '→ '}
          {url}
          {http.redirectStatusCodes[i] !== undefined && <span className="text-muted-foreground"> ({http.redirectStatusCodes[i]})</span>}
        </li>
      ))}
    </ol>
  )
}

function CookieFlags({ cookie, https }: { cookie: HttpCookie; https: boolean }) {
  return (
    <div className="flex flex-wrap gap-1">
      <Badge variant={cookie.secure ? 'success' : https ? 'warning' : 'outline'}>{cookie.secure ? 'Secure' : 'no Secure'}</Badge>
      <Badge variant={cookie.httpOnly ? 'success' : 'outline'}>{cookie.httpOnly ? 'HttpOnly' : 'no HttpOnly'}</Badge>
      <Badge variant="outline">SameSite: {cookie.sameSite ?? '—'}</Badge>
    </div>
  )
}

function HttpSection({ http, artifacts }: { http: HttpDetails; artifacts: ServiceArtifact[] }) {
  const header = (name: string) => Object.entries(http.headers).find(([k]) => k.toLowerCase() === name)?.[1]
  const noteFor = (kind: string, name: string) => artifacts.find((a) => a.kind === kind && a.name.toLowerCase() === name.toLowerCase())
  const headers = Object.entries(http.headers).sort(([a], [b]) => a.localeCompare(b))
  const https = http.scheme === 'https'
  return (
    <>
      <Section title="HTTP" testId="http-section">
        <KeyValues
          items={[
            ['URL', <span className="font-mono text-xs">{http.url}</span>],
            ['Status', http.statusCode],
            ['Title', http.title],
            ['Server', http.webServer],
            ['Content type', http.contentType ?? header('content-type')],
            ['Redirects', <Redirects http={http} />],
            ['Final URL', http.finalUrl && <span className="font-mono text-xs">{http.finalUrl}</span>],
            ['Page type', http.pageType && <Badge variant="outline">{http.pageType}</Badge>],
            ['CDN / WAF', http.cdn ? `${http.cdn}${http.cdnType ? ` (${http.cdnType})` : ''}` : undefined],
            ['Favicon', (http.faviconHash || http.faviconMd5) && <span className="font-mono text-xs">mmh3 {http.faviconHash ?? '—'} · md5 {http.faviconMd5 ?? '—'}</span>],
          ]}
        />
      </Section>
      <Section title={`Headers (${headers.length})`} testId="headers-section">
        {headers.length === 0 ? (
          <EmptyState>No headers recorded.</EmptyState>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Header</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Why it is interesting</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {headers.map(([name, value]) => {
                const note = noteFor('header', name)
                return (
                  <TableRow key={name} data-interesting={note ? 'true' : undefined} className={note ? 'bg-warning/10' : undefined}>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{name}</TableCell>
                    <TableCell className="max-w-md font-mono text-xs break-all">{value}</TableCell>
                    <TableCell className="text-xs">{note ? note.reason : ''}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </Section>
      <Section title={`Cookies (${http.cookies.length})`} testId="cookies-section">
        {http.cookies.length === 0 ? (
          <EmptyState>No cookies set.</EmptyState>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Flags</TableHead>
                <TableHead>Domain / path</TableHead>
                <TableHead>Notes</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {http.cookies.map((c) => (
                <TableRow key={c.name} data-testid="cookie-row">
                  <TableCell className="font-mono text-xs">{c.name}</TableCell>
                  <TableCell>
                    <CookieFlags cookie={c} https={https} />
                  </TableCell>
                  <TableCell className="font-mono text-xs">{[c.domain, c.path].filter(Boolean).join(' ') || '—'}</TableCell>
                  <TableCell className="text-xs">
                    {c.decodedValue && <div className="font-mono">{c.decodedValue}</div>}
                    {noteFor('cookie', c.name)?.reason}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <p className="text-muted-foreground mt-2 text-xs">Cookie values are never collected.</p>
      </Section>
    </>
  )
}

function Body({ d }: { d: ServiceDetail }) {
  const s = d.service
  const cert = d.certificate
  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-3 font-mono">
            {s.address}:{s.port}/{s.transport.toLowerCase()}
            <Badge variant={s.state === 'Open' ? 'success' : 'outline'}>{s.state}</Badge>
            {d.device && (
              <Badge variant="secondary" data-testid="device-badge">
                {d.device.type}
              </Badge>
            )}
          </span>
        }
        description={
          <>
            <Link to="/assets/services" className="hover:underline">
              {t.assets.services}
            </Link>
            {' / '}
            <Link to={`/assets/hosts/${s.hostId}`} className="font-mono hover:underline">
              {s.address}
            </Link>
          </>
        }
      />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Service</CardTitle>
          </CardHeader>
          <CardContent>
            <KeyValues
              items={[
                ['Zone', zoneLabel(s.zone)],
                ['Endpoint', <EndpointLink address={s.address} port={s.port} url={s.url} serviceName={s.serviceName} tls={!!s.tls} />],
                ['Service', [s.serviceName, s.product, s.version].filter(Boolean).join(' ') || 'unknown'],
                ['Device', d.device ? [d.device.type, d.device.vendor, d.device.product].filter(Boolean).join(' · ') : undefined],
                ['First seen', formatDateTime(s.firstSeenAt)],
                ['Last seen', formatDateTime(s.lastSeenAt)],
              ]}
            />
          </CardContent>
        </Card>
        <Card data-testid="tls-section">
          <CardHeader>
            <CardTitle>TLS certificate</CardTitle>
          </CardHeader>
          <CardContent>
            {cert ? (
              <KeyValues
                items={[
                  ['Subject', cert.subjectCommonName],
                  ['Alt names', cert.subjectAlternativeNames?.join(', ')],
                  ['Issuer', <>{cert.issuer ?? '—'} {cert.selfSigned && <Badge variant="warning">self-signed</Badge>}</>],
                  ['Valid', `${cert.notBefore?.slice(0, 10) ?? '—'} → ${cert.notAfter?.slice(0, 10) ?? '—'}`],
                  ['SHA-256', <span className="font-mono text-xs break-all">{cert.fingerprintSha256}</span>],
                ]}
              />
            ) : (
              <EmptyState>No certificate.</EmptyState>
            )}
          </CardContent>
        </Card>
      </div>
      <Section title={`Artifacts (${d.artifacts.length})`} testId="artifacts-section">
        {d.artifacts.length === 0 ? (
          <EmptyState>No interesting headers, cookies or pages.</EmptyState>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Kind</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead>Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {d.artifacts.map((a) => (
                <TableRow key={`${a.kind}-${a.name}`} data-testid="artifact-row">
                  <TableCell>{a.kind}</TableCell>
                  <TableCell className="font-mono text-xs">{a.name}</TableCell>
                  <TableCell className="max-w-xs font-mono text-xs break-all">{a.value ?? '—'}</TableCell>
                  <TableCell className="text-xs">{a.reason}</TableCell>
                  <TableCell>
                    <ArtifactTags tags={a.tags} />
                  </TableCell>
                  <TableCell>
                    <Badge variant={a.severity === 'low' ? 'warning' : 'outline'}>{a.severity}</Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>
      {d.http ? <HttpSection http={d.http} artifacts={d.artifacts} /> : <Section title="HTTP">{<EmptyState>No HTTP response recorded.</EmptyState>}</Section>}
      <Section title={`Technologies (${d.technologies.length})`}>
        {d.technologies.length === 0 ? (
          <EmptyState />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Technology</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Method</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {d.technologies.map((x) => (
                <TableRow key={x.name}>
                  <TableCell className="font-medium">{x.name}</TableCell>
                  <TableCell>{x.version ?? '—'}</TableCell>
                  <TableCell>{x.category ?? '—'}</TableCell>
                  <TableCell>
                    <ConfidenceBar score={x.confidence} method={x.confidenceMethod} />
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">{x.confidenceMethod ?? '—'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>
      <Section title={`Findings (${d.findings.length})`}>
        <FindingsTable findings={d.findings} urlFor={() => s.url} />
      </Section>
    </>
  )
}

export function ServiceDetailPage() {
  const { id = '' } = useParams()
  return <Loadable query={useService(id)}>{(d) => <Body d={d} />}</Loadable>
}
