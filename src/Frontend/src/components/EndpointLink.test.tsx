import { render, screen } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { EndpointLink, endpointHref, TargetLink } from './EndpointLink'

describe('endpointHref', () => {
  it.each([
    [{ address: '10.0.0.1', port: 8080, url: 'http://10.0.0.1:8080/login' }, 'http://10.0.0.1:8080/login'],
    [{ address: '10.0.0.1', port: 443 }, 'https://10.0.0.1:443/'],
    [{ address: '10.0.0.1', port: 8443 }, 'https://10.0.0.1:8443/'],
    [{ address: '10.0.0.1', port: 9999, serviceName: 'ssl/http' }, 'https://10.0.0.1:9999/'],
    [{ address: '10.0.0.1', port: 9999, serviceName: 'https-alt' }, 'https://10.0.0.1:9999/'],
    [{ address: '10.0.0.1', port: 993, tls: true }, 'https://10.0.0.1:993/'],
    [{ address: '10.0.0.1', port: 22, serviceName: 'ssh' }, 'http://10.0.0.1:22/'],
    [{ address: '2001:db8::1', port: 8080 }, 'http://[2001:db8::1]:8080/'],
  ])('%o → %s', (endpoint, href) => expect(endpointHref(endpoint)).toBe(href))
})

const renderInRouter = (ui: React.ReactElement) => render(<RouterProvider router={createMemoryRouter([{ path: '/', element: ui }])} />)

describe('EndpointLink', () => {
  it('opens the endpoint in a new tab without an opener', () => {
    render(<EndpointLink address="2001:db8::1" port={443} />)
    const link = screen.getByRole('link', { name: '[2001:db8::1]:443' })
    expect(link).toHaveAttribute('href', 'https://[2001:db8::1]:443/')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('links a plain address (no port) to the host detail page', () => {
    renderInRouter(<TargetLink hostId="h1" address="10.0.0.5" />)
    const link = screen.getByRole('link', { name: '10.0.0.5' })
    expect(link).toHaveAttribute('href', '/assets/hosts/h1')
    expect(link).not.toHaveAttribute('target')
  })

  it('links an address with a port externally plus a host-detail icon', () => {
    renderInRouter(<TargetLink hostId="h1" address="10.0.0.5" port={80} url="http://10.0.0.5/" />)
    expect(screen.getByRole('link', { name: '10.0.0.5:80' })).toHaveAttribute('href', 'http://10.0.0.5/')
    expect(screen.getByRole('link', { name: 'Host 10.0.0.5' })).toHaveAttribute('href', '/assets/hosts/h1')
  })
})
