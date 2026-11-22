import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ConditionExpression } from '@/api/types'
import { ConditionBuilder } from './ConditionBuilder'

function setup(initial: ConditionExpression) {
  let current: ConditionExpression | undefined = initial
  function Harness() {
    const [value, setValue] = useState<ConditionExpression | undefined>(initial)
    current = value
    return <ConditionBuilder label="When" value={value} onChange={setValue} />
  }
  render(<Harness />)
  return { user: userEvent.setup(), value: () => current }
}

describe('condition builder fields', () => {
  it('offers the passive HTTP/TLS/banner fields and marks list fields', () => {
    setup({ field: 'http.title', operator: 'Contains', values: ['admin'] })
    const options = Array.from((screen.getByLabelText('Field') as HTMLSelectElement).options).map((o) => o.value)
    for (const f of ['http.cookieNames', 'http.faviconHash', 'http.finalUrl', 'http.redirectChain', 'http.contentType', 'http.technologies', 'service.banner', 'tls.subjectAlternativeNames', 'http.header.'])
      expect(options).toContain(f)
    expect(screen.getByRole('option', { name: 'http.cookieNames (list: any element)' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Header name')).not.toBeInTheDocument()
  })

  it('edits a dynamic http.header.<Name> field', async () => {
    const { user, value } = setup({ field: 'http.title', operator: 'Exists' })
    await user.selectOptions(screen.getByLabelText('Field'), 'http.header.')
    await user.type(screen.getByLabelText('Header name'), 'X-Powered-By')
    expect(value()).toEqual({ field: 'http.header.X-Powered-By', operator: 'Exists' })
    expect((screen.getByLabelText('Field') as HTMLSelectElement).value).toBe('http.header.')
  })

  it('shows the header name of an existing header rule', () => {
    setup({ field: 'http.header.Server', operator: 'Contains', values: ['Hikvision'] })
    expect(screen.getByLabelText('Header name')).toHaveValue('Server')
  })
})
