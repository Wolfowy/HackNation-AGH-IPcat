import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { MultiSelect, networkOption } from './MultiSelect'

const networks = [
  { id: 'a', name: 'Office LAN', zone: 'office', ranges: ['192.168.10.0/24'], tags: ['workstations'] },
  { id: 'b', name: 'home 10.250.160.0/20', zone: 'home', ranges: ['10.250.169.64/26'], tags: ['agent-subnet'] },
  { id: 'c', name: 'lab 172.30.0.0/24', zone: 'lab', ranges: ['172.30.0.0/24'], tags: ['agent-subnet'] },
]

function Harness({ onSubmit = () => {} }: { onSubmit?: () => void }) {
  const [value, setValue] = useState<string[]>([])
  return (
    <form onSubmit={(e) => (e.preventDefault(), onSubmit())}>
      <MultiSelect legend="Networks" options={networks.map(networkOption)} value={value} onChange={setValue} />
      <output data-testid="value">{value.join(',')}</output>
    </form>
  )
}

describe('MultiSelect', () => {
  it('searches name, zone, ranges and #tags; selects all matches; removes with chips and backspace', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    const search = screen.getByRole('combobox', { name: 'Search networks' })

    await user.type(search, '#agent-subnet')
    expect(screen.getAllByRole('option').map((o) => o.textContent)).toEqual([expect.stringContaining('home'), expect.stringContaining('lab')])
    await user.click(screen.getByRole('button', { name: 'Select all 2 matches' }))
    expect(screen.getByTestId('value')).toHaveTextContent('b,c')

    await user.clear(search)
    await user.type(search, '192.168')
    expect(screen.getAllByRole('option')).toHaveLength(1)
    await user.click(screen.getByRole('option', { name: /Office LAN/ }))
    expect(screen.getByTestId('value')).toHaveTextContent('b,c,a')

    await user.click(screen.getByRole('button', { name: 'Remove home 10.250.160.0/20' }))
    expect(screen.getByTestId('value')).toHaveTextContent('c,a')
    await user.clear(search)
    await user.keyboard('{Backspace}')
    expect(screen.getByTestId('value')).toHaveTextContent('c')
  })

  it('picks with the keyboard and never submits the surrounding form', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    render(<Harness onSubmit={onSubmit} />)
    await user.type(screen.getByRole('combobox', { name: 'Search networks' }), 'office{arrowdown}{enter}')
    expect(screen.getByTestId('value')).toHaveTextContent('a')
    expect(screen.getByRole('option', { name: /Office LAN/ })).toHaveAttribute('aria-selected', 'true')
    expect(onSubmit).not.toHaveBeenCalled()
  })
})
