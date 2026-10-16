import { apiErrorMessage, findingTypeLabel, roleLabel } from './labels';

describe('labels', () => {
  it('names finding types, falling back to the raw value for unknown ones', () => {
    expect(findingTypeLabel('open_port')).toBe('Open port');
    expect(findingTypeLabel('something_new')).toBe('something_new');
  });

  it('names roles', () => {
    expect(roleLabel('analyst')).toBe('Analyst');
    expect(roleLabel(null)).toBe('No role');
  });

  it('pulls the readable message out of an API error', () => {
    expect(apiErrorMessage({ error: { detail: 'Not allowed.' } }, 'x')).toBe('Not allowed.');
    expect(apiErrorMessage({ error: { root_domain: ['Enter a public domain.'] } }, 'x')).toBe(
      'Enter a public domain.',
    );
    expect(apiErrorMessage({ error: '<html>502</html>' }, 'Fallback')).toBe('Fallback');
    expect(apiErrorMessage(undefined, 'Fallback')).toBe('Fallback');
  });
});
