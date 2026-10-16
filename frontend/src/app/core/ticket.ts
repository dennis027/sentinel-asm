import { FRAMEWORK_SHORT_NAMES } from './labels';
import { Finding } from './models/models';

/**
 * A finding as a ready-to-paste ticket for Jira, GitHub, ServiceNow or
 * an email -- everything the person fixing it needs, no login required.
 */
export function ticketText(finding: Finding): string {
  const lines = [
    `[${finding.severity.toUpperCase()}] ${finding.title} on ${finding.asset_value}`,
    '',
    finding.due_at
      ? `Fix by: ${new Date(finding.due_at).toISOString().slice(0, 10)}${finding.overdue ? ' (overdue)' : ''}`
      : '',
    finding.assignee_username ? `Owner: ${finding.assignee_username}` : '',
    finding.impact ? `\nWhy it matters:\n${finding.impact}` : '',
    finding.remediation ? `\nWhat to do:\n${finding.remediation}` : '',
    finding.description ? `\nDetails:\n${finding.description}` : '',
    finding.controls.length
      ? `\nRelated controls: ${finding.controls
          .map((c) => `${FRAMEWORK_SHORT_NAMES[c.framework] ?? c.framework} ${c.code} (${c.name})`)
          .join('; ')}`
      : '',
    `\nFirst seen: ${new Date(finding.first_seen).toISOString().slice(0, 10)}`,
    'Reported by Densight',
  ].filter((line) => line !== '');
  return lines.join('\n');
}
