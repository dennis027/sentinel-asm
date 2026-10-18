import { LogCategory } from '../../core/models/models';

export const LOG_CATEGORIES: { value: LogCategory; label: string }[] = [
  { value: 'auth_failure', label: 'Failed sign-ins' },
  { value: 'auth_success', label: 'Sign-ins' },
  { value: 'privilege', label: 'Admin rights used' },
  { value: 'account_change', label: 'Account changes' },
  { value: 'log_tampering', label: 'Logs cleared' },
  { value: 'service', label: 'Services and tasks' },
  { value: 'app_error', label: 'App errors' },
  { value: 'http_request', label: 'Web requests' },
  { value: 'other', label: 'Other' },
];
