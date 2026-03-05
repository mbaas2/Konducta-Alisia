# Alisia

Mailing list server built on the [Konducata](https://github.com/mbaas2/Konducata)
framework, written in Dyalog APL.

Alisia handles subscription management, message distribution, admin commands,
GDPR compliance (audit log, DELETEME), and bounce processing for email-based
mailing lists.

## Dependencies

- **Konducata** — provides the runtime, rule engine, and `eventler_Handler` base class
- **Dyalog APL 20+** with .NET 8
- **MimeKit / MailKit** (loaded automatically via NuGet at startup)

## Deployment

Alisia is loaded by Konducata at startup via the `ALISIA_HOME` environment variable.
The deployment configuration (POP3/SMTP credentials, list names, rules) lives in a
separate config repo (e.g. **APLde-Konducata**).

## Related Repos

- **Konducata** — the event framework
- **APLde-Konducata** — APL Germany deployment configuration
