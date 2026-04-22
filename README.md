# Alisia

Mailing list server built on the [Konducta](https://github.com/mbaas2/Konducta)
framework, written in Dyalog APL.

Alisia handles subscription management, message distribution, admin commands,
GDPR compliance (audit log, DELETEME), and bounce processing for email-based
mailing lists.

## Dependencies

- **Konducta** — provides the runtime, rule engine, and `eventler_Handler` base class
- **[Dyalog APL 20+](https://www.dyalog.com/dyalog/dyalog-versions/200.htm)** with .NET 8
- **[MimeKit / MailKit](https://github.com/jstedfast/MailKit)** (loaded automatically via NuGet at startup)

## Deployment

Alisia is loaded by Konducta at startup via the `ALISIA_HOME` environment variable.
The deployment configuration (POP3/SMTP credentials, list names, rules) lives in a
separate config repo (e.g. **APLde-Konducta**).

