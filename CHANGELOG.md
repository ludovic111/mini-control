# Changelog

All notable updates to Mini Control are listed here.

## 2026-02-16

### Added
- Changelog tab in the web UI (`/changelog`) with full git commit history.
- Release notes panel that reads this `CHANGELOG.md` file.
- File Manager actions to create new folders and files.
- Terminal output actions (copy and clear).
- Persistent terminal command history in browser storage.
- Logs download action for current source/filter selection.

### Improved
- Logs page auto-loads on open and supports Enter key in filter input.
- README feature list and deployment docs refreshed.

## 2026-02-16 (Monitoring + Scheduler Update)

### Added
- Live dashboard endpoint (`/api/stats`) with pause/resume refresh controls.
- In-memory stats collector thread with one-hour history (`/api/history`).
- Four lightweight Canvas charts: CPU, RAM, Disk I/O, and Network bandwidth.
- Scheduler page (`/scheduler`) with cron add/edit/delete and quick actions.
- Power management API routes and dashboard controls for reboot/shutdown/schedule/cancel.

### Improved
- Sidebar navigation now includes Scheduler between Packages and Logs.
- Setup script and README include sudoers entries required for power actions.
