"""The application catalog: permanent IDs, tiers, and what each tier includes."""

from uuid import UUID

NOTES_ID = UUID("10000000-0000-4000-8000-000000000001")
REPORTS_ID = UUID("10000000-0000-4000-8000-000000000002")
FILES_ID = UUID("10000000-0000-4000-8000-000000000003")

# Gaps in the numbers leave room for a new tier later, without changing existing grants.
TIERS = {"basic": 10, "standard": 20, "premium": 30}

# feature: (lowest tier, limit per tier). None means no limit.
APPLICATIONS = {
    "notes": {
        "id": NOTES_ID,
        "name": "Notes",
        "client_id": "notes-app",
        "features": {
            "notes.read": {"basic": None, "standard": None, "premium": None},
            "notes.create": {"basic": 50, "standard": None, "premium": None},
            "notes.share": {"standard": None, "premium": None},
            "notes.export": {"premium": None},
        },
    },
    "reports": {
        "id": REPORTS_ID,
        "name": "Reports",
        "client_id": "reports-app",
        "features": {
            "reports.view": {"basic": None, "standard": None, "premium": None},
            "reports.export_csv": {"standard": None, "premium": None},
            "reports.schedule": {"premium": None},
        },
    },
    "files": {
        "id": FILES_ID,
        "name": "Files",
        "client_id": "files-app",
        "features": {
            "files.storage_mb": {"basic": 100, "standard": 5000, "premium": 50000},
            "files.folders": {"standard": None, "premium": None},
            "files.share_links": {"premium": None},
        },
    },
}
