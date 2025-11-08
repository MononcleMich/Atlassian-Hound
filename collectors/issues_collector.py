"""
AtlassianHound - Jira Issues Collector

STATUS: ❌ DISABLED / WORK IN PROGRESS

The Jira issues collector is intentionally disabled. Jira Cloud’s search
endpoint (`/rest/api/3/search`) requires per-project “Browse Projects” and
“View Issues” permissions that most API tokens do not possess, and the JQL
handling differs between project types. Leaving this stub in place avoids
accidental execution while preserving a future development path.
"""

import logging

LOG = logging.getLogger("AtlassianHound.issues")


def run(graph, project_id=None, project_key=None):
    """
    Disabled collector placeholder.

    If you plan to re-enable this collector, consult:
      https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/
    and ensure JQL, pagination, and permissions are handled for all project types.
    """
    LOG.debug("Issues collector is DISABLED (work in progress). Skipping execution.")
    return None
