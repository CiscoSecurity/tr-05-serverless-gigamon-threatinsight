MODULE_NAME = 'Gigamon ThreatINSIGHT'
GIGAMON_URL = 'https://portal.icebrg.io'
CONFIDENCE = SEVERITY = ('High', 'Medium', 'Low')
RELATIONS_TYPES = (
    'Connected_To', 'Sent_From', 'Sent_To',
    'Resolved_To', 'Hosted_On', 'Queried_For',
    'Downloaded_To', 'Downloaded_From',
    'Uploaded_From', 'Uploaded_To',
)
TARGETS_OBSERVABLES_TYPES = ('ip', 'hostname', 'mac_address')
RELATED_OBSERVABLES_TYPES = (
    'ip', 'domain', 'sha1', 'sha256', 'md5', 'url', 'user_agent'
)
OBSERVABLE_HUMAN_READABLE_NAME = {
    'ip': 'IP',
    'sha256': 'SHA256',
    'md5': 'MD5',
    'sha1': 'SHA1',
    'domain': 'domain'
}
