from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Optional

_SAFE_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})
_SAFE_PREFIXES = (
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)

@dataclass
class AuthorizationScope:
    project_path: str = ""
    allowed_hosts: set[str] = field(default_factory=lambda: set(_SAFE_HOSTS))
    allowed_ports: set[int] = field(default_factory=set)
    active_testing_enabled: bool = False
    static_analysis_only: bool = True
    authorized_by: str = ""
    authorization_notes: str = ""
    excluded_paths: list[str] = field(default_factory=list)
    max_severity_action: str = "report"

    def is_target_authorized(self, host: str, port: Optional[int] = None) -> bool:
        if host in self.allowed_hosts:
            if port and self.allowed_ports:
                return port in self.allowed_ports
            return True
        for prefix in _SAFE_PREFIXES:
            if host.startswith(prefix):
                return True
        return False

    def validate_path(self, path: str) -> bool:
        norm_path = os.path.normpath(os.path.abspath(path))
        norm_project = os.path.normpath(os.path.abspath(self.project_path))
        if not norm_path.startswith(norm_project):
            return False
        for excluded in self.excluded_paths:
            if norm_path.startswith(os.path.normpath(os.path.join(norm_project, excluded))):
                return False
        return True

POLICY_TEXT = """
==================================================================
                 SECURITY TESTING POLICY                          
==================================================================

Before performing active security testing:

 1. Determine the target.                                       
 2. Determine whether the target is explicitly authorized.      
 3. Prefer localhost, test containers, dev/staging servers,     
    and intentionally vulnerable labs.                           
 4. Never attack arbitrary external systems.                    
 5. Never steal, dump, or publish credentials.                  
 6. Never destroy or corrupt data.                              
 7. Never establish persistence.                                
 8. Never evade security monitoring.                            
 9. Never use findings to attack unrelated systems.             
10. Stop when testing could affect systems outside scope.       
                                                                  
==================================================================
""".strip()

def print_policy() -> str:
    return POLICY_TEXT
