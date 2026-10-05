ALLOWED_TOOLS = {
    "viewer": {"read_file", "search", "summarize"},
    "analyst": {"read_file", "search", "summarize", "write_report"},
    "editor": {"read_file", "search", "write_file", "summarize"},
    "admin": {
        "read_file", "write_file", "delete_file",
        "execute_command", "send_email", "search", "summarize",
    },
}

PROTECTED_PATHS = [
    "/etc/", "/var/", "/root/", "/home/",
    "C:\\Windows", "C:\\Program Files",
]

SANDBOX_PREFIX = "./sandbox/"

DANGEROUS_COMMAND_PATTERNS = ["rm -rf", "del /f", "format", "shutdown", ">"]
