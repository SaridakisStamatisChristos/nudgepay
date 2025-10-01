"""Command-line utilities for managing admin users."""

from __future__ import annotations

import argparse
import secrets
import sys

from .admins import deactivate_admin, ensure_admin, list_admins, rotate_password
from .db import session_scope


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Admin management tooling")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a new admin user")
    create.add_argument("email", help="Email address of the admin")
    create.add_argument("password", help="Initial password")
    create.add_argument(
        "--role",
        default="viewer",
        help="Role to assign (viewer, operator, superadmin)",
    )
    create.add_argument(
        "--permission",
        action="append",
        dest="permissions",
        default=None,
        help="Additional fine-grained permissions (may be repeated)",
    )

    rotate = sub.add_parser("rotate", help="Rotate password for an admin")
    rotate.add_argument("admin_id", type=int, help="ID of the admin user")

    deactivate = sub.add_parser("disable", help="Disable an admin user")
    deactivate.add_argument("admin_id", type=int, help="ID of the admin user")

    sub.add_parser("list", help="List admin users")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    with session_scope() as session:
        if args.command == "list":
            admins = list_admins(session)
            for admin in admins:
                status = "active" if admin.is_active else "disabled"
                perms = ",".join(admin.permissions)
                print(f"{admin.id}\t{admin.email}\t{status}\t{admin.role}\t{perms}")
            return 0

        if args.command == "create":
            admin = ensure_admin(
                session,
                email=args.email,
                password=args.password,
                role=args.role,
                permissions=args.permissions,
            )
            print(f"Created admin {admin.email} (id={admin.id})")
            return 0

        if args.command == "rotate":
            new_password = secrets.token_urlsafe(16)
            admin = rotate_password(session, admin_id=args.admin_id, new_password=new_password)
            print(f"New password for {admin.email}: {new_password}")
            return 0

        if args.command == "disable":
            admin = deactivate_admin(session, admin_id=args.admin_id)
            print(f"Admin {admin.email} disabled")
            return 0

    return 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main())
