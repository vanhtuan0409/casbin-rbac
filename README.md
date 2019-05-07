# Casbin RBAC

Simple demonstration for RBAC using Casbin

### Policy

- Repos must belonged to a specific group
- There are 3 basic privilege to a repo:
  - Read
  - Write
  - Delete
- A group will have these roles:
  - Admin
    + Have all privilege
  - Moderator
    + Have read and write privilege
  - Member
    + Have read privilege
- Owner of a repo have full access to that repo
- Each role will have a specific privilege to all repo within group
