# access-control

### v0.1.0

A simple access restriction system to simulate a real-world
system that requires simple, reliable, and flexible security

## Types

### Terminal
A Terminal is a crucial type in the access control system.
It represents a single access point, and may be added to a
Group for easier permission configuration. All permissions
defined within a Terminal overwrite those from its Group.

### Group
A Group is a collection of permission information which can
be linked to from Terminals. Groups allow you to define an
Access Level, a list of Permissions, and a list of Denied users that
will immediately Deny access to a terminal.

### Key
A Key represents a physical access device like a keycard.
The Key also contains a keyholder/owner User, which determines
the Access Level, base roles, and if the User has been disabled.
A Key may also define a set of additional roles for only itself.
Keys may be set to expire after at a certain time.

### User
A User represents a person with an Access Level, Roles, and flags
such as Disabled that are typically read by the Terminals. Users
can hold multiple Keys.

### Permission
A Permission is anything that has a `Clears` method that determines
whether a given Key should have access to a Terminal or Group
using the Permission. Examples include permissions that only allow
users with specific roles, flags, or keys to be allowed.


## Determining access

When a Key is used on a Terminal, follow these steps:
- Check if the user is disabled. If so, Block the action.
- Check if the key is disabled or has expired. If so, Block the action.
- \* Check if the Terminal Permissions allow this Key.
  The permissions are all checked and stored in a list.
  - If the list contains Deny, Block the action (short-circuit capable)
  - If the list contains Allow, Clear the action
  - If the list is all Neutral, repeat this step for the parent Group.
    If there is no parent, continue checking
- If the Terminal does not belong to a Group, Block the action
- \* Check if the Group Permissions allow this Key.
  The permissions are all checked and stored in a list.
  - If the list contains Deny, Block the action (short-circuit capable)
  - If the list contains Allow, Allow the action
  - If the list is all Neutral, continue checking
- Deny; the User and Key do not have permission to access this terminal

&ast; When an overwrite is active, it will first check if the
overwrite rules allows or denies the key, and will act accordingly.
If the override returns Neutral, it will treat this as a Deny, as
the overwrite ignores normal permissions. Neutral is the state returned
when none of the permissions explicitly allow or deny an action.

## TODO

- add logging functionality and logwatchers
- add key expiry after n-uses using logwatcher
- create an api around the system

## License
Not yet licensed.
