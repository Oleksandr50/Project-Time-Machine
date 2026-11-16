# Authentication and network access

Administrator setup has no default password. Native 0.7.5 installations bind to 0.0.0.0.
First setup over the network requires the one-time owner code from
`"$HOME/ProjectTimeMachine/bin/ptm" setup-code`. Existing administrators sign in normally.
See [INSTALL_EN.md](../INSTALL_EN.md) for network-on/network-off and setup instructions.

Roles are Administrator, Operator and Viewer, with explicit project grants and a separate
restore permission. Server-side sessions use HttpOnly/SameSite cookies, inactivity expiry,
CSRF protection and login rate limits. Use HTTPS or VPN over untrusted networks.
Cookie Secure behavior depends on the actual connection/proxy configuration.
