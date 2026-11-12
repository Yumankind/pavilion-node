# Security

pavilion-node runs other people's jobs on your machine, so we take reports seriously.

**Please don't open a public issue for a vulnerability.** Use GitHub's private reporting instead:
**Security › Report a vulnerability** on this repository. We'll answer within a few working days, keep you informed,
and credit you if you'd like.

**In scope:**
- getting out of a job sandbox;
- reaching the host's services or network from a sandbox;
- getting a secret's value onto the machine or into the sandbox;
- forging or replaying jobs, join codes or signed requests;
- making the resource guard fail to protect the host.

The known limits are listed in [docs/DESIGN.md](docs/DESIGN.md#limits-to-know).
