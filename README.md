# not-a-mused

A proof-of-concept for a local Muse (https://muse.ai) vulnerability 0day that can let an unprivileged local process redirect Muse’s dictation traffic and abuse the trust/access granted to the app.

## What it demonstrates

Muse exposes an undocumented setting:

`endo_voyager_dictation_endpoint`

A local attacker or malware can modify this endpoint without special privileges.

Once redirected, dictated prompts can be sent to an attacker-controlled endpoint, potentially allowing:

* Capture of dictated audio/prompts
* Prompt injection into Muse
* Theft of Muse authentication material
* Abuse of whatever access the user has granted Muse

In short: Muse’s access can potentially become the attacker’s access.

## Usage

Run:

```bash
./not-a-mused -h
```

for available options.

The PoC implements a subset of the 50+ commands exposed by Muse.

Once running, click the microphone button in Muse and dictate a prompt to trigger the PoC.

## Notes

This is a **local attack**. An attacker must already be able to execute code as the local user.

The concern is that Muse may have significantly broader access than ordinary local malware, making it a particularly useful target for privilege/access amplification.

## Disclaimer

Provided for security research and educational purposes.
