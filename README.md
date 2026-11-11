# NiceCat bootstrap metadata

This repository contains the encrypted, Ed25519-signed endpoint discovery document for the NiceCat client. It contains no application source code or account credentials.

`bootstrap.json` is mirrored to Cloudflare Worker and R2 discovery endpoints. Clients verify signatures with keys bundled in the application and enforce monotonically increasing versions and expiry.

The daily renewal workflow keeps at least 21 days of validity and signs a new version with a 30-day lifetime when renewal is due. The workflow receives only the dedicated discovery signing key and bootstrap AES key through encrypted Actions secrets; the offline configuration signing key is never uploaded.

Endpoint changes must first pass production health checks and be published with a version greater than the current document. Mirror the identical encrypted document to every source. Do not publish local configuration files, private keys or access tokens here.
