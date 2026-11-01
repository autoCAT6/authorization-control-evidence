# Third-party components

The source and wheel contain this example's Python adapter and JavaScript
probe/audit. They do not bundle Dioptra, Node, OpenSSL, or npm dependencies.
`prepare_runtime.py` obtains dependencies separately with the supplied npm lock.
Their licenses and attribution remain in the installed packages.

`dependency-inventory.json` records all 98 locked npm packages, metadata hashes,
declared licenses and available top-level license-file hashes. The direct
`@digitalbazaar/ezcap-express` 7.3.0 package omits a license field in its metadata;
its included LICENSE explicitly states BSD 3-Clause. This file inspection fills
that metadata gap. The inventory is not an automated legal clearance.

The lock also includes pako under `(MIT AND Zlib)` and type-fest under
`(MIT OR CC0-1.0)`. No dependency source has been relicensed as this example's code.

The optional integration imports unmodified NIST Dioptra at
`71bf4fa7ad62f96640e0884b0d11e7c3fdc1b4c0` and its upstream test fixtures.
Dioptra's own LICENSE explains US-government works and the CC BY 4.0 terms
applicable to copyrights held by NIST. Obtain and retain that source and its
license separately. `dioptra-source-hashes.json` contains hashes, not that code.

The copy-service pattern follows the public discussion in
[W3C CCG zcap-spec issue 130](https://github.com/w3c-ccg/zcap-spec/issues/130).
The probe uses the released Digital Bazaar libraries unchanged. This example
does not contribute to their vendor repositories or submit specification text.
