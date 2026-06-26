# TN Decrypt — Privacy Policy

Last updated: 2026-06-17

TN Decrypt is a browser extension that decrypts TN protocol ciphertexts
shown on a web page using reader keys that you hold locally. This policy
describes what the extension does and does not do with your data.

## Summary

The extension does not collect, transmit, sell, or share any personal
data. All processing happens locally inside your browser. Your keys never
leave your machine.

## What the extension stores, and where

- **Reader kits / keystores.** When you import a kit from a file, or pair
  one from your tn-proto.org vault, the kit is stored in your browser's
  local extension storage (`chrome.storage.local`) on your own device.
  These keys are used only to decrypt content you choose to reveal.
- **In-memory state.** While the extension is unlocked, decryption keys
  live in the extension's service-worker memory and are discarded when the
  browser ends the session or you click "Lock all".

This data stays on your device. It is not uploaded anywhere by the
extension.

## Page content

When you click the extension on a page and choose "Decrypt this page", the
extension reads the text of that one tab to find TN ciphertexts and
rewrites the recognized ones in place with their decrypted values. This
reading happens locally and only on the tab you activated. Page content is
never transmitted off your device. The extension does not run in the
background and does not read pages you have not explicitly activated.

## Network activity

The extension performs no background network requests, contains no
analytics or telemetry, and sends no usage data to us or to any third
party.

The one optional network interaction is "Sign in with vault": if you
choose it, the extension opens your own tn-proto.org vault
(`https://vault.tn-proto.org`) in a new tab. After you sign in and approve
pairing there, your vault sends reader kits to the extension. This happens
only at your initiative and only with your own vault account. No other
origin can deliver kits to the extension.

## Permissions

- `activeTab` and `scripting`: read and rewrite the current tab only when
  you click the extension, in order to decrypt TN content on that page.
- `storage`: keep your imported reader keys in local browser storage.
- Connection to `https://vault.tn-proto.org`: receive kits you pair from
  your own vault.

The extension requests no broad host permissions and cannot read your
browsing history or your tabs in the background.

## Data sharing

None. The extension does not share data with anyone because it does not
collect or transmit any.

## Changes

Material changes to this policy will be reflected in the extension's store
listing and in this document, with an updated date above.

## Contact

Questions: gil@cyaxios.com
