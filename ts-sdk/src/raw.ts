// Re-export of the raw tn-wasm surface.
//
// The rest of the SDK wraps these with idiomatic TypeScript types. If
// you need something the SDK does not yet expose, pull from here rather
// than reimplementing the primitive.

export {
  adminReduce,
  adminCatalogKinds,
  adminValidateEmit,
  canonicalBytes,
  canonicalJson,
  deriveDidKey,
  deviceKeyFromSeed,
  generateDeviceKey,
  signMessage,
  verifyDid,
  signatureB64,
  signatureFromB64,
  deriveGroupIndexKey,
  indexToken,
  zeroHash,
  computeRowHash,
  buildEnvelope,
  BtnPublisher,
  btnDecrypt,
  btnCiphertextPublisherId,
  btnKitLeaf,
  btnKitPublisherId,
  btnMaxLeaves,
  btnTreeHeight,
} from "tn-wasm";
