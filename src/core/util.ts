export function fromLittleEndian(bytes: Uint8Array): bigint {
  const n256 = BigInt(256);
  let result = BigInt(0);
  let base = BigInt(1);
  bytes.forEach((byte) => {
    result += base * BigInt(byte);
    base = base * n256;
  });
  return result;
}

export function fromBigEndian(bytes: Uint8Array): bigint {
  return fromLittleEndian(bytes.reverse());
}

export function toLittleEndian(bigNumber: bigint, len = 31): Uint8Array {
  const n256 = BigInt(256);
  const result = new Uint8Array(len);
  let i = 0;
  while (bigNumber > BigInt(0)) {
    result[i] = Number(bigNumber % n256);
    bigNumber = bigNumber / n256;
    i += 1;
  }
  return result;
}

export function toBigEndian(bigNumber: bigint): Uint8Array {
  return toLittleEndian(bigNumber).reverse();
}
