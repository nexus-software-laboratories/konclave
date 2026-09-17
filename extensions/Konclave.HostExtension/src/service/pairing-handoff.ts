import { Byte, Encoder } from '@nuintun/qrcode';

export const pairingRendezvousTokenCharacters = 26;
export const pairingRendezvousUriPrefix = 'konclave://pair/';

const tokenPattern = /^[0-9A-HJKMNP-TV-Z]{26}$/u;
const uriPattern = /^konclave:\/\/pair\/([0-9A-HJKMNP-TV-Z]{26})$/iu;
const quietZoneModules = 2;
const maximumQrModules = 64;

export interface PairingHandoff {
  readonly token: string;
  readonly uri: string;
}

export interface PairingQr {
  readonly lines: readonly string[];
  readonly columns: number;
}

export class PairingHandoffError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PairingHandoffError';
  }
}

/** Canonicalizes one raw compact token or versioned pairing URI. */
export function parsePairingHandoff(value: string): PairingHandoff {
  const trimmed = value.trim();
  const uriMatch = uriPattern.exec(trimmed);
  const token = (uriMatch?.[1] ?? trimmed).toUpperCase();
  if (token.length !== pairingRendezvousTokenCharacters || !tokenPattern.test(token)) {
    throw new PairingHandoffError(
      'connect requires a 26-character pairing token or konclave://pair/<token> URI',
    );
  }
  return {
    token,
    uri: `${pairingRendezvousUriPrefix}${token}`,
  };
}

/** Renders a bounded QR matrix without ANSI control sequences. */
export function renderPairingQr(uri: string): PairingQr {
  let encoded;
  try {
    encoded = new Encoder({ level: 'M' }).encode(new Byte(uri));
  } catch {
    throw new PairingHandoffError('pairing QR code could not be generated');
  }
  if (encoded.size <= 0 || encoded.size > maximumQrModules) {
    throw new PairingHandoffError('pairing QR code exceeds the terminal bound');
  }

  const start = -quietZoneModules;
  const end = encoded.size + quietZoneModules;
  const lines: string[] = [];
  for (let y = start; y < end; y += 2) {
    let line = '';
    for (let x = start; x < end; x += 1) {
      const top =
        x >= 0 && x < encoded.size && y >= 0 && y < encoded.size && encoded.get(x, y) === 1;
      const bottom =
        x >= 0 &&
        x < encoded.size &&
        y + 1 >= 0 &&
        y + 1 < encoded.size &&
        encoded.get(x, y + 1) === 1;
      line += top ? (bottom ? '█' : '▀') : bottom ? '▄' : ' ';
    }
    lines.push(`│${line}│`);
  }
  return {
    lines,
    columns: end - start + 2,
  };
}
