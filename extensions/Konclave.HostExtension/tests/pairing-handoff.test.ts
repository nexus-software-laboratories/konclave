import { describe, expect, it } from 'vitest';
import { BitMatrix, Decoder } from '@nuintun/qrcode';

import {
  PairingHandoffError,
  pairingRendezvousUriPrefix,
  parsePairingHandoff,
  renderPairingQr,
} from '../src/service/pairing-handoff.js';

const token = '000G40R40M30E209185GR38E1W';

describe('pairing handoff', () => {
  it('canonicalizes raw and URI handoffs to identical bytes', () => {
    const raw = parsePairingHandoff(token.toLowerCase());
    const uri = parsePairingHandoff(`${pairingRendezvousUriPrefix}${token.toLowerCase()}`);

    expect(raw).toEqual({ token, uri: `${pairingRendezvousUriPrefix}${token}` });
    expect(uri).toEqual(raw);
  });

  it('rejects ambiguous, extended, and decorated handoffs without echoing input', () => {
    for (const value of [
      '',
      `${token}0`,
      token.replace('0', 'O'),
      `${pairingRendezvousUriPrefix}${token}?source=test`,
      `${pairingRendezvousUriPrefix}${token}#fragment`,
      `https://example.test/${token}`,
    ]) {
      expect(() => parsePairingHandoff(value)).toThrow(PairingHandoffError);
      try {
        parsePairingHandoff(value);
      } catch (error: unknown) {
        if (value.length > 0) {
          expect(String(error)).not.toContain(value);
        }
      }
    }
  });

  it('renders a bounded control-sequence-free QR representation', () => {
    const uri = `${pairingRendezvousUriPrefix}${token}`;
    const qr = renderPairingQr(uri);

    expect(qr.columns).toBeGreaterThan(0);
    expect(qr.columns).toBeLessThanOrEqual(70);
    expect(qr.lines.length).toBeLessThanOrEqual(40);
    expect(qr.lines.every((line) => line.length === qr.columns)).toBe(true);
    expect(qr.lines.join('\n')).toMatch(/[▀▄█]/u);
    expect(qr.lines.join('\n')).not.toContain('\u001b');
    expect(qr.lines.join('\n')).not.toContain(token);

    const size = qr.columns - 6;
    const matrix = new BitMatrix(size);
    for (let y = 0; y < size; y += 1) {
      const line = qr.lines[Math.floor((y + 2) / 2)];
      for (let x = 0; x < size; x += 1) {
        const module = line?.[x + 3];
        const dark =
          (y + 2) % 2 === 0 ? module === '▀' || module === '█' : module === '▄' || module === '█';
        if (dark) {
          matrix.set(x, y);
        }
      }
    }
    expect(new Decoder().decode(matrix).content).toBe(uri);
  });
});
