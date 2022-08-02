/* crypto_template.ts
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

import wolfssl from '@src/addon/wolfssl';

import Events from 'events';
import StreamBuffers from 'stream-buffers';
import { CryptographicService } from '@src/cryptographic-service';
import { Decryptor } from '@src/decryptor';
import { WolfSSLDecryptor } from './wolfssl-decryptor';
import { DecryptionStream } from '@src/streams/decryption-stream';
import { cryptographicServiceFactory } from '@src/cryptographic-services';

describe('DecryptionStream', () => {
  test('should transform all the bytes when pipe is called with other stream', async () => {
    const input = new StreamBuffers.ReadableStreamBuffer();
    const service = cryptographicServiceFactory.create('null');
    const stream = new DecryptionStream(
      service,
      { 'cipher': 'AES-256-CBC', 'key': Buffer.alloc(0), 'iv': Buffer.alloc(0) }
    );

    const spyTransform = jest.spyOn(stream, '_transform');
    const spyFlush = jest.spyOn(stream, '_flush');

    input.put(Buffer.from('test message'));
    input.stop();
    input.pipe(stream);

    await Events.once(stream, 'finish');

    expect(spyTransform).toHaveBeenCalledWith(Buffer.from('test message'), 'buffer', expect.anything());
    expect(spyFlush).toHaveBeenCalledTimes(1);
  });
});

import { WolfSSLDecryptor } from '@src/cryptographic-services/wolfssl-decryptor';

describe('WolfSSLDecryptor', () => {
  test('should successfully decrypt an encrypted text by calling update and finalize', () => {
    const key = Buffer.from('12345678901234567890123456789012');
    const iv = Buffer.from('1234567890123456');
    const decrypt = new WolfSSLDecryptor('AES-256-CBC', key, iv);
    const expected = 'test';

    const actual = Buffer.concat([
      decrypt.update(Buffer.from('24d31b1e41fc8c40', 'hex')),
      decrypt.update(Buffer.from('e521531d67c72c20', 'hex')),
      decrypt.finalize()
    ]);

    expect(actual.toString('utf8')).toStrictEqual(expected);
  });

  test('should throw an error when calling finalize and the decryption was invalid', () => {
    const key = Buffer.from('12345678901234567890123456789012');
    const iv = Buffer.from('1234567890123456');
    const decrypt = new WolfSSLDecryptor('AES-256-CBC', key, iv);

    decrypt.update(Buffer.from('not a valid encrypted text'));

    expect(() => decrypt.finalize()).toThrowError();
  });
});


export class WolfSSLCryptographicService implements CryptographicService {
  /**
   * Initializes a new instance of the WolfSSLCryptographicService.
   */
  public constructor() {
    if (!wolfssl.isFipsEnabled() && !wolfssl.enableFips()) {
      logger.logWarning('FIPS mode not available.');
    }
  }

  /**
   * Encrypts the given data.
   *
   * @param data The data to encrypt.
   *
   * @returns The encrypted data blob.
   *
   * @throws {Error} If the operation fails.
   *
   * @remarks The encrypted data blob layout is defined by the cryptographic
   * service which could or not be standard. Decryption must be done with a
   * compatible cryptographic service.
   */
  public async encrypt(data: Buffer): Promise<Buffer> {
    if (data.length > 0) {
      throw new Error('Encryption is not implemented.');
    }

    throw new Error('Encryption is not implemented.');
  }

  /**
   * Decrypts the given data.
   *
   * @param data The encrypted data to decrypt.
   *
   * @returns The decrypted data.
   *
   * @throws {Error} If the operation fails.
   */
  public async decrypt(data: Buffer): Promise<Buffer> {
    if (data.length > 0) {
      throw new Error('Decryption is not implemented.');
    }

    throw new Error('Decryption is not implemented.');
  }

  /**
   * Creates a Decryption instance used to decrypt data.
   *
   * @param cipher The decryption cipher name to use.
   * @param key    The decryption key to use.
   * @param iv     The initialization vector.
   *
   * @returns A new instance of the Decryptor class.
   *
   * @throws {Error} If cipher is not available or unknown.
   * @throws {Error} If the creation of the Decryption object failed.
   */
  public createDecryptor(cipher: string, key: Buffer, iv: Buffer): Decryptor {
    return new WolfSSLDecryptor(cipher, key, iv);
  }
}


/**
 * The WolfSSLDecryptor class that provides decryption functionalities for data in chunks of
 * arbitrary size using the WolfSSL addon.
 */
export class WolfSSLDecryptor implements Decryptor {
  private readonly decryption: wolfssl.Decryption;

  /**
   * Initializes a new instance of the WolfSSLDecryptor class.
   *
   * @param cipher The cipher name to use.
   * @param key    The decryption key to use.
   * @param iv     The initialization vector.
   *
   * @throws {Error} If cipher is not available or unknown.
   * @throws {Error} If the creation of the Decryption object failed.
   */
  public constructor(cipher: string, key: Buffer, iv: Buffer) {
    this.enableFips();
    this.decryption = new wolfssl.Decryption(cipher, key, iv);
  }

  /**
   * Updates the internal state with data for decryption.
   *
   * @param data The data that will be added for decryption.
   *
   * @returns The decrypted data if possible.
   *
   * @throws {Error} If the decryption fails.
   *
   * @remarks This function should be called multiple times.
   */
  public update(data: Buffer): Buffer {
    return this.decryption.update(data);
  }

  /**
   * Finalize the decryption process.
   *
   * @returns The last block of decrypted data.
   *
   * @throws {Error} If the decryption fails.
   *
   * @remarks This function should be called once to finalize the decryption
   * process.
   */
  public finalize(): Buffer {
    return this.decryption.finalize();
  }

  /**
   * Enables the FIPS mode.
   */
  private enableFips(): void {
    if (!wolfssl.isFipsEnabled() && !wolfssl.enableFips()) {
      logger.logWarning('FIPS mode not available.');
    }
  }
}
