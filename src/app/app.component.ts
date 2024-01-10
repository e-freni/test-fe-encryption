import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
})
export class AppComponent {
  public plainPassword: any;
  encryptedPassword: any = '';

  //NB: le chiavi presenti sono autogenerate e solo di esempio
  publicKeyPem: any = '-----BEGIN PUBLIC KEY-----\n' +
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWVQPgdWsmSr6/UWCi1CEdXhYV\n' +
    '8msxQBjNzUi5K2kA/Puv1vuUHEtYVUPj6igRzqe83MCAAoVkhQwySTJVGK5WAovG\n' +
    'k5w3FfD0xUJc+P/xA9OywLjgT3hUTSTpbrsS4H3ddbPvGmCaoeGvIZ4cbYJdzG5E\n' +
    'CaEMr0UHz8Wyr25VSQIDAQAB\n' +
    '-----END PUBLIC KEY-----';
//NB: RSA di 1024 bit per leggibilità, nel caso eventualmente va usata ALMENO 2048(e ovviamente non harcodata :) )
  privateKeyPem: any = '-----BEGIN PRIVATE KEY-----\n' +
    'MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBANZVA+B1ayZKvr9R\n' +
    'YKLUIR1eFhXyazFAGM3NSLkraQD8+6/W+5QcS1hVQ+PqKBHOp7zcwIAChWSFDDJJ\n' +
    'MlUYrlYCi8aTnDcV8PTFQlz4//ED07LAuOBPeFRNJOluuxLgfd11s+8aYJqh4a8h\n' +
    'nhxtgl3MbkQJoQyvRQfPxbKvblVJAgMBAAECgYA0m41mDKwOLA6BuyGzFcpDARL+\n' +
    'tA/neModyaNt/9+4JGBKmsQJaKB9v//380N+i3DUhIKjaPsA3z9NIHZAONyhQNSc\n' +
    'YgO+hZOr1tiCSzj7KzwvugNCVtsCgu0hi0jgYNOQLwo58+qfLf1cSIbOOg2Ugf0a\n' +
    'CjM7hf/Zh+DE3TjoWQJBAPI7hXIqMymeV18Fk5Y1vPxA+RxoJc5gZ3QYjY46hR0Q\n' +
    'pZE4MY84daK4Yr6DwynSsCE2tYVxzcybDtdFjpzQTkMCQQDig4sXUl5sbljdDJyC\n' +
    '6rHAGHyfZeOgGu1brgrVe4/eayIkzZatnk7PaMrw0dy8apnIWMD57mofDasOzs9o\n' +
    'boODAkAYv8wapgUkM3Fp3AAAUO1GOL07EckLFP589iVAauo+1fyUodEueO5L+drc\n' +
    '7El8dHJacmSJhd8pEI6roAe6Le5RAkAzV8vESohanZyI5l3nktkdiK9e1hKFbPUW\n' +
    'Tdnoz+wpZzFDFFKuIe8NNlyhv4AAOU2ISw3a2P628TsvzRLYQgyPAkBjE4Ux4QS1\n' +
    'tAwxy4dwekmH9zT8FkGrg4X71E3qw3q5JATWbWApV9zdp68JKODqrFAUKHWM2UPs\n' +
    'TMvc2XKc5Tlk\n' +
    '-----END PRIVATE KEY-----';
  decryptedPassword: string = '';

  async encryptWithPublicKey() {
    const content = this.plainPassword;
    const publicKey = await this.importPublicKey(this.publicKeyPem);

    const encoder = new TextEncoder();
    const encodedContent = encoder.encode(content);

    const encryptedContent = await window.crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP'
      },
      publicKey,
      encodedContent
    );

    this.encryptedPassword = this.arrayBufferToBase64(encryptedContent);
  }

  async decryptWithPrivateKey() {
    const privateKey = await this.importPrivateKey(this.privateKeyPem);
    const decryptedContent = await window.crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP'
      },
      privateKey,
      this.base64ToArrayBuffer(this.encryptedPassword)
    );

    this.decryptedPassword = new TextDecoder().decode(decryptedContent);
  }

  private async importPrivateKey(pem: string): Promise<CryptoKey> {
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').trim();
    const binaryDerString = window.atob(pemContents);
    const binaryDer = this.stringToArrayBuffer(binaryDerString);

    return window.crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['decrypt']
    );
  }

  private async importPublicKey(pem: string): Promise<CryptoKey> {
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').trim();
    const binaryDerString = window.atob(pemContents);
    const binaryDer = this.stringToArrayBuffer(binaryDerString);

    return window.crypto.subtle.importKey(
      'spki',
      binaryDer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['encrypt']
    );
  }

  private stringToArrayBuffer(str: string): ArrayBuffer {
    const buffer = new ArrayBuffer(str.length);
    const bufferView = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) {
      bufferView[i] = str.charCodeAt(i);
    }
    return buffer;
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer as ArrayBuffer;
  }

}

