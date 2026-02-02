import { BadRequestException, Injectable, Scope } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import OpenIDClient, { ClientAuth } from 'openid-client';
import * as client from 'openid-client';
import { userInfo } from 'os';
import { RecordableHistogram } from 'perf_hooks';
import { schedulePromise } from 'rxjs/internal/scheduled/schedulePromise';
@Injectable()
export class AuthService {
  private server!: URL;
  private clientID!: string;
  private clientSecret!: string;
  private redicrectURL!: string;
  private nonce: string | undefined;

  constructor(private readonly configService: ConfigService) {
    this.server = new URL('https://accounts.google.com');
    this.clientID = this.configService.getOrThrow('CLIENT_ID');
    this.clientSecret = this.configService.getOrThrow('CLIENT_SECRET');
    this.redicrectURL = 'http://localhost:3000/auth/google/callback';
  }

  /*** Steps to be done!
   * 1) discovery the server within the client id and client secret
   * 2) generate the random pure string and store it inside the session (it will not be sent over google oauth)
   * 3) generate the hased version of this string
   * 4) Send this hashed string within the configiration and built the complete redirectUrl
   * 5)
   */
  async googleAuthUrlHandle(session: any): Promise<URL> {
    let config = await client.discovery(
      this.server,
      this.clientID,
      this.clientSecret,
    );
    const codeChallengeMethod = 'S256'; // The encryption method
    const codeVerifier = client.randomPKCECodeVerifier(); // Long random secret string
    session.code_verifier = codeVerifier;
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier); // the encrypted version
    const parameters: Record<string, string> = {
      redirect_uri: this.redicrectURL,
      scope: 'openid email profile',
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    };

    // If the third party auth provider doesn't support PKCE Just you will create code that is used
    // Only once for the request and if the attacker try to payload if will fail
    if (!config.serverMetadata().supportsPKCE()) {
      this.nonce = client.randomNonce();
      session.nonce = this.nonce;
      parameters.nonce = this.nonce;
    }

    const redirectTo = client.buildAuthorizationUrl(config, parameters);
    console.log(`Redirecting to ${redirectTo.href}`);
    return redirectTo;
  }

  async handleTheCallback(url: string, session: any) {
    const config = await client.discovery(
      this.server,
      this.clientID,
      this.clientSecret,
    );

    try {
      const tokens = await client.authorizationCodeGrant(config, new URL(url), {
        pkceCodeVerifier: session.code_verifier, // Must match the session key used above
        expectedNonce: session.nonce,
        idTokenExpected: true,
      });

      const claims = tokens.claims();
      const user = await client.fetchUserInfo(
        config,
        tokens.access_token,
        claims!.sub,
      );

      delete session.code_verifier;
      delete session.nonce;

      return { tokens, user };
    } catch (err) {
      console.error(err);
      throw new BadRequestException(`Authentication Failed: ${err.message}`);
    }
  }
}
