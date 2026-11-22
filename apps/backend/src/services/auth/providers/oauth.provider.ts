import {
  AuthProvider,
  AuthProviderAbstract,
} from '@gitroom/backend/services/auth/providers.interface';

@AuthProvider({ provider: 'GENERIC' })
export class OauthProvider extends AuthProviderAbstract {
  private _discovery?: Promise<{
    authorization_endpoint?: string;
    token_endpoint?: string;
    userinfo_endpoint?: string;
  }>;

  // POSTIZ_OAUTH_URL is the issuer of an OpenID Connect provider, the
  // endpoints that are not set explicitly are read from its discovery document
  private loadDiscovery(issuer: string) {
    if (!this._discovery) {
      const url = issuer.includes('/.well-known/')
        ? issuer
        : `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;

      this._discovery = fetch(url, {
        headers: { Accept: 'application/json' },
      }).then(async (response) => {
        if (!response.ok) {
          throw new Error(
            `OpenID discovery request failed: ${await response.text()}`
          );
        }

        return response.json();
      });

      this._discovery.catch(() => {
        this._discovery = undefined;
      });
    }

    return this._discovery;
  }

  private async getConfig() {
    const {
      POSTIZ_OAUTH_URL,
      POSTIZ_OAUTH_CLIENT_ID,
      POSTIZ_OAUTH_CLIENT_SECRET,
      FRONTEND_URL,
    } = process.env;

    let {
      POSTIZ_OAUTH_AUTH_URL,
      POSTIZ_OAUTH_TOKEN_URL,
      POSTIZ_OAUTH_USERINFO_URL,
    } = process.env;

    if (
      POSTIZ_OAUTH_URL &&
      (!POSTIZ_OAUTH_AUTH_URL ||
        !POSTIZ_OAUTH_TOKEN_URL ||
        !POSTIZ_OAUTH_USERINFO_URL)
    ) {
      const discovery = await this.loadDiscovery(POSTIZ_OAUTH_URL);
      POSTIZ_OAUTH_AUTH_URL ||= discovery.authorization_endpoint;
      POSTIZ_OAUTH_TOKEN_URL ||= discovery.token_endpoint;
      POSTIZ_OAUTH_USERINFO_URL ||= discovery.userinfo_endpoint;
    }

    if (
      !POSTIZ_OAUTH_USERINFO_URL ||
      !POSTIZ_OAUTH_TOKEN_URL ||
      !POSTIZ_OAUTH_CLIENT_ID ||
      !POSTIZ_OAUTH_CLIENT_SECRET ||
      !POSTIZ_OAUTH_AUTH_URL ||
      !FRONTEND_URL
    ) {
      throw new Error('POSTIZ_OAUTH environment variables are not set');
    }

    return {
      authUrl: POSTIZ_OAUTH_AUTH_URL,
      clientId: POSTIZ_OAUTH_CLIENT_ID,
      clientSecret: POSTIZ_OAUTH_CLIENT_SECRET,
      tokenUrl: POSTIZ_OAUTH_TOKEN_URL,
      userInfoUrl: POSTIZ_OAUTH_USERINFO_URL,
      frontendUrl: FRONTEND_URL,
    };
  }

  async generateLink(query?: { state?: string }): Promise<string> {
    const { authUrl, clientId, frontendUrl } = await this.getConfig();
    const params = new URLSearchParams({
      client_id: clientId,
      scope: 'openid profile email',
      response_type: 'code',
      state: query?.state || 'login',
      redirect_uri: `${frontendUrl}/settings`,
    });

    return `${authUrl}?${params.toString()}`;
  }

  async getToken(code: string, _redirectUri?: string): Promise<string> {
    const { tokenUrl, clientId, clientSecret, frontendUrl } =
      await this.getConfig();
    const response = await fetch(`${tokenUrl}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: `${frontendUrl}/settings`,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token request failed: ${error}`);
    }

    const { access_token } = await response.json();
    return access_token;
  }

  async getUser(access_token: string): Promise<{ email: string; id: string }> {
    const { userInfoUrl } = await this.getConfig();
    const response = await fetch(`${userInfoUrl}`, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`User info request failed: ${error}`);
    }

    const { email, sub: id } = await response.json();
    return { email, id };
  }
}
