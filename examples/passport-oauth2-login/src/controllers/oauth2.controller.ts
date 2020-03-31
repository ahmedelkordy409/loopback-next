// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: @loopback/example-access-control-migration
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {get, RestBindings, Response, Request} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {SecurityBindings, UserProfile} from '@loopback/security';


// session interface to set session variables
interface Session {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

// extending express request type with a session field
interface RequestWithSession extends Request {
  session: Session;
}

// user profile to add in session
interface SessionProfile {
  user: UserProfile;
  provider: string;
  token: string;
}

/**
 * Login controller for third party oauth provider
 */
export class Oauth2Controller {
  constructor() {}

  @authenticate('Oauth2')
  @get('/auth/thirdparty')
  /**
   * Endpoint: '/auth/thirdparty'
   *          an endpoint for api clients to login via a third party app, redirects to third party app
   */
  loginToThirdParty(
    @inject('authentication.redirect.url')
    redirectUrl: string,
    @inject('authentication.redirect.status')
    status: number,
    @inject(RestBindings.Http.RESPONSE)
    response: Response,
  ) {
    response.statusCode = status || 302;
    response.setHeader('Location', redirectUrl);
    response.end();
    return response;
  }

  @authenticate('Oauth2')
  @get('/auth/thirdparty/callback')
  /**
   * Endpoint: '/auth/thirdparty/callback'
   *          an endpoint which serves as a oauth2 callback for the thirdparty app
   *          this endpoint sets the user profile in the session
   */
  async thirdPartyCallBack(
    @inject(SecurityBindings.USER) user: UserProfile,
    @inject(RestBindings.Http.REQUEST) request: RequestWithSession,
    @inject(RestBindings.Http.RESPONSE) response: Response,
  ) {
    const userProfile: SessionProfile = {
      ...user.profile
    };
    if (!request.session.user) {
      request.session.user = {
        profiles: [userProfile],
      };
    }
    if (request.session.user) {
      request.session.user.profiles.push(userProfile);
    }
    response.redirect('/auth/account');
    return response;
  }
}
