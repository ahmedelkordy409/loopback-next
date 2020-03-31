// Copyright IBM Corp. 2019. All Rights Reserved.
// Node module: @loopback/example-lb3-application
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {ApplicationConfig} from '@loopback/core';
import express from 'express';
import http from 'http';
import {AddressInfo} from 'net';
import pEvent from 'p-event';
import {Oauth2LoginApplication} from './application';


/**
 * an express server which embeds an express web app and a LB4 API server
 * 
 * The LB4 API server serves to provide Oauth2 interfaces with external providers
 */
export class ExpressServer {

  /**
   * An express web app which requires local authentication
   */
  private webApp: express.Application;
  public readonly lbApp: Oauth2LoginApplication;
  private server?: http.Server;
  public url: String;

  constructor(options: ApplicationConfig = {}) {

    // Express Web App
    this.webApp = require('../client/web-app');

    // LB4 App
    this.lbApp = new Oauth2LoginApplication(options);

    // Wrap the LB4 REST API with an express mount
    /**
     * This means we are also able to wrap the lb4 api with express middleware
     * 
     * This is very crucial in this app for the functioning of saving user profiles as login sessions
     */
    this.webApp.use('/api', this.lbApp.requestHandler);
  }

  public async boot() {
    await this.lbApp.boot();
  }

  /**
   * Start the express app and the lb4 app
   */
  public async start() {
    await this.lbApp.start();
    const port = this.lbApp.restServer.config.port ?? 3000;
    const host = this.lbApp.restServer.config.host ?? 'localhost';
    this.server = this.webApp.listen(port, host);
    await pEvent(this.server, 'listening');
    const add = <AddressInfo>this.server.address();
    this.url = `https://${add.address}:${add.port}`;
  }

  /**
   * Stop lb4 and express apps
   */
  public async stop() {
    if (!this.server) return;
    await this.lbApp.stop();
    this.server.close();
    await pEvent(this.server, 'close');
    this.server = undefined;
  }
}
