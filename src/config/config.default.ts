import { Config } from '@yunflyjs/yunfly';
import { JWTConfig } from '../types';

/**
 * 包内置默认配置项
 *
 * @export
 * @param {KoaApp} app
 * @returns
 */
export default function config(): Config {
  const config: Config & { jwt?: JWTConfig } = {};

  /**
   * jwt configs
   */
  config.jwt = {
    enable: false,
    expiredPassThrough: false,
    secret: 'YUNFLYJS_JWT_TOKEN_DEMO',
    expire: '2h',
    // token: {
    //   type: 'cookie',
    //   key: 'authorization',
    //   httpOnly: true,
    //   path: '/'
    // },
    // rsSign: {
    //   enable: false,
    //   interval: 15,
    // },
    token: { type: 'header', key: 'Authorization' },
    global: true,
    passThrough: false,
    unless: ['/favicon.ico'],
  };

  return config;
}
