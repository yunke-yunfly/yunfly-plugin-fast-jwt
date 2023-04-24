import {
  UnauthorizedError, BadRequestError, Context,
  Action, KoaMiddlewareInterface, Middleware
} from '@yunflyjs/yunfly';
import ms from 'ms';

const { createSigner, createVerifier, createDecoder } = require('fast-jwt')
const decode = createDecoder();

import {
  DecodeTokenOption,
  GenerateTokenOption,
  InjectTokenOption,
  JWTConfig,
  JWTOptions,
  JWTpayload,
  RsSignOption,
  VerifyTokenOption,
} from '../types';
import { getJwtToken, include } from '../utils';

const DEFAULT_RELOAD_TIME = 900; // 15分钟

export function getJwtConfig(ctx: Context): JWTOptions {
  let jwtConfig: JWTConfig = ctx.config?.jwt || {};
  if (typeof jwtConfig === 'function') {
    jwtConfig = jwtConfig(ctx);
  }
  return jwtConfig;
}

/**
 * 生成token
 *
 * @export
 * @param {GenerateTokenOption} opt
 * @returns
 */
export function generateToken(opt: GenerateTokenOption): string {
  if (!opt.data) throw new UnauthorizedError('加密数据不能为空!');
  const { data, ctx } = opt;
  const JWTConfig = getJwtConfig(ctx);
  if (!JWTConfig.secret) throw new UnauthorizedError('JWT配置secret参数不能为空!');

  if (!JWTConfig.enable) return '';

  const expiresIn = typeof JWTConfig.expire === 'number' ? JWTConfig.expire : ms(JWTConfig.expire as string);
  const signSync = createSigner({ key: JWTConfig.secret, expiresIn })
  const token = signSync(data)

  const resToken = `Bearer ${token}`;

  injectToken({ ctx, token: resToken });

  return resToken;
}

// 判断是否要过期了
export function checkExpired(iat: number, exp: number, rsSign: RsSignOption): boolean {
  if (!rsSign || !rsSign.enable) {
    return false;
  }
  const reloadTime =
    typeof rsSign.interval === 'number' ? rsSign.interval * 60 : DEFAULT_RELOAD_TIME;
  const timestampNow = Math.round(Date.now() / 1000);

  // 有效期小于 重签时间，不处理
  if (exp - iat <= reloadTime) {
    return false;
  }
  // 过期时间小于 重启时间，重签
  if (exp - timestampNow < reloadTime) {
    return true;
  }
  return false;
}

/**
 *
 * 重签 jwt
 * @param {string} token
 * @param {Context} ctx
 */
export function reloadJwt(token: string, ctx: Context): any {
  const data: any = decodeToken({ token });
  delete data.iat;
  delete data.exp;
  ctx.state.payload = data;
  generateToken({ data, ctx });
  return data;
}

/**
 * 验证token
 *
 * @export
 * @param {VerifyTokenOption} opt
 */
export async function verifyToken(opt: VerifyTokenOption): Promise<any> {
  const { ctx } = opt;
  const JWTConfig = getJwtConfigForHttp(ctx);
  if (!JWTConfig.enable) return Promise.resolve({});
  if (!JWTConfig.secret) throw new UnauthorizedError('JWT secret不能为空!');
  if (!JWTConfig.token) throw new UnauthorizedError('JWT token不能为空!');
  const expiredPassThrough = JWTConfig.expiredPassThrough ?? true;
  const token = JWTConfig.token.replace(/Bearer\s?/, '').trim();

  const verifyWithPromise = createVerifier({ key: async () => JWTConfig.secret as string })
  try {
    const decoded = await verifyWithPromise(token);
    // 重签
    if (checkExpired(decoded.iat, decoded.exp, JWTConfig.rsSign as RsSignOption)) {
      return reloadJwt(token, ctx);
    }
    delete decoded.iat;
    delete decoded.exp;
    ctx.state.payload = decoded;
    return decoded;
  } catch (err: any) {
    if (err.message.includes('token has expired')) {
      if (!expiredPassThrough) {
        throw new UnauthorizedError('jwt 验证过期');
      }
      console.info({
        msg: 'jwt 验证过期',
        error: err,
      });
      // jwt 重签
      return reloadJwt(token, ctx);
    }
    throw new UnauthorizedError(err.message || 'jwt token验证失败!');
  }
}

/**
 * 解码token
 *
 * @export
 * @param {DecodeTokenOption} opt
 */
export function decodeToken(opt: DecodeTokenOption) {
  if (!opt.token) throw new UnauthorizedError('jwt token不能为空!');
  return decode(opt.token, opt.option);
}

/**
 * 注入token
 *
 * @export
 * @param {InjectTokenOption} opt
 */
export function injectToken(opt: InjectTokenOption): string {
  const { ctx, token } = opt;
  if (!token) throw new UnauthorizedError('jwt token不能为空!');

  const jwtConfig = getJwtConfig(ctx);
  const tokenConfig = jwtConfig.token || {};
  const key: string = tokenConfig.key || 'Authorization';
  const type: string = tokenConfig.type || 'header';
  const newTokenConfig = { ...tokenConfig };
  if (type === 'header') {
    ctx.set(`Set-${key}`, token);
  } else if (type === 'cookie') {
    const { expires } = tokenConfig || {};
    if (typeof expires === 'function') {
      const exp = expires();
      if (exp) newTokenConfig.expires = exp;
    }
    ctx.cookies.set(key, token, { ...newTokenConfig } as any);
  }
  return token;
}

/**
 * 获得 http 请求的token
 *
 * @param {Context} ctx
 * @returns
 */
function getJwtConfigForHttp(ctx: Context) {
  const jwtConfig = getJwtConfig(ctx);
  const tokenConfig = jwtConfig.token || {};
  const key: string = (tokenConfig.key || 'Authorization').toUpperCase();
  const type: string = tokenConfig.type || 'header';

  const token: string = getJwtToken(ctx, type, key);
  return {
    ...jwtConfig,
    token,
  };
}

/**
 * 用户状态数据
 *
 * @param {Action} action
 * @returns {Promise<AnyOptions>}
 */
export const currentUserChecker = async (action: Action): Promise<JWTpayload> =>
  action.context.state.payload;

/**
 * JWT middleware
 *
 * @param {*} ctx
 * @param {(err?: any) => Promise<any>} next
 * @returns {Promise<any>}
 */
export const JWTMiddleware = async (
  ctx: any,
  next: (err?: any) => Promise<any>,
  passThrough?: boolean,
): Promise<any> => {
  const jwtConfig = getJwtConfig(ctx);

  // 以下条件不做校验
  if (!jwtConfig.enable || !jwtConfig.secret) {
    return await next();
  }

  // jwt 校验
  try {
    await verifyToken({ ctx });
  } catch (err: any) {
    if (!passThrough) {
      throw new BadRequestError(err);
    }
  }

  await next();
};

/**
 * JWT middleware 校验不通过时可继续执行
 *
 * @param {*} ctx
 * @param {(err?: any) => Promise<any>} next
 * @returns {Promise<any>}
 */
export const JWTPassThroughMiddleware = async (
  ctx: any,
  next: (err?: any) => Promise<any>,
): Promise<any> => JWTMiddleware(ctx, next, true);

/**
 * JWT 校验
 *
 * @export
 * @class JWTMiddleware
 * @implements {KoaMiddlewareInterface}
 */
@Middleware({ type: 'before', priority: 18 })
export default class YunflyPluginJWTMiddleware implements KoaMiddlewareInterface {
  async use(ctx: Context, next: (err?: any) => Promise<any>): Promise<any> {
    const jwtConfig = getJwtConfig(ctx);
    // 以下条件不做校验
    if (!jwtConfig.global || (jwtConfig.unless && include(jwtConfig.unless, ctx.request.url))) {
      return await next();
    }
    const passThrough = jwtConfig.passThrough ? true : false;
    return JWTMiddleware(ctx, next, passThrough);
  }
}
