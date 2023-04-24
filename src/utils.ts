import { Context } from 'koa';
import { JWTpayload } from './types';
const cookie = require('cookie');

/**
 *
 * @param {string[]} arr
 * @param {string} str
 * @returns
 */
export const include = (arr: string[], str: string) => {
  if (!arr || !arr.length || !str) {
    return false;
  }

  let result = false;
  for (const key of arr) {
    if (str.indexOf(key) > -1) {
      result = true;
      return result;
    }
  }
  return result;
};

const getValue = (obj: JWTpayload = {}, key: string): string => {
  let res: string = '';
  const keys = Object.keys(obj);
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toUpperCase() === key) {
      res = obj[keys[i]];
      break;
    }
  }
  return res;
};

/**
 * get jwt token
 *
 * @param {Context} ctx
 * @param {string} type
 * @param {string} key
 */
export const getJwtToken = (ctx: Context, type: string, key: string): string => {
  const headers = ctx.headers || ctx.request.headers || {};
  if (type === 'header') {
    return getValue(headers, key);
  } else if (type === 'cookie') {
    const cookies = cookie.parse(headers.cookie || '');
    return getValue(cookies, key);
  }
  return '';
};
