import { Context } from '@yunflyjs/yunfly';

export interface KeysConfig {
  lower: string;
  upper: string;
}

export interface JWTpayload {
  [propsName: string]: any;
}

export interface GenerateTokenOption {
  data: JWTpayload;
  ctx: Context;
}

export interface VerifyTokenOption {
  ctx: Context;
}

export interface DecodeOption {
  json?: boolean;
  complete?: boolean;
}

export interface DecodeTokenOption {
  token: string;
  option?: DecodeOption;
}

export interface InjectTokenOption {
  ctx: Context;
  token: string;
}

export interface JWTOptions {
  enable?: boolean;
  secret?: string;
  expire?: string | number;
  token?: JWTTokenOptions;
  unless?: string[];
  global?: boolean;
  passThrough?: boolean;
  expiredPassThrough?: boolean;
  rsSign?: RsSignOption;
}

export type JWTConfig = JWTOptions | ((ctx: Context) => JWTOptions);

export interface RsSignOption {
  enable?: boolean;
  interval?: number;
}

export interface JWTTokenOptions {
  type?: 'cookie' | 'header';
  key?: string;
  httpOnly?: boolean;
  domain?: string;
  path?: string;
  maxAge?: number;
  expires?: any;
  secure?: boolean;
  sameSite?: boolean | string;
  signed?: boolean;
  overwrite?: boolean;
}
