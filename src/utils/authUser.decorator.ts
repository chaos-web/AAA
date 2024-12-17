import {
    createParamDecorator,
    ExecutionContext,
    HttpException,
    HttpStatus,
  } from '@nestjs/common';
  
 export interface JwtPayload {
    sub: string;
    did: string;
    jti:string
    exp: number;
    roles:string[]
  }
  
  export const AuthUser = createParamDecorator(
    (data: string, ctx: ExecutionContext) => {
      try {
        const auth = ctx.switchToHttp().getRequest().auth;
        return auth.sub
      } catch (error) {
        throw new HttpException('Forbidden', HttpStatus.UNAUTHORIZED);
      }
    },
  );
  

    
  export const Jwt = createParamDecorator(
    (data: string, ctx: ExecutionContext) => {
      try {
        const auth:JwtPayload = ctx.switchToHttp().getRequest().auth;
        return auth
      } catch (error) {
        throw new HttpException('Forbidden', HttpStatus.UNAUTHORIZED);
      }
    },
  );
  