import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import * as jsonwebtoken from 'jsonwebtoken';
import { bloom } from './bloom.repo';
import { Reflector } from '@nestjs/core';
import { log } from 'console';

interface JwtPayload {
  sub: string;
  did: string;
  jti: string;
  exp: number;
  roles: string[];
}

@Injectable()
export class UserGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const request = context.switchToHttp().getRequest();
      if (!request.headers.authorization)
        throw new HttpException('UNAUTHORIZED', HttpStatus.UNAUTHORIZED);
      const bearer = request.headers.authorization.split(' ')[1];
      request.auth = jsonwebtoken.verify(bearer, process.env.JWT_SECRET);
      const payload: JwtPayload = request.auth;
      const filterList = await bloom.has(payload.jti);
      if (payload.roles.includes('refresh_token'))
        throw new HttpException('UNAUTHORIZED', HttpStatus.UNAUTHORIZED);
      if (filterList) throw new UnauthorizedException();
      return true;
    } catch (error) {
      throw new UnauthorizedException();
    }
  }
}

@Injectable()
export class JWTRefreshGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const request = context.switchToHttp().getRequest();
      if (!request.headers.authorization)
        throw new HttpException('UNAUTHORIZED', HttpStatus.UNAUTHORIZED);
      const bearer = request.headers.authorization.split(' ')[1];
      request.auth = jsonwebtoken.verify(bearer, process.env.JWT_SECRET);
      const payload: JwtPayload = request.auth;
      const filterList = await bloom.has(payload.jti);
      if (filterList) return false;
      return true;
    } catch (error) {
      throw new UnauthorizedException();
    }
  }
}

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const requiredRoles = this.reflector.getAllAndOverride<string[]>(
        ROLES_KEY,
        [context.getHandler(), context.getClass()],
      );
      const request = context.switchToHttp().getRequest();
      if (!request.headers.authorization)
        throw new HttpException('Forbidden', HttpStatus.UNAUTHORIZED);
      const bearer = request.headers.authorization.split(' ')[1];
      request.auth = jsonwebtoken.verify(bearer, process.env.JWT_SECRET);
      const payload: JwtPayload = request.auth;
      if (requiredRoles)
        for (const role of requiredRoles)
          if (!payload.roles.includes(role))
            throw new HttpException('Forbiden', HttpStatus.FORBIDDEN);
      const filterList = await bloom.has(payload.jti);
      if (filterList) return false;
      return true;
    } catch (error) {
      return false;
    }
  }
}

// checks only for superadmin role
@Injectable()
export class AdminGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const request = context.switchToHttp().getRequest();
      if (!request.headers.authorization)
        throw new HttpException('UNAUTHORIZED', HttpStatus.UNAUTHORIZED);
      const bearer = request.headers.authorization.split(' ')[1];
      request.auth = jsonwebtoken.verify(bearer, process.env.JWT_SECRET);
      const payload: JwtPayload = request.auth;
      if (!payload.roles.includes('superadmin')) return false;
      const filterList = await bloom.has(payload.jti);
      if (filterList) return false;
      return true;
    } catch (error) {
      return false;
    }
  }
}
