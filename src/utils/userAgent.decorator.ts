import { ExecutionContext, createParamDecorator } from "@nestjs/common";

export const UserAgent = createParamDecorator(
    (data: string, ctx: ExecutionContext) => {
      try {
        const req = ctx.switchToHttp().getRequest().headers;
        return req['user-agent'] 
      } catch (error) {
        return ''
      }
    },
  );
  