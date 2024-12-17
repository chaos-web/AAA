
export enum sessionState{
    active = 'active',
    deactive = 'deactive'
}

export interface Session {
  _id?: string;
  jti: string;
  exp: Date;
  userid: string;
  userAgent: string;
  state:sessionState
}

export interface JwtTokens {
    access_token: any;
    refresh_token: any;
    exp: number;
    jti: string;
  }
  

  export interface MessagePattern<T> {
    message: string;
    tId?: string;
    data: T;
  }
  
  