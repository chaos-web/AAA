import { config } from "dotenv";
import Redis from "ioredis";
config()

class bloomFilter {
   client:Redis = new Redis({
    db: 0,
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: +process.env?.REDIS_PORT || 6379,
  });

  async has(id:string){
    try {
        const sess = await this.client.zscore('revokeList',id)
        if(!sess) return false
        return true
    } catch (error) {
        return false        
    }
  }

}

export const bloom = new bloomFilter()