import { log } from 'console';
import Web3 from 'web3';

export const ethProvider = {
  provide: 'ETHEREUM',
  useFactory: async (): Promise<Web3> => {
    try {
      return new Web3(
        'https://mainnet.infura.io/v3/e301ffa1dc9144679f181838268c8b4e',
      );
    } catch (error) {
        log(error)
    }
  },
};
