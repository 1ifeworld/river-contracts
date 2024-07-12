import { SyndicateClient } from '@syndicateio/syndicate-node'

export const syndicateClient = new SyndicateClient({ token: process.env.SYNDICATE_API_KEY as string })

type Register = {
  to: string
  recovery: string
  deadline: number
  sig: string
}

// need to replace scrypt
export const generateRegisterForInput = async (register: Register) => ({
  projectId: process.env.SYNDICATE_PROJECT_ID,
  contractAddress: addresses.idRegistry.baseSepolia,
  chainId: 84532,
  functionSignature:
    'registerFor(address to, address recovery, uint256 deadline, bytes sig)',
  args: {
    to: register.to,
    recovery: register.recovery,
    deadline: register.deadline,
    sig: register.sig,
  },
})

const registerTx =
// biome-ignore lint:
await syndicateClient.transact.sendTransaction(
    generateRegisterForInput({ to, recovery, deadline, sig }),
)