import { BraavosStrkKeyPairMultisigMetamask, Eip191KeyPairMultisigMetamask, normalizeSecpK1Signature } from "./secp256";
import { ArgentAccountWithoutExecute, ArgentSigner, ArgentSignerStrk } from "./signer";
import { TypedDataRevision } from "@starknet-io/types-js";
import { Signature as EthersSignature } from "ethers";
import {
  AccountInterface,
  Call,
  CallData,
  RPC,
  RawArgs,
  RpcProvider,
  SignerInterface,
  TypedData,
  cairo,
  hash,
  num,
  typedData,
  uint256,
} from "starknet";
import { createWalletClient, custom } from "viem";
import { mainnet } from "viem/chains";

const typesRev0 = {
  StarkNetDomain: [
    { name: "name", type: "felt" },
    { name: "version", type: "felt" },
    { name: "chainId", type: "felt" },
  ],
  OutsideExecution: [
    { name: "caller", type: "felt" },
    { name: "nonce", type: "felt" },
    { name: "execute_after", type: "felt" },
    { name: "execute_before", type: "felt" },
    { name: "calls_len", type: "felt" },
    { name: "calls", type: "OutsideCall*" },
  ],
  OutsideCall: [
    { name: "to", type: "felt" },
    { name: "selector", type: "felt" },
    { name: "calldata_len", type: "felt" },
    { name: "calldata", type: "felt*" },
  ],
};

const typesRev1 = {
  StarknetDomain: [
    { name: "name", type: "shortstring" },
    { name: "version", type: "shortstring" },
    { name: "chainId", type: "shortstring" },
    { name: "revision", type: "shortstring" },
  ],
  OutsideExecution: [
    { name: "Caller", type: "ContractAddress" },
    { name: "Nonce", type: "felt" },
    { name: "Execute After", type: "u128" },
    { name: "Execute Before", type: "u128" },
    { name: "Calls", type: "Call*" },
  ],
  Call: [
    { name: "To", type: "ContractAddress" },
    { name: "Selector", type: "selector" },
    { name: "Calldata", type: "felt*" },
  ],
};

function getDomain(chainId: string, revision: TypedDataRevision) {
  if (revision == TypedDataRevision.ACTIVE) {
    // WARNING! Version and revision are encoded as numbers in the StarkNetDomain type and not as shortstring
    // This is due to a bug in the Braavos implementation, and has been kept for compatibility
    return {
      name: "Account.execute_from_outside",
      version: "2",
      chainId: chainId,
      revision: "1",
    };
  }
  return {
    name: "Account.execute_from_outside",
    version: "1",
    chainId: chainId,
  };
}

export interface OutsideExecution {
  caller: string;
  nonce: num.BigNumberish;
  execute_after: num.BigNumberish;
  execute_before: num.BigNumberish;
  calls: OutsideCall[];
}

export interface OutsideCall {
  to: string;
  selector: num.BigNumberish;
  calldata: RawArgs;
}

export function getOutsideCall(call: Call): OutsideCall {
  return {
    to: call.contractAddress,
    selector: hash.getSelectorFromName(call.entrypoint),
    calldata: call.calldata ?? [],
  };
}

export function getTypedDataHash(
  outsideExecution: OutsideExecution,
  accountAddress: num.BigNumberish,
  chainId: string,
  revision: TypedDataRevision,
): string {
  return typedData.getMessageHash(getTypedData(outsideExecution, chainId, revision), accountAddress);
}

export function getTypedData(outsideExecution: OutsideExecution, chainId: string, revision: TypedDataRevision) {
  if (revision == TypedDataRevision.ACTIVE) {
    return {
      types: typesRev1,
      primaryType: "OutsideExecution",
      domain: getDomain(chainId, revision),
      message: {
        Caller: outsideExecution.caller,
        Nonce: outsideExecution.nonce,
        "Execute After": outsideExecution.execute_after,
        "Execute Before": outsideExecution.execute_before,
        Calls: outsideExecution.calls.map(call => {
          return {
            To: call.to,
            Selector: call.selector,
            Calldata: call.calldata,
          };
        }),
      },
    };
  }

  return {
    types: typesRev0,
    primaryType: "OutsideExecution",
    domain: getDomain(chainId, revision),
    message: {
      ...outsideExecution,
      calls_len: outsideExecution.calls.length,
      calls: outsideExecution.calls.map(call => {
        return {
          ...call,
          calldata_len: call.calldata.length,
          calldata: call.calldata,
        };
      }),
    },
  };
}

export async function getOutsideExecutionCall(
  outsideExecution: OutsideExecution,
  multisigAcountAddress: string,
  strkAccount: AccountInterface,
  revision: TypedDataRevision,
  chainId: string,
  isEthAddress: boolean,
  ethAddress: string,
  strkPubKey: string,
): Promise<{
  contractAddress: string;
  entrypoint: string;
  calldata: {
    signature: any;
    outsideExecution: any;
    calldata: any;
  };
}> {
  const currentTypedData = getTypedData(outsideExecution, chainId, revision);

  let signature;
  let normalizedSig;

  console.log("isEthAddress", isEthAddress);
  if (isEthAddress) {
    console.log("ETH SIGNER IS SIGNING");
    signature = await signMessageMultisig(ethAddress!, multisigAcountAddress, currentTypedData);
    const ethSig = EthersSignature.from(signature[1]?.signature as string);
    normalizedSig = normalizeSecpK1Signature({
      r: BigInt(ethSig.r),
      s: BigInt(ethSig.s),
      recovery: ethSig.yParity ? 1 : 0,
    });
  } else {
    signature = await strkSignMessageMultisig(
      strkAccount.address,
      strkAccount,
      BigInt(strkPubKey),
      multisigAcountAddress,
      currentTypedData,
    );

    const r = signature[2];
    const s = signature[3];

    console.log(signature);

    return {
      contractAddress: multisigAcountAddress,
      entrypoint: revision == TypedDataRevision.ACTIVE ? "execute_from_outside_v2" : "execute_from_outside",
      calldata: {
        signature,
        outsideExecution: currentTypedData,
        calldata: CallData.compile({
          outside_execution: outsideExecution,
          signature: [
            1,
            0, // SignerType.Starknet
            cairo.felt(strkPubKey), // pub_key
            r, // r
            s, // s
          ],
        }),
      },
    };
  }

  return {
    contractAddress: multisigAcountAddress,
    entrypoint: revision == TypedDataRevision.ACTIVE ? "execute_from_outside_v2" : "execute_from_outside",
    calldata: {
      signature,
      outsideExecution: currentTypedData,
      calldata: CallData.compile({
        outside_execution: outsideExecution,
        signature: [
          1, // signer length
          3, // SignerType.Eip191
          ethAddress, // eth_address
          uint256.bnToUint256(normalizedSig.r).low, // r low
          uint256.bnToUint256(normalizedSig.r).high, // r high
          uint256.bnToUint256(normalizedSig.s).low, // s low
          uint256.bnToUint256(normalizedSig.s).high, // s high
          normalizedSig.yParity ? 1 : 0, // y_parity,
        ],
      }),
    },
  };
}

export const signTransactionMultisig = async (
  connectedAddress: string,
  deployedMultisigAddress: string,
  calls: Array<Call>,
  gasFeeAmount?: bigint,
): Promise<[any, bigint]> => {
  const provider = new RpcProvider({ nodeUrl: process.env.NEXT_PUBLIC_PROVIDER_URL });

  const transactionVersion = RPC.ETransactionVersion.V2;
  const owner = new Eip191KeyPairMultisigMetamask(BigInt(connectedAddress), async (messageBytes: Uint8Array) => {
    const walletClient = createWalletClient({
      chain: mainnet,
      transport: custom(window.ethereum),
    });
    try {
      const signature = await walletClient.signMessage({
        account: connectedAddress as `0x${string}`,
        message: { raw: messageBytes },
      });

      // Parse the signature
      //   const ethSig = EthersSignature.from(signature);
      //   const normalizedSig = normalizeSecpK1Signature({
      //     r: BigInt(ethSig.r),
      //     s: BigInt(ethSig.s),
      //     recovery: ethSig.yParity ? 1 : 0,
      //   });
      //   return normalizedSig;

      return {
        signature: signature,
        messageBytes: messageBytes,
      };
    } catch (error) {
      console.error("Signing error:", error);
      throw error;
    }
  });
  const signer = new ArgentSigner(owner as any);

  const account = new ArgentAccountWithoutExecute(
    provider,
    deployedMultisigAddress,
    owner.signer as any,
    "1",
    transactionVersion,
  );
  account.signer = signer;

  // estimate gas
  const fee = await account.estimateInvokeFee(calls);

  const adjustedMaxFee = gasFeeAmount != null ? gasFeeAmount : fee?.suggestedMaxFee * BigInt(10);

  // paymaster
  const signature = await account.execute(calls, {
    skipValidate: true,
    maxFee: adjustedMaxFee,
  });

  return [signature, adjustedMaxFee];
};

export const signMessageMultisig = async (
  connectedAddress: string,
  deployedMultisigAddress: string,
  typedData: TypedData,
) => {
  const provider = new RpcProvider({ nodeUrl: process.env.NEXT_PUBLIC_PROVIDER_URL });

  const transactionVersion = RPC.ETransactionVersion.V2;
  const owner = new Eip191KeyPairMultisigMetamask(BigInt(connectedAddress), async (messageBytes: Uint8Array) => {
    const walletClient = createWalletClient({
      chain: mainnet,
      transport: custom(window.ethereum),
    });
    try {
      const signature = await walletClient.signMessage({
        account: connectedAddress as `0x${string}`,
        message: { raw: messageBytes },
      });

      // Parse the signature
      //   const ethSig = EthersSignature.from(signature);
      //   const normalizedSig = normalizeSecpK1Signature({
      //     r: BigInt(ethSig.r),
      //     s: BigInt(ethSig.s),
      //     recovery: ethSig.yParity ? 1 : 0,
      //   });
      //   return normalizedSig;

      return {
        signature: signature,
        messageBytes: messageBytes,
      };
    } catch (error) {
      console.error("Signing error:", error);
      throw error;
    }
  });
  const signer = new ArgentSigner(owner as any);

  const account = new ArgentAccountWithoutExecute(
    provider,
    deployedMultisigAddress,
    owner.signer as any,
    "1",
    transactionVersion,
  );
  account.signer = signer;

  const signature: any = await account.signMessage(typedData);

  return signature;
};

export const strkSignMessageMultisig = async (
  connectedAddress: string,
  connectedStrkAccount: AccountInterface,
  connectedStrkPubKey: bigint,
  deployedMultisigAddress: string,
  typedData: TypedData,
) => {
  const provider = new RpcProvider({ nodeUrl: process.env.NEXT_PUBLIC_PROVIDER_URL });

  const transactionVersion = RPC.ETransactionVersion.V2;
  const owner = new BraavosStrkKeyPairMultisigMetamask(connectedAddress, connectedStrkPubKey, connectedStrkAccount);
  const signer = new ArgentSignerStrk(owner as any);
  console.log("owner guid", num.toHex(owner.guid));
  const account = new ArgentAccountWithoutExecute(
    provider,
    deployedMultisigAddress,
    owner.signer as any,
    "1",
    transactionVersion,
  );
  account.signer = signer;

  const signature: any = await account.signMessage(typedData);

  return signature;
};
