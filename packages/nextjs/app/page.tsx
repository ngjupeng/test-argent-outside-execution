"use client";

import { useState } from "react";
import { StarknetChainId } from "../utils/constant";
import { getOutsideExecutionCall, getTypedData } from "../utils/outsideExecution";
import { SignerType, randomStarknetKeyPair, signerTypeToCustomEnum } from "../utils/signer";
import { useAccount as useStrkAccount } from "@scaffold-stark-2/hooks/useAccount";
import { universalStrkAddress } from "@scaffold-stark-2/utils/Constants";
import { TypedDataRevision } from "@starknet-io/types-js";
import toast from "react-hot-toast";
import { Account, CallData, RPC, RawArgs, RpcProvider, hash, num, shortString } from "starknet";
import { parseEther } from "viem";
import { useEthStarkAccount } from "~~/dynamic/hooks";

interface OutsideCall {
  to: string;
  selector: num.BigNumberish;
  calldata: RawArgs;
}

interface OutsideExecution {
  caller: string;
  nonce: num.BigNumberish;
  execute_after: num.BigNumberish;
  execute_before: num.BigNumberish;
  calls: OutsideCall[];
}

const yourAddress = "";
const yourPrivateKey = "";
const TESTNET_URL = "https://starknet-sepolia.blastapi.io/64168c77-3fa5-4e1e-9fe4-41675d212522/rpc/v0_7";
const YOUR_STARKNET_ACCOUNT_PUBLIC_KEY = "0x44d6cAAC62A593A53931E2DB6124c9045f78345c"; // this is from braavos

// get timestamp now
const currentTime = Math.floor(Date.now() / 1000);

const outsideExecution: OutsideExecution = {
  caller: shortString.encodeShortString("ANY_CALLER"),
  nonce: String(randomStarknetKeyPair().publicKey),
  execute_after: 0,
  execute_before: currentTime + 10000,
  calls: [
    {
      to: universalStrkAddress, // Use your target contract address
      selector: hash.getSelectorFromName("transfer"), // The function you want to call
      calldata: CallData.compile({
        // Properly format the calldata
        recipient: "0x0207Aa63B0364Df37e11b8EDc0529E1d4A0ab5C0a720f4Ea6c945a5E8054Eb40", // Your recipient address
        amount: parseEther("0.0001"),
      }),
    },
  ],
};

const DeployMultisig = () => {
  const { address: accountAddress } = useEthStarkAccount();
  const { account: accountStrk } = useStrkAccount();
  const isEthAddress = (address: string) => {
    return address.length === 42 && address.startsWith("0x");
  };

  const handleDeployArgentMultisig = async (addressesEth: string[], addressesStrk: string[]) => {
    const ARGENT_MULTISIG_CLASS_HASH = "0x07aeca3456816e3b833506d7cc5c1313d371fbdb0ae95ee70af72a4ddbf42594";
    let multisigAddress = "";

    try {
      const constructorCalldataMultisig = CallData.compile({
        new_threshold: BigInt(addressesEth.length + addressesStrk.length),
        // new_threshold: BigInt(addressesEth.length),
        signers: [
          ...addressesEth.map(address =>
            signerTypeToCustomEnum(SignerType.Eip191, {
              signer: address,
            }),
          ),
          ...addressesStrk.map(address =>
            signerTypeToCustomEnum(SignerType.Starknet, {
              signer: address,
            }),
          ),
        ],
      });

      const provider = new RpcProvider({ nodeUrl: TESTNET_URL });

      const deployAccountPayloadMultisig = {
        classHash: ARGENT_MULTISIG_CLASS_HASH,
        constructorCalldata: constructorCalldataMultisig,
        salt: String(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)),
        unique: false,
      };
      const accountAX = new Account(provider, yourAddress, yourPrivateKey);
      const udcCallsMultisig = await accountAX.buildUDCContractPayload(deployAccountPayloadMultisig);

      const responseMultisig = await accountAX.execute(udcCallsMultisig);
      console.log("Transaction Hash Multisig:", responseMultisig.transaction_hash);
      const receipt: any = await provider.waitForTransaction(responseMultisig.transaction_hash);
      const multisigAddress = receipt?.events[0]?.from_address;

      return multisigAddress;
    } catch (error) {
      console.log(error);
    }
    console.log("MULTISIG ADDRESS", multisigAddress);
  };

  const handleSignTransactionUsingOutsideExecutionMetamask = async () => {
    try {
      if (!accountAddress) return toast.error("No account address found");

      const provider = new RpcProvider({ nodeUrl: TESTNET_URL });
      let account;
      const transactionVersion = RPC.ETransactionVersion.V2;

      const multisigAddress = await handleDeployArgentMultisig([accountAddress], []);
      console.log("MULTISIG ADDRESS", multisigAddress);

      account = accountStrk;

      const outsideExecutionCall = await getOutsideExecutionCall(
        outsideExecution,
        multisigAddress,
        account!,
        TypedDataRevision.ACTIVE,
        StarknetChainId.SN_SEPOLIA,
        isEthAddress(accountAddress),
        accountAddress,
        YOUR_STARKNET_ACCOUNT_PUBLIC_KEY,
      );

      console.log("OUTSIDE EXECUTION CALL", outsideExecutionCall);

      const accountAX = new Account(provider, yourAddress, yourPrivateKey, "1", transactionVersion);
      const response = await accountAX.execute({
        contractAddress: outsideExecutionCall.contractAddress,
        entrypoint: outsideExecutionCall.entrypoint,
        calldata: outsideExecutionCall.calldata.calldata,
      });

      console.log("Outside execution response:", response);
    } catch (error) {
      console.log(error);
    }
  };

  const handleSignTransactionUsingOutsideExecutionBraavos = async () => {
    try {
      if (!accountAddress) return toast.error("No account address found");

      const provider = new RpcProvider({ nodeUrl: TESTNET_URL });
      let account;

      const multisigAddress = await handleDeployArgentMultisig([], [YOUR_STARKNET_ACCOUNT_PUBLIC_KEY]);
      console.log("MULTISIG ADDRESS", multisigAddress);

      account = accountStrk;

      const outsideExecutionCall = await getOutsideExecutionCall(
        outsideExecution,
        multisigAddress,
        account!,
        TypedDataRevision.ACTIVE,
        StarknetChainId.SN_SEPOLIA,
        isEthAddress(accountAddress),
        accountAddress,
        YOUR_STARKNET_ACCOUNT_PUBLIC_KEY,
      );

      console.log("OUTSIDE EXECUTION CALL", outsideExecutionCall);

      // setOutsideExecutionCall(outsideExecutionCall);

      const accountAX = new Account(provider, yourAddress, yourPrivateKey);
      const response = await accountAX.execute({
        contractAddress: outsideExecutionCall.contractAddress,
        entrypoint: outsideExecutionCall.entrypoint,
        calldata: outsideExecutionCall.calldata.calldata,
      });
      console.log("Outside execution response:", response);
    } catch (error) {
      console.log(error);
    }
  };

  const handleSignOutsideExecutionMessage = async () => {
    try {
      const currentTypedData = getTypedData(outsideExecution, StarknetChainId.SN_SEPOLIA, TypedDataRevision.ACTIVE);

      const signature = accountStrk?.signMessage(currentTypedData);
      console.log("Signature:", signature);
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div>
      <div className="flex flex-col items-center gap-6 p-8 text-white">
        <h1 className="text-2xl font-bold">Deploy Multisig Account for STRK</h1>
        {/* Deploy Button */}
        <button
          onClick={() => handleDeployArgentMultisig([YOUR_STARKNET_ACCOUNT_PUBLIC_KEY], [])}
          //   disabled={isDeploying || addresses.length === 0}
          className="btn btn-primary btn-lg mt-4"
        >
          Deploy Argent Multisig That Contain Braavos Account
        </button>

        <button onClick={handleSignTransactionUsingOutsideExecutionMetamask} className="btn btn-primary btn-lg mt-4">
          Execute Outside Execution Metamask (PLEASE FIRST CONNECT METAMASK)
        </button>
        <button onClick={handleSignTransactionUsingOutsideExecutionBraavos} className="btn btn-primary btn-lg mt-4">
          Execute Outside Execution Braavos
        </button>

        <button onClick={handleSignOutsideExecutionMessage} className="btn btn-primary btn-lg mt-4">
          Just signing outside execution message Argent
        </button>
      </div>
      <hr />
    </div>
  );
};

export default DeployMultisig;
