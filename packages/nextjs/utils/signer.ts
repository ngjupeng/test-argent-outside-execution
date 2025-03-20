import { FeeMarginPercentage, ZERO } from "./constant";
import { normalizeSecpK1Signature } from "./secp256";
import { Signature as EthersSignature } from "ethers";
import {
  Abi,
  Account,
  AccountInterface,
  AllowArray,
  BigNumberish,
  CairoCustomEnum,
  CairoOption,
  CairoOptionVariant,
  Call,
  CallData,
  Calldata,
  Contract,
  DeclareSignerDetails,
  DeployAccountContractPayload,
  DeployAccountSignerDetails,
  DeployContractResponse,
  FeeEstimate,
  InvocationsSignerDetails,
  InvokeFunctionResponse,
  RPC,
  Signature,
  SignerInterface,
  TransactionType,
  UniversalDetails,
  V2DeclareSignerDetails,
  V2DeployAccountSignerDetails,
  V2InvocationsSignerDetails,
  V3DeclareSignerDetails,
  V3DeployAccountSignerDetails,
  V3InvocationsSignerDetails,
  ec,
  encode,
  hash,
  num,
  shortString,
  stark,
  transaction,
  typedData,
  uint256,
} from "starknet";

export type ValuesType<T extends ReadonlyArray<any> | ArrayLike<any> | Record<any, any>> = T extends ReadonlyArray<any>
  ? T[number]
  : T extends ArrayLike<any>
  ? T[number]
  : T extends object
  ? T[keyof T]
  : never;

export const EDataAvailabilityMode = {
  L1: "L1",
  L2: "L2",
} as const;

export type EDataAvailabilityMode = ValuesType<typeof EDataAvailabilityMode>;

export const ETransactionVersion = {
  V0: "0x0",
  V1: "0x1",
  V2: "0x2",
  V3: "0x3",
  F0: "0x100000000000000000000000000000000",
  F1: "0x100000000000000000000000000000001",
  F2: "0x100000000000000000000000000000002",
  F3: "0x100000000000000000000000000000003",
} as const;

export type ETransactionVersion = ValuesType<typeof ETransactionVersion>;
export type u64 = string;
export type u128 = string;
export type RESOURCE_BOUNDS = {
  max_amount: u64;
  max_price_per_unit: u128;
};
export type RESOURCE_BOUNDS_MAPPING = {
  l1_gas: RESOURCE_BOUNDS;
  l2_gas: RESOURCE_BOUNDS;
};

export type ResourceBounds = RESOURCE_BOUNDS_MAPPING;

/**
 * This class allows to easily implement custom signers by overriding the `signRaw` method.
 * This is based on Starknet.js implementation of Signer, but it delegates the actual signing to an abstract function
 */
export abstract class RawSigner implements SignerInterface {
  abstract signRaw(messageHash: string): Promise<string[]>;

  public async getPubKey(): Promise<string> {
    throw new Error("This signer allows multiple public keys");
  }

  public async signMessage(typedDataArgument: typeof typedData.TypedData, accountAddress: string): Promise<Signature> {
    const messageHash = typedData.getMessageHash(typedDataArgument, accountAddress);
    console.log("I AM HERE");
    return this.signRaw(messageHash);
  }

  public async signTransaction(transactions: Call[], details: InvocationsSignerDetails): Promise<Signature> {
    console.log("signTransaction called with transactions:", transactions);

    const compiledCalldata = transaction.getExecuteCalldata(transactions, details.cairoVersion);
    let msgHash;

    // TODO: How to do generic union discriminator for all like this
    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
      });
      console.log("Sign transaction hash v2", msgHash, {
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
      console.log("Sign transaction hash v3", msgHash);
    } else {
      throw new Error("unsupported signTransaction version");
    }
    return await this.signRaw(msgHash);
  }

  public async signDeployAccountTransaction(details: DeployAccountSignerDetails): Promise<Signature> {
    const compiledConstructorCalldata = CallData.compile(details.constructorCalldata);
    /*     const version = BigInt(details.version).toString(); */
    let msgHash;

    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        constructorCalldata: compiledConstructorCalldata,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        compiledConstructorCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error(`unsupported signDeployAccountTransaction version: ${details.version}}`);
    }

    return await this.signRaw(msgHash);
  }

  public async signDeclareTransaction(
    // contractClass: ContractClass,  // Should be used once class hash is present in ContractClass
    details: DeclareSignerDetails,
  ): Promise<Signature> {
    let msgHash;

    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error("unsupported signDeclareTransaction version");
    }

    return await this.signRaw(msgHash);
  }
}

export abstract class StrkRawSigner implements SignerInterface {
  abstract signRaw(typedDataArgument: typeof typedData.TypedData | string): Promise<string[]>;

  public async getPubKey(): Promise<string> {
    throw new Error("This signer allows multiple public keys");
  }

  public async signMessage(typedDataArgument: typeof typedData.TypedData, accountAddress: string): Promise<Signature> {
    return this.signRaw(typedDataArgument);
  }

  public async signTransaction(transactions: Call[], details: InvocationsSignerDetails): Promise<Signature> {
    console.log("signTransaction called with transactions:", transactions);

    const compiledCalldata = transaction.getExecuteCalldata(transactions, details.cairoVersion);
    let msgHash;

    // TODO: How to do generic union discriminator for all like this
    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
      });
      console.log("Sign transaction hash v2", msgHash, {
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
      console.log("Sign transaction hash v3", msgHash);
    } else {
      throw new Error("unsupported signTransaction version");
    }
    return await this.signRaw(msgHash);
  }

  public async signDeployAccountTransaction(details: DeployAccountSignerDetails): Promise<Signature> {
    const compiledConstructorCalldata = CallData.compile(details.constructorCalldata);
    /*     const version = BigInt(details.version).toString(); */
    let msgHash;

    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        constructorCalldata: compiledConstructorCalldata,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        compiledConstructorCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error(`unsupported signDeployAccountTransaction version: ${details.version}}`);
    }

    return await this.signRaw(msgHash);
  }

  public async signDeclareTransaction(
    // contractClass: ContractClass,  // Should be used once class hash is present in ContractClass
    details: DeclareSignerDetails,
  ): Promise<Signature> {
    let msgHash;

    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error("unsupported signDeclareTransaction version");
    }

    return await this.signRaw(msgHash);
  }
}

export class MultisigSigner extends RawSigner {
  constructor(public keys: KeyPair[]) {
    super();
  }

  async signRaw(messageHash: string): Promise<string[]> {
    const keys = [];
    for (const key of this.keys) {
      keys.push(await key.signRaw(messageHash));
    }
    return [keys.length.toString(), keys.flat()].flat();
  }
}

export class StrkMultisigSigner extends StrkRawSigner {
  constructor(public keys: KeyPair[]) {
    super();
  }

  async signRaw(messageHash: string): Promise<string[]> {
    const keys = [];
    for (const key of this.keys) {
      keys.push(await key.signRaw(messageHash));
    }
    return [keys.length.toString(), keys.flat()].flat();
  }
}

export class ArgentSigner extends MultisigSigner {
  constructor(public owner: KeyPair = randomStarknetKeyPair(), public guardian?: KeyPair) {
    const signers = [owner];
    if (guardian) {
      signers.push(guardian);
    }
    super(signers);
  }
}

export class ArgentSignerStrk extends StrkMultisigSigner {
  constructor(public owner: KeyPair = randomStarknetKeyPair(), public guardian?: KeyPair) {
    const signers = [owner];
    if (guardian) {
      signers.push(guardian);
    }
    super(signers);
  }
}

export abstract class KeyPair extends RawSigner {
  abstract get signer(): CairoCustomEnum;
  abstract get guid(): bigint;
  abstract get storedValue(): bigint;

  public get compiledSigner(): Calldata {
    return CallData.compile([this.signer]);
  }

  public get signerAsOption() {
    return new CairoOption(CairoOptionVariant.Some, {
      signer: this.signer,
    });
  }
  public get compiledSignerAsOption() {
    return CallData.compile([this.signerAsOption]);
  }
}

export abstract class KeyPairArgent extends RawSigner {
  abstract get signer(): CairoCustomEnum;
  abstract get guid(): Promise<bigint>;

  public get compiledSigner(): Calldata {
    return CallData.compile([this.signer]);
  }

  public get signerAsOption() {
    return new CairoOption(CairoOptionVariant.Some, {
      signer: this.signer,
    });
  }
  public get compiledSignerAsOption() {
    return CallData.compile([this.signerAsOption]);
  }
}

export class StarknetKeyPair extends KeyPair {
  pk: string;

  constructor(pk?: string | bigint) {
    super();
    this.pk = pk ? num.toHex(pk) : `0x${encode.buf2hex(ec.starkCurve.utils.randomPrivateKey())}`;
  }

  public get privateKey(): string {
    return this.pk;
  }

  public get publicKey() {
    return BigInt(ec.starkCurve.getStarkKey(this.pk));
  }

  public get guid() {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Starknet Signer"), this.publicKey));
  }

  public get storedValue() {
    return this.publicKey;
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Starknet, { signer: this.publicKey });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    const { r, s } = ec.starkCurve.sign(messageHash, this.pk);
    return starknetSignatureType(this.publicKey, r, s);
  }
}

// export class StarknetKeyPairWithoutPk extends KeyPairArgent {
//   constructor(public account: AccountInterface) {
//     super();
//   }

//   public async get guid() {
//     let contract = new Contract(ARGENT_ACCOUNT_ABI, this.account.address, this.account);
//     const guid = await contract.get_owner_guid();
//     return guid;
//   }

//   public get signer(): CairoCustomEnum {
//     return signerTypeToCustomEnum(SignerType.Starknet, { signer: this.publicKey });
//   }

//   public async signRaw(messageHash: string): Promise<string[]> {
//     const { r, s } = ec.starkCurve.sign(messageHash, this.pk);
//     return starknetSignatureType(this.publicKey, r, s);
//   }
// }

export class EstimateStarknetKeyPair extends KeyPair {
  readonly pubKey: bigint;

  constructor(pubKey: bigint) {
    super();
    this.pubKey = pubKey;
  }

  public get privateKey(): string {
    throw new Error("EstimateStarknetKeyPair does not have a private key");
  }

  public get publicKey() {
    return this.pubKey;
  }

  public get guid() {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Starknet Signer"), this.publicKey));
  }

  public get storedValue() {
    return this.publicKey;
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Starknet, { signer: this.publicKey });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    const fakeR = "0x6cefb49a1f4eb406e8112db9b8cdf247965852ddc5ca4d74b09e42471689495";
    const fakeS = "0x25760910405a052b7f08ec533939c54948bc530c662c5d79e8ff416579087f7";
    return starknetSignatureType(this.publicKey, fakeR, fakeS);
  }
}

export function starknetSignatureType(
  signer: bigint | number | string,
  r: bigint | number | string,
  s: bigint | number | string,
) {
  return CallData.compile([signerTypeToCustomEnum(SignerType.Starknet, { signer, r, s })]);
}

export function zeroStarknetSignatureType() {
  return signerTypeToCustomEnum(SignerType.Starknet, { signer: 0 });
}

// reflects the signer type in signer_signature.cairo
// needs to be updated for the signer types
// used to convert signertype to guid
export enum SignerType {
  Starknet,
  Secp256k1,
  Secp256r1,
  Eip191,
  Webauthn,
}

export function signerTypeToCustomEnum(signerType: SignerType, value: any): CairoCustomEnum {
  const contents = {
    Starknet: undefined,
    Secp256k1: undefined,
    Secp256r1: undefined,
    Eip191: undefined,
    Webauthn: undefined,
  };

  if (signerType === SignerType.Starknet) {
    contents.Starknet = value;
  } else if (signerType === SignerType.Secp256k1) {
    contents.Secp256k1 = value;
  } else if (signerType === SignerType.Secp256r1) {
    contents.Secp256r1 = value;
  } else if (signerType === SignerType.Eip191) {
    contents.Eip191 = value;
  } else if (signerType === SignerType.Webauthn) {
    contents.Webauthn = value;
  } else {
    throw new Error(`Unknown SignerType`);
  }

  return new CairoCustomEnum(contents);
}

export function sortByGuid(keys: KeyPair[]) {
  return keys.sort((n1, n2) => (n1.guid < n2.guid ? -1 : 1));
}

export const randomStarknetKeyPair = () => new StarknetKeyPair();
export const randomStarknetKeyPairs = (length: number) => Array.from({ length }, randomStarknetKeyPair);

export class ArgentAccount extends Account {
  // Increase the gas limit by 30% to avoid failures due to gas estimation being too low with tx v3 and transactions the use escaping
  override async deployAccount(
    payload: DeployAccountContractPayload,
    details?: UniversalDetails,
  ): Promise<DeployContractResponse> {
    details ||= {};
    if (!details.skipValidate) {
      details.skipValidate = false;
    }
    return super.deployAccount(payload, details);
  }

  override execute(
    transactions: AllowArray<Call>,
    abis?: Abi[],
    transactionsDetail?: UniversalDetails,
  ): Promise<InvokeFunctionResponse>;
  override execute(
    transactions: AllowArray<Call>,
    transactionsDetail?: UniversalDetails,
  ): Promise<InvokeFunctionResponse>;
  override async execute(
    transactions: AllowArray<Call>,
    abisOrDetails?: Abi[] | UniversalDetails,
    transactionsDetail?: UniversalDetails,
  ): Promise<InvokeFunctionResponse> {
    const details = (transactionsDetail || abisOrDetails || {}) as UniversalDetails;
    details.skipValidate ??= false;
    // if (details.resourceBounds) {
    //   return super.execute(transactions, details);
    // }
    // let estimate = await this.estimateFee(transactions, details);
    // // estimate.suggestedMaxFee = (estimate.suggestedMaxFee * BigInt(150)) / BigInt(100); // 1.5x multiplication
    // estimate.suggestedMaxFee = BigInt(96677799942448); // 1.5x multiplication
    // console.log("estimate", estimate);
    return super.execute(transactions, abisOrDetails as any, details);
  }
}

export function toBigInt(value: BigNumberish): bigint {
  return BigInt(value);
}

export function isBigInt(value: any): value is bigint {
  return typeof value === "bigint";
}

export function addPercent(number: BigNumberish, percent: number): bigint {
  const bigIntNum = BigInt(number);
  return bigIntNum + (bigIntNum * BigInt(percent)) / 100n;
}

export const isUndefined = (value: unknown): value is undefined => {
  return typeof value === "undefined" || value === undefined;
};

export function removeHexPrefix(hex: string): string {
  return hex.replace(/^0x/i, "");
}

export function addHexPrefix(hex: string): string {
  return `0x${removeHexPrefix(hex)}`;
}

export function toHex(value: BigNumberish): string {
  return addHexPrefix(toBigInt(value).toString(16));
}

export function toTransactionVersion(
  defaultVersion: BigNumberish,
  providedVersion?: BigNumberish,
): ETransactionVersion {
  const providedVersion0xs = providedVersion ? toHex(providedVersion) : undefined;
  const defaultVersion0xs = toHex(defaultVersion);

  if (providedVersion && !Object.values(ETransactionVersion).includes(providedVersion0xs as any)) {
    throw Error(`providedVersion ${providedVersion} is not ETransactionVersion`);
  }
  if (!Object.values(ETransactionVersion).includes(defaultVersion0xs as any)) {
    throw Error(`defaultVersion ${defaultVersion} is not ETransactionVersion`);
  }

  return (providedVersion ? providedVersion0xs : defaultVersion0xs) as ETransactionVersion;
}

export function estimateFeeToBounds(
  estimate: FeeEstimate | 0n,
  amountOverhead: number = FeeMarginPercentage.L1_BOUND_MAX_AMOUNT,
  priceOverhead: number = FeeMarginPercentage.L1_BOUND_MAX_PRICE_PER_UNIT,
): ResourceBounds {
  if (isBigInt(estimate)) {
    return {
      l2_gas: { max_amount: "0x0", max_price_per_unit: "0x0" },
      l1_gas: { max_amount: "0x0", max_price_per_unit: "0x0" },
    };
  }

  if (isUndefined(estimate.gas_consumed) || isUndefined(estimate.gas_price)) {
    throw Error("estimateFeeToBounds: estimate is undefined");
  }

  const maxUnits =
    estimate.data_gas_consumed !== undefined && estimate.data_gas_price !== undefined // RPC v0.7
      ? toHex(addPercent(BigInt(estimate.overall_fee) / BigInt(estimate.gas_price), amountOverhead))
      : toHex(addPercent(estimate.gas_consumed, amountOverhead));
  const maxUnitPrice = toHex(addPercent(estimate.gas_price, priceOverhead));
  return {
    l2_gas: { max_amount: "0x0", max_price_per_unit: "0x0" },
    l1_gas: { max_amount: maxUnits, max_price_per_unit: maxUnitPrice },
  };
}

type V3Details = Required<
  Pick<
    UniversalDetails,
    | "tip"
    | "paymasterData"
    | "accountDeploymentData"
    | "nonceDataAvailabilityMode"
    | "feeDataAvailabilityMode"
    | "resourceBounds"
  >
>;

export function v3Details(details: UniversalDetails): V3Details {
  return {
    tip: details.tip || 0,
    paymasterData: details.paymasterData || [],
    accountDeploymentData: details.accountDeploymentData || [],
    nonceDataAvailabilityMode: details.nonceDataAvailabilityMode || EDataAvailabilityMode.L1,
    feeDataAvailabilityMode: details.feeDataAvailabilityMode || EDataAvailabilityMode.L1,
    resourceBounds: details.resourceBounds ?? estimateFeeToBounds(ZERO),
  };
}

export class ArgentAccountWithoutExecute extends Account {
  // Increase the gas limit by 30% to avoid failures due to gas estimation being too low with tx v3 and transactions the use escaping
  override async deployAccount(
    payload: DeployAccountContractPayload,
    details?: UniversalDetails,
  ): Promise<DeployContractResponse> {
    details ||= {};
    if (!details.skipValidate) {
      details.skipValidate = false;
    }
    return super.deployAccount(payload, details);
  }

  override execute(
    transactions: AllowArray<Call>,
    abis?: Abi[],
    transactionsDetail?: UniversalDetails,
  ): Promise<InvokeFunctionResponse>;
  override execute(
    transactions: AllowArray<Call>,
    transactionsDetail?: UniversalDetails,
  ): Promise<InvokeFunctionResponse>;
  override async execute(
    transactions: AllowArray<Call>,
    abisOrDetails?: Abi[] | UniversalDetails,
    transactionsDetail?: UniversalDetails,
  ): Promise<any> {
    const details = (transactionsDetail || abisOrDetails || {}) as UniversalDetails;
    const calls = Array.isArray(transactions) ? transactions : [transactions];
    const nonce = toBigInt(details.nonce ?? (await this.getNonce()));
    const version = toTransactionVersion(
      this.getPreferredVersion(ETransactionVersion.V1, ETransactionVersion.V3), // TODO: does this depend on cairo version ?
      details.version,
    );

    const estimate = await this.getUniversalSuggestedFee(
      version,
      { type: TransactionType.INVOKE, payload: transactions },
      {
        ...details,
        version,
      },
    );

    const chainId = await this.getChainId();

    const signerDetails: InvocationsSignerDetails = {
      ...v3Details(details),
      resourceBounds: estimate.resourceBounds,
      walletAddress: this.address,
      nonce,
      maxFee: estimate.maxFee,
      version,
      chainId,
      cairoVersion: await this.getCairoVersion(),
    };
    const signature = await this.signer.signTransaction(calls, signerDetails);
    return signature;
  }
}

export const parseEthSignature = (signature: string, address: string) => {
  const ethSig = EthersSignature.from(signature);
  const normalizedSig = normalizeSecpK1Signature({
    r: BigInt(ethSig.r),
    s: BigInt(ethSig.s),
    recovery: ethSig.yParity ? 1 : 0,
  });
  const callData = CallData.compile([
    signerTypeToCustomEnum(SignerType.Eip191, {
      ethAddress: address,
      r: uint256.bnToUint256(normalizedSig.r),
      s: uint256.bnToUint256(normalizedSig.s),
      y_parity: normalizedSig.yParity,
    }),
  ]);
  return callData;
};

export const parseEthSignatureWithoutCompile = (signature: string, address: string) => {
  const ethSig = EthersSignature.from(signature);
  const normalizedSig = normalizeSecpK1Signature({
    r: BigInt(ethSig.r),
    s: BigInt(ethSig.s),
    recovery: ethSig.yParity ? 1 : 0,
  });

  const rUint256 = uint256.bnToUint256(normalizedSig.r);
  const sUint256 = uint256.bnToUint256(normalizedSig.s);

  return signerTypeToCustomEnum(SignerType.Eip191, {
    ethAddress: address,
    r_low: rUint256.low,
    r_high: rUint256.high,
    s_low: sUint256.low,
    s_high: sUint256.high,
    y_parity: normalizedSig.yParity,
  });
};

export const ARGENT_ACCOUNT_ABI = [
  {
    name: "AccountImpl",
    type: "impl",
    interface_name: "argent::account::interface::IAccount",
  },
  {
    name: "core::array::Span::<core::felt252>",
    type: "struct",
    members: [
      {
        name: "snapshot",
        type: "@core::array::Array::<core::felt252>",
      },
    ],
  },
  {
    name: "core::starknet::account::Call",
    type: "struct",
    members: [
      {
        name: "to",
        type: "core::starknet::contract_address::ContractAddress",
      },
      {
        name: "selector",
        type: "core::felt252",
      },
      {
        name: "calldata",
        type: "core::array::Span::<core::felt252>",
      },
    ],
  },
  {
    name: "argent::account::interface::IAccount",
    type: "interface",
    items: [
      {
        name: "__validate__",
        type: "function",
        inputs: [
          {
            name: "calls",
            type: "core::array::Array::<core::starknet::account::Call>",
          },
        ],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "external",
      },
      {
        name: "__execute__",
        type: "function",
        inputs: [
          {
            name: "calls",
            type: "core::array::Array::<core::starknet::account::Call>",
          },
        ],
        outputs: [
          {
            type: "core::array::Array::<core::array::Span::<core::felt252>>",
          },
        ],
        state_mutability: "external",
      },
      {
        name: "is_valid_signature",
        type: "function",
        inputs: [
          {
            name: "hash",
            type: "core::felt252",
          },
          {
            name: "signature",
            type: "core::array::Array::<core::felt252>",
          },
        ],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
    ],
  },
  {
    name: "UpgradeableCallbackOldImpl",
    type: "impl",
    interface_name: "argent::upgrade::interface::IUpgradableCallbackOld",
  },
  {
    name: "argent::upgrade::interface::IUpgradableCallbackOld",
    type: "interface",
    items: [
      {
        name: "execute_after_upgrade",
        type: "function",
        inputs: [
          {
            name: "data",
            type: "core::array::Array::<core::felt252>",
          },
        ],
        outputs: [
          {
            type: "core::array::Array::<core::felt252>",
          },
        ],
        state_mutability: "external",
      },
    ],
  },
  {
    name: "UpgradeableCallbackImpl",
    type: "impl",
    interface_name: "argent::upgrade::interface::IUpgradableCallback",
  },
  {
    name: "argent::upgrade::interface::IUpgradableCallback",
    type: "interface",
    items: [
      {
        name: "perform_upgrade",
        type: "function",
        inputs: [
          {
            name: "new_implementation",
            type: "core::starknet::class_hash::ClassHash",
          },
          {
            name: "data",
            type: "core::array::Span::<core::felt252>",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
    ],
  },
  {
    name: "ArgentUserAccountImpl",
    type: "impl",
    interface_name: "argent::account::interface::IArgentUserAccount",
  },
  {
    name: "argent::signer::signer_signature::StarknetSigner",
    type: "struct",
    members: [
      {
        name: "pubkey",
        type: "core::zeroable::NonZero::<core::felt252>",
      },
    ],
  },
  {
    name: "core::starknet::eth_address::EthAddress",
    type: "struct",
    members: [
      {
        name: "address",
        type: "core::felt252",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::Secp256k1Signer",
    type: "struct",
    members: [
      {
        name: "pubkey_hash",
        type: "core::starknet::eth_address::EthAddress",
      },
    ],
  },
  {
    name: "core::integer::u256",
    type: "struct",
    members: [
      {
        name: "low",
        type: "core::integer::u128",
      },
      {
        name: "high",
        type: "core::integer::u128",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::Secp256r1Signer",
    type: "struct",
    members: [
      {
        name: "pubkey",
        type: "core::zeroable::NonZero::<core::integer::u256>",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::Eip191Signer",
    type: "struct",
    members: [
      {
        name: "eth_address",
        type: "core::starknet::eth_address::EthAddress",
      },
    ],
  },
  {
    name: "core::array::Span::<core::integer::u8>",
    type: "struct",
    members: [
      {
        name: "snapshot",
        type: "@core::array::Array::<core::integer::u8>",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::WebauthnSigner",
    type: "struct",
    members: [
      {
        name: "origin",
        type: "core::array::Span::<core::integer::u8>",
      },
      {
        name: "rp_id_hash",
        type: "core::zeroable::NonZero::<core::integer::u256>",
      },
      {
        name: "pubkey",
        type: "core::zeroable::NonZero::<core::integer::u256>",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::Signer",
    type: "enum",
    variants: [
      {
        name: "Starknet",
        type: "argent::signer::signer_signature::StarknetSigner",
      },
      {
        name: "Secp256k1",
        type: "argent::signer::signer_signature::Secp256k1Signer",
      },
      {
        name: "Secp256r1",
        type: "argent::signer::signer_signature::Secp256r1Signer",
      },
      {
        name: "Eip191",
        type: "argent::signer::signer_signature::Eip191Signer",
      },
      {
        name: "Webauthn",
        type: "argent::signer::signer_signature::WebauthnSigner",
      },
    ],
  },
  {
    name: "core::option::Option::<argent::signer::signer_signature::Signer>",
    type: "enum",
    variants: [
      {
        name: "Some",
        type: "argent::signer::signer_signature::Signer",
      },
      {
        name: "None",
        type: "()",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::StarknetSignature",
    type: "struct",
    members: [
      {
        name: "r",
        type: "core::felt252",
      },
      {
        name: "s",
        type: "core::felt252",
      },
    ],
  },
  {
    name: "core::bool",
    type: "enum",
    variants: [
      {
        name: "False",
        type: "()",
      },
      {
        name: "True",
        type: "()",
      },
    ],
  },
  {
    name: "core::starknet::secp256_trait::Signature",
    type: "struct",
    members: [
      {
        name: "r",
        type: "core::integer::u256",
      },
      {
        name: "s",
        type: "core::integer::u256",
      },
      {
        name: "y_parity",
        type: "core::bool",
      },
    ],
  },
  {
    name: "argent::signer::webauthn::Sha256Implementation",
    type: "enum",
    variants: [
      {
        name: "Cairo0",
        type: "()",
      },
      {
        name: "Cairo1",
        type: "()",
      },
    ],
  },
  {
    name: "argent::signer::webauthn::WebauthnSignature",
    type: "struct",
    members: [
      {
        name: "cross_origin",
        type: "core::bool",
      },
      {
        name: "client_data_json_outro",
        type: "core::array::Span::<core::integer::u8>",
      },
      {
        name: "flags",
        type: "core::integer::u8",
      },
      {
        name: "sign_count",
        type: "core::integer::u32",
      },
      {
        name: "ec_signature",
        type: "core::starknet::secp256_trait::Signature",
      },
      {
        name: "sha256_implementation",
        type: "argent::signer::webauthn::Sha256Implementation",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::SignerSignature",
    type: "enum",
    variants: [
      {
        name: "Starknet",
        type: "(argent::signer::signer_signature::StarknetSigner, argent::signer::signer_signature::StarknetSignature)",
      },
      {
        name: "Secp256k1",
        type: "(argent::signer::signer_signature::Secp256k1Signer, core::starknet::secp256_trait::Signature)",
      },
      {
        name: "Secp256r1",
        type: "(argent::signer::signer_signature::Secp256r1Signer, core::starknet::secp256_trait::Signature)",
      },
      {
        name: "Eip191",
        type: "(argent::signer::signer_signature::Eip191Signer, core::starknet::secp256_trait::Signature)",
      },
      {
        name: "Webauthn",
        type: "(argent::signer::signer_signature::WebauthnSigner, argent::signer::webauthn::WebauthnSignature)",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::SignerType",
    type: "enum",
    variants: [
      {
        name: "Starknet",
        type: "()",
      },
      {
        name: "Secp256k1",
        type: "()",
      },
      {
        name: "Secp256r1",
        type: "()",
      },
      {
        name: "Eip191",
        type: "()",
      },
      {
        name: "Webauthn",
        type: "()",
      },
    ],
  },
  {
    name: "core::option::Option::<core::felt252>",
    type: "enum",
    variants: [
      {
        name: "Some",
        type: "core::felt252",
      },
      {
        name: "None",
        type: "()",
      },
    ],
  },
  {
    name: "core::option::Option::<argent::signer::signer_signature::SignerType>",
    type: "enum",
    variants: [
      {
        name: "Some",
        type: "argent::signer::signer_signature::SignerType",
      },
      {
        name: "None",
        type: "()",
      },
    ],
  },
  {
    name: "argent::recovery::interface::LegacyEscapeType",
    type: "enum",
    variants: [
      {
        name: "None",
        type: "()",
      },
      {
        name: "Guardian",
        type: "()",
      },
      {
        name: "Owner",
        type: "()",
      },
    ],
  },
  {
    name: "argent::signer::signer_signature::SignerStorageValue",
    type: "struct",
    members: [
      {
        name: "stored_value",
        type: "core::felt252",
      },
      {
        name: "signer_type",
        type: "argent::signer::signer_signature::SignerType",
      },
    ],
  },
  {
    name: "core::option::Option::<argent::signer::signer_signature::SignerStorageValue>",
    type: "enum",
    variants: [
      {
        name: "Some",
        type: "argent::signer::signer_signature::SignerStorageValue",
      },
      {
        name: "None",
        type: "()",
      },
    ],
  },
  {
    name: "argent::recovery::interface::LegacyEscape",
    type: "struct",
    members: [
      {
        name: "ready_at",
        type: "core::integer::u64",
      },
      {
        name: "escape_type",
        type: "argent::recovery::interface::LegacyEscapeType",
      },
      {
        name: "new_signer",
        type: "core::option::Option::<argent::signer::signer_signature::SignerStorageValue>",
      },
    ],
  },
  {
    name: "argent::account::interface::Version",
    type: "struct",
    members: [
      {
        name: "major",
        type: "core::integer::u8",
      },
      {
        name: "minor",
        type: "core::integer::u8",
      },
      {
        name: "patch",
        type: "core::integer::u8",
      },
    ],
  },
  {
    name: "argent::recovery::interface::EscapeStatus",
    type: "enum",
    variants: [
      {
        name: "None",
        type: "()",
      },
      {
        name: "NotReady",
        type: "()",
      },
      {
        name: "Ready",
        type: "()",
      },
      {
        name: "Expired",
        type: "()",
      },
    ],
  },
  {
    name: "argent::account::interface::IArgentUserAccount",
    type: "interface",
    items: [
      {
        name: "__validate_declare__",
        type: "function",
        inputs: [
          {
            name: "class_hash",
            type: "core::felt252",
          },
        ],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "__validate_deploy__",
        type: "function",
        inputs: [
          {
            name: "class_hash",
            type: "core::felt252",
          },
          {
            name: "contract_address_salt",
            type: "core::felt252",
          },
          {
            name: "owner",
            type: "argent::signer::signer_signature::Signer",
          },
          {
            name: "guardian",
            type: "core::option::Option::<argent::signer::signer_signature::Signer>",
          },
        ],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "set_escape_security_period",
        type: "function",
        inputs: [
          {
            name: "new_security_period",
            type: "core::integer::u64",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "change_owner",
        type: "function",
        inputs: [
          {
            name: "signer_signature",
            type: "argent::signer::signer_signature::SignerSignature",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "change_guardian",
        type: "function",
        inputs: [
          {
            name: "new_guardian",
            type: "core::option::Option::<argent::signer::signer_signature::Signer>",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "change_guardian_backup",
        type: "function",
        inputs: [
          {
            name: "new_guardian_backup",
            type: "core::option::Option::<argent::signer::signer_signature::Signer>",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "trigger_escape_owner",
        type: "function",
        inputs: [
          {
            name: "new_owner",
            type: "argent::signer::signer_signature::Signer",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "trigger_escape_guardian",
        type: "function",
        inputs: [
          {
            name: "new_guardian",
            type: "core::option::Option::<argent::signer::signer_signature::Signer>",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "escape_owner",
        type: "function",
        inputs: [],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "escape_guardian",
        type: "function",
        inputs: [],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "cancel_escape",
        type: "function",
        inputs: [],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "get_owner",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_owner_guid",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_owner_type",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "argent::signer::signer_signature::SignerType",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_guardian",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "is_guardian",
        type: "function",
        inputs: [
          {
            name: "guardian",
            type: "argent::signer::signer_signature::Signer",
          },
        ],
        outputs: [
          {
            type: "core::bool",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_guardian_guid",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::option::Option::<core::felt252>",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_guardian_type",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::option::Option::<argent::signer::signer_signature::SignerType>",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_guardian_backup",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_guardian_backup_guid",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::option::Option::<core::felt252>",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_guardian_backup_type",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::option::Option::<argent::signer::signer_signature::SignerType>",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_escape",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "argent::recovery::interface::LegacyEscape",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_name",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_version",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "argent::account::interface::Version",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_last_owner_trigger_escape_attempt",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::integer::u64",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_last_guardian_trigger_escape_attempt",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::integer::u64",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_last_owner_escape_attempt",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::integer::u64",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_last_guardian_escape_attempt",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::integer::u64",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_escape_and_status",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "(argent::recovery::interface::LegacyEscape, argent::recovery::interface::EscapeStatus)",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_escape_security_period",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::integer::u64",
          },
        ],
        state_mutability: "view",
      },
    ],
  },
  {
    name: "DeprecatedArgentAccountImpl",
    type: "impl",
    interface_name: "argent::account::interface::IDeprecatedArgentAccount",
  },
  {
    name: "argent::account::interface::IDeprecatedArgentAccount",
    type: "interface",
    items: [
      {
        name: "getVersion",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "getName",
        type: "function",
        inputs: [],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "isValidSignature",
        type: "function",
        inputs: [
          {
            name: "hash",
            type: "core::felt252",
          },
          {
            name: "signatures",
            type: "core::array::Array::<core::felt252>",
          },
        ],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
    ],
  },
  {
    name: "Sessionable",
    type: "impl",
    interface_name: "argent::session::interface::ISessionable",
  },
  {
    name: "argent::session::interface::ISessionable",
    type: "interface",
    items: [
      {
        name: "revoke_session",
        type: "function",
        inputs: [
          {
            name: "session_hash",
            type: "core::felt252",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
      {
        name: "is_session_revoked",
        type: "function",
        inputs: [
          {
            name: "session_hash",
            type: "core::felt252",
          },
        ],
        outputs: [
          {
            type: "core::bool",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "is_session_authorization_cached",
        type: "function",
        inputs: [
          {
            name: "session_hash",
            type: "core::felt252",
          },
        ],
        outputs: [
          {
            type: "core::bool",
          },
        ],
        state_mutability: "view",
      },
    ],
  },
  {
    name: "ExecuteFromOutside",
    type: "impl",
    interface_name: "argent::outside_execution::interface::IOutsideExecution",
  },
  {
    name: "core::array::Span::<core::starknet::account::Call>",
    type: "struct",
    members: [
      {
        name: "snapshot",
        type: "@core::array::Array::<core::starknet::account::Call>",
      },
    ],
  },
  {
    name: "argent::outside_execution::interface::OutsideExecution",
    type: "struct",
    members: [
      {
        name: "caller",
        type: "core::starknet::contract_address::ContractAddress",
      },
      {
        name: "nonce",
        type: "core::felt252",
      },
      {
        name: "execute_after",
        type: "core::integer::u64",
      },
      {
        name: "execute_before",
        type: "core::integer::u64",
      },
      {
        name: "calls",
        type: "core::array::Span::<core::starknet::account::Call>",
      },
    ],
  },
  {
    name: "argent::outside_execution::interface::IOutsideExecution",
    type: "interface",
    items: [
      {
        name: "execute_from_outside",
        type: "function",
        inputs: [
          {
            name: "outside_execution",
            type: "argent::outside_execution::interface::OutsideExecution",
          },
          {
            name: "signature",
            type: "core::array::Array::<core::felt252>",
          },
        ],
        outputs: [
          {
            type: "core::array::Array::<core::array::Span::<core::felt252>>",
          },
        ],
        state_mutability: "external",
      },
      {
        name: "execute_from_outside_v2",
        type: "function",
        inputs: [
          {
            name: "outside_execution",
            type: "argent::outside_execution::interface::OutsideExecution",
          },
          {
            name: "signature",
            type: "core::array::Span::<core::felt252>",
          },
        ],
        outputs: [
          {
            type: "core::array::Array::<core::array::Span::<core::felt252>>",
          },
        ],
        state_mutability: "external",
      },
      {
        name: "is_valid_outside_execution_nonce",
        type: "function",
        inputs: [
          {
            name: "nonce",
            type: "core::felt252",
          },
        ],
        outputs: [
          {
            type: "core::bool",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_outside_execution_message_hash_rev_0",
        type: "function",
        inputs: [
          {
            name: "outside_execution",
            type: "argent::outside_execution::interface::OutsideExecution",
          },
        ],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
      {
        name: "get_outside_execution_message_hash_rev_1",
        type: "function",
        inputs: [
          {
            name: "outside_execution",
            type: "argent::outside_execution::interface::OutsideExecution",
          },
        ],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
    ],
  },
  {
    name: "SRC5",
    type: "impl",
    interface_name: "argent::introspection::interface::ISRC5",
  },
  {
    name: "argent::introspection::interface::ISRC5",
    type: "interface",
    items: [
      {
        name: "supports_interface",
        type: "function",
        inputs: [
          {
            name: "interface_id",
            type: "core::felt252",
          },
        ],
        outputs: [
          {
            type: "core::bool",
          },
        ],
        state_mutability: "view",
      },
    ],
  },
  {
    name: "SRC5Legacy",
    type: "impl",
    interface_name: "argent::introspection::interface::ISRC5Legacy",
  },
  {
    name: "argent::introspection::interface::ISRC5Legacy",
    type: "interface",
    items: [
      {
        name: "supportsInterface",
        type: "function",
        inputs: [
          {
            name: "interfaceId",
            type: "core::felt252",
          },
        ],
        outputs: [
          {
            type: "core::felt252",
          },
        ],
        state_mutability: "view",
      },
    ],
  },
  {
    name: "Upgradable",
    type: "impl",
    interface_name: "argent::upgrade::interface::IUpgradeable",
  },
  {
    name: "argent::upgrade::interface::IUpgradeable",
    type: "interface",
    items: [
      {
        name: "upgrade",
        type: "function",
        inputs: [
          {
            name: "new_implementation",
            type: "core::starknet::class_hash::ClassHash",
          },
          {
            name: "data",
            type: "core::array::Array::<core::felt252>",
          },
        ],
        outputs: [],
        state_mutability: "external",
      },
    ],
  },
  {
    name: "constructor",
    type: "constructor",
    inputs: [
      {
        name: "owner",
        type: "argent::signer::signer_signature::Signer",
      },
      {
        name: "guardian",
        type: "core::option::Option::<argent::signer::signer_signature::Signer>",
      },
    ],
  },
  {
    kind: "enum",
    name: "argent::outside_execution::outside_execution::outside_execution_component::Event",
    type: "event",
    variants: [],
  },
  {
    kind: "enum",
    name: "argent::introspection::src5::src5_component::Event",
    type: "event",
    variants: [],
  },
  {
    kind: "struct",
    name: "argent::upgrade::upgrade::upgrade_component::AccountUpgraded",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_implementation",
        type: "core::starknet::class_hash::ClassHash",
      },
    ],
  },
  {
    kind: "enum",
    name: "argent::upgrade::upgrade::upgrade_component::Event",
    type: "event",
    variants: [
      {
        kind: "nested",
        name: "AccountUpgraded",
        type: "argent::upgrade::upgrade::upgrade_component::AccountUpgraded",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::session::session::session_component::SessionRevoked",
    type: "event",
    members: [
      {
        kind: "data",
        name: "session_hash",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "enum",
    name: "argent::session::session::session_component::Event",
    type: "event",
    variants: [
      {
        kind: "nested",
        name: "SessionRevoked",
        type: "argent::session::session::session_component::SessionRevoked",
      },
    ],
  },
  {
    kind: "enum",
    name: "openzeppelin::security::reentrancyguard::ReentrancyGuardComponent::Event",
    type: "event",
    variants: [],
  },
  {
    name: "core::array::Span::<core::array::Span::<core::felt252>>",
    type: "struct",
    members: [
      {
        name: "snapshot",
        type: "@core::array::Array::<core::array::Span::<core::felt252>>",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::TransactionExecuted",
    type: "event",
    members: [
      {
        kind: "key",
        name: "hash",
        type: "core::felt252",
      },
      {
        kind: "data",
        name: "response",
        type: "core::array::Span::<core::array::Span::<core::felt252>>",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::AccountCreated",
    type: "event",
    members: [
      {
        kind: "key",
        name: "owner",
        type: "core::felt252",
      },
      {
        kind: "data",
        name: "guardian",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::AccountCreatedGuid",
    type: "event",
    members: [
      {
        kind: "key",
        name: "owner_guid",
        type: "core::felt252",
      },
      {
        kind: "data",
        name: "guardian_guid",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::EscapeOwnerTriggeredGuid",
    type: "event",
    members: [
      {
        kind: "data",
        name: "ready_at",
        type: "core::integer::u64",
      },
      {
        kind: "data",
        name: "new_owner_guid",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::EscapeGuardianTriggeredGuid",
    type: "event",
    members: [
      {
        kind: "data",
        name: "ready_at",
        type: "core::integer::u64",
      },
      {
        kind: "data",
        name: "new_guardian_guid",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::OwnerEscapedGuid",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_owner_guid",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::GuardianEscapedGuid",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_guardian_guid",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::EscapeCanceled",
    type: "event",
    members: [],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::OwnerChanged",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_owner",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::OwnerChangedGuid",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_owner_guid",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::GuardianChanged",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_guardian",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::GuardianChangedGuid",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_guardian_guid",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::GuardianBackupChanged",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_guardian_backup",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::GuardianBackupChangedGuid",
    type: "event",
    members: [
      {
        kind: "data",
        name: "new_guardian_backup_guid",
        type: "core::felt252",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::SignerLinked",
    type: "event",
    members: [
      {
        kind: "key",
        name: "signer_guid",
        type: "core::felt252",
      },
      {
        kind: "data",
        name: "signer",
        type: "argent::signer::signer_signature::Signer",
      },
    ],
  },
  {
    kind: "struct",
    name: "argent::presets::argent_account::ArgentAccount::EscapeSecurityPeriodChanged",
    type: "event",
    members: [
      {
        kind: "data",
        name: "escape_security_period",
        type: "core::integer::u64",
      },
    ],
  },
  {
    kind: "enum",
    name: "argent::presets::argent_account::ArgentAccount::Event",
    type: "event",
    variants: [
      {
        kind: "flat",
        name: "ExecuteFromOutsideEvents",
        type: "argent::outside_execution::outside_execution::outside_execution_component::Event",
      },
      {
        kind: "flat",
        name: "SRC5Events",
        type: "argent::introspection::src5::src5_component::Event",
      },
      {
        kind: "flat",
        name: "UpgradeEvents",
        type: "argent::upgrade::upgrade::upgrade_component::Event",
      },
      {
        kind: "flat",
        name: "SessionableEvents",
        type: "argent::session::session::session_component::Event",
      },
      {
        kind: "flat",
        name: "ReentrancyGuardEvent",
        type: "openzeppelin::security::reentrancyguard::ReentrancyGuardComponent::Event",
      },
      {
        kind: "nested",
        name: "TransactionExecuted",
        type: "argent::presets::argent_account::ArgentAccount::TransactionExecuted",
      },
      {
        kind: "nested",
        name: "AccountCreated",
        type: "argent::presets::argent_account::ArgentAccount::AccountCreated",
      },
      {
        kind: "nested",
        name: "AccountCreatedGuid",
        type: "argent::presets::argent_account::ArgentAccount::AccountCreatedGuid",
      },
      {
        kind: "nested",
        name: "EscapeOwnerTriggeredGuid",
        type: "argent::presets::argent_account::ArgentAccount::EscapeOwnerTriggeredGuid",
      },
      {
        kind: "nested",
        name: "EscapeGuardianTriggeredGuid",
        type: "argent::presets::argent_account::ArgentAccount::EscapeGuardianTriggeredGuid",
      },
      {
        kind: "nested",
        name: "OwnerEscapedGuid",
        type: "argent::presets::argent_account::ArgentAccount::OwnerEscapedGuid",
      },
      {
        kind: "nested",
        name: "GuardianEscapedGuid",
        type: "argent::presets::argent_account::ArgentAccount::GuardianEscapedGuid",
      },
      {
        kind: "nested",
        name: "EscapeCanceled",
        type: "argent::presets::argent_account::ArgentAccount::EscapeCanceled",
      },
      {
        kind: "nested",
        name: "OwnerChanged",
        type: "argent::presets::argent_account::ArgentAccount::OwnerChanged",
      },
      {
        kind: "nested",
        name: "OwnerChangedGuid",
        type: "argent::presets::argent_account::ArgentAccount::OwnerChangedGuid",
      },
      {
        kind: "nested",
        name: "GuardianChanged",
        type: "argent::presets::argent_account::ArgentAccount::GuardianChanged",
      },
      {
        kind: "nested",
        name: "GuardianChangedGuid",
        type: "argent::presets::argent_account::ArgentAccount::GuardianChangedGuid",
      },
      {
        kind: "nested",
        name: "GuardianBackupChanged",
        type: "argent::presets::argent_account::ArgentAccount::GuardianBackupChanged",
      },
      {
        kind: "nested",
        name: "GuardianBackupChangedGuid",
        type: "argent::presets::argent_account::ArgentAccount::GuardianBackupChangedGuid",
      },
      {
        kind: "nested",
        name: "SignerLinked",
        type: "argent::presets::argent_account::ArgentAccount::SignerLinked",
      },
      {
        kind: "nested",
        name: "EscapeSecurityPeriodChanged",
        type: "argent::presets::argent_account::ArgentAccount::EscapeSecurityPeriodChanged",
      },
    ],
  },
];
